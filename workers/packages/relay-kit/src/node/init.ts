/**
 * `gray-assistant init`: one directory that a relay operator can review, back up and run.
 *
 * It writes the relay key (0600), the config skeleton (every key documented, every default shown),
 * the default allow-all policy bundle signed with the relay key (the policy upload is mandatory on
 * the lane's request path), one registration document per official vendor endpoint, and the nginx
 * and Caddy snippets that terminate TLS in front of the agent's plain HTTP.
 *
 * Nothing here talks to the lane or the relay software, and plain `init` is offline by construction. `init --pair`
 * (`pairWorkspace`, S57) makes one request to Gray: the code, the key's public half and its signature, answered with
 * the values it writes into the config. Then it reads the signed release list Gray's answer names (a public GET,
 * verified with the answer's keys as the agent verifies it) and records what the list names as accepted at pairing.
 */
import { chmodSync, existsSync, lstatSync, mkdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { bytesToLowerHex, ed25519Sign, lowerHexBytes } from "@gray/attest";
import { PAIR_REFUSALS, normalizePairingCode, pairAnswerSchema, pairMessage, relayKeyFingerprint, type PairAnswer, type PairRefusal } from "@gray/control/stack-pairing";
import { tunnelName } from "@gray/control/tunnel";
import { get, isObject, parseStrict, toJsonString, type Json } from "@gray/json";
import { isStackRelayImage, osImageProvenance, relayImageRegistry, releaseFreshnessLocation } from "@gray/lane-verify";
import { ALLOW_MODULE_BASE64 } from "../assets/allow-module.ts";
import { decodeBase64 } from "../base64.ts";
import { MAX_PAIRING_ACCEPTANCES } from "../daemon/config.ts";
import { fetchReleaseList, ReleaseListError } from "../daemon/releases.ts";
import { RELAY_KIT_VERSION } from "../endpoints.ts";
import { RelayKitError } from "../errors.ts";
import {
  INIT_FILES,
  APP_ID_PLACEHOLDER,
  KMS_CA_PUBKEY_PLACEHOLDER,
  LANE_ORIGIN_PLACEHOLDER,
  REGISTRY_HOST_PLACEHOLDER,
  REGISTRY_USERNAME_PATTERN,
  REGISTRY_USERNAME_PLACEHOLDER,
  RELEASE_LIST_PLACEHOLDER,
  RELEASE_PUBLIC_KEY_PLACEHOLDER,
  RELAY_ID_PLACEHOLDER,
  SCHEDULER_URL_PLACEHOLDER,
  TOKEN_URL_PLACEHOLDER,
  initCaddySnippet,
  initConfigText,
  initNginxSnippet,
  PAIRED_COMPOSE_FILE,
  pairedComposeText,
  pairedConfigText,
  printableReleaseName,
  registrationDocuments,
  relayImagePlaceholder,
  utcSecondsMs,
  type InitDocumentOptions,
  type PairingAcceptedHash,
} from "../init.ts";
import { generateRelayKey, relayPublicKeyHex, relayKeyValue, verifyRelayKeyPair, type RelayKeyFile } from "../keys.ts";
import { prepareAndSignPolicyBundle } from "../policy-bundle.ts";
import { ensureDirectory, readPrivateFile, writePrivateFile } from "./files.ts";
import { createPlainDaemonFetch } from "./release-list-source.ts";
import { initWorkspaceInterpreter } from "./interpreter.ts";
import { buildKeyFromText } from "./scheduler-load.ts";
import { APP_ID_PATTERN, KMS_CA_PUBKEY_PATTERN } from "../lane-binding.ts";

const URL_MAX = 2048;
const TOKEN = /^[A-Za-z0-9._:-]{1,128}$/;

export interface InitWorkspaceOptions {
  readonly directory: string;
  readonly relayId?: string;
  readonly schedulerUrl?: string;
  readonly laneOrigin?: string;
  readonly releaseListUrl?: string;
  readonly releasePublicKey?: string;
  /** D137: Gray's freshness public key, written into the config when given. */
  readonly releaseFreshnessPublicKey?: string;
  /** The lane instance's dstack app id and node KMS `ca_pubkey` (plan S12); placeholders when absent. */
  readonly appId?: string;
  readonly kmsCaPubkey?: string;
  /** Replace existing files (never a key or a policy bundle that is there). */
  readonly force?: boolean;
}

export interface InitWorkspaceResult {
  readonly directory: string;
  readonly relayId: string;
  readonly publicKeyHex: string;
  readonly keyPath: string;
  readonly policyBundlePath: string;
  readonly configPath: string;
  readonly files: readonly string[];
  /** The release config keys that still hold the init placeholder (K5-1). */
  readonly placeholders: readonly string[];
}

/**
 * A public (non-secret) file, written 0644. It goes through the same symlink-proof private writer
 * (exclusive create, O_NOFOLLOW), then has its mode widened: a pre-planted link can never make
 * `init` write outside the workspace, even with `--force`.
 */
function writePublicFile(path: string, text: string, force: boolean): void {
  try {
    writePrivateFile(path, text, { force });
    chmodSync(path, 0o644);
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    throw new RelayKitError("io", `cannot write ${path}`);
  }
}

function checkedUrl(value: string, what: string, httpsOnly: boolean, originOnly = false): string {
  if (value.length === 0 || value.length > URL_MAX) throw new RelayKitError("usage", `${what} is not a URL`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RelayKitError("usage", `${what} is not a URL`);
  }
  if (httpsOnly ? url.protocol !== "https:" : url.protocol !== "https:" && url.protocol !== "http:") {
    throw new RelayKitError("usage", `${what} must be ${httpsOnly ? "https" : "http(s)"}`);
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new RelayKitError("usage", `${what} must not carry credentials, a query or a fragment`);
  }
  if (originOnly && (url.pathname !== "/" || url.href !== `${url.origin}/` || /\s/.test(value))) {
    throw new RelayKitError("usage", `${what} must be an origin without a path, a query or a fragment`);
  }
  return value;
}

/**
 * Create the workspace. A wrong flag is a usage refusal (exit 2); an existing file is an I/O
 * refusal unless `--force`. `compose.yaml` and the guides are not copied: they live in
 * `deploy/relay/` and are the operator's deployment files, not per-workspace artifacts.
 */
export async function initWorkspace(options: InitWorkspaceOptions): Promise<InitWorkspaceResult> {
  const directory = options.directory;
  const relayId = options.relayId ?? RELAY_ID_PLACEHOLDER;
  if (!TOKEN.test(relayId)) throw new RelayKitError("usage", "the relay id must match [A-Za-z0-9._:-]{1,128}");
  const schedulerUrl = checkedUrl(options.schedulerUrl ?? SCHEDULER_URL_PLACEHOLDER, "scheduler URL", true, true);
  const laneOrigin = checkedUrl(options.laneOrigin ?? LANE_ORIGIN_PLACEHOLDER, "lane origin", true, true);
  const releaseListUrl = checkedUrl(options.releaseListUrl ?? RELEASE_LIST_PLACEHOLDER, "release-list URL", false);
  const releasePublicKey = options.releasePublicKey ?? RELEASE_PUBLIC_KEY_PLACEHOLDER;
  if (!/^[0-9a-f]{64}$/.test(releasePublicKey)) throw new RelayKitError("usage", "the release public key must be 32 bytes as 64 lower-case hex");
  const placeholders: string[] = [];
  if (releaseListUrl === RELEASE_LIST_PLACEHOLDER) placeholders.push("lane.release_list");
  if (releasePublicKey === RELEASE_PUBLIC_KEY_PLACEHOLDER) placeholders.push("lane.release_public_key");
  const releaseFreshnessPublicKey = options.releaseFreshnessPublicKey;
  if (releaseFreshnessPublicKey !== undefined && (!/^[0-9a-f]{64}$/.test(releaseFreshnessPublicKey) || releaseFreshnessPublicKey === releasePublicKey || releaseFreshnessPublicKey === RELEASE_PUBLIC_KEY_PLACEHOLDER)) {
    throw new RelayKitError("usage", "the release freshness public key must be 32 bytes as 64 lower-case hex, and not the release key");
  }
  const appId = options.appId ?? APP_ID_PLACEHOLDER;
  const kmsCaPubkey = options.kmsCaPubkey ?? KMS_CA_PUBKEY_PLACEHOLDER;
  if (!APP_ID_PATTERN.test(appId)) throw new RelayKitError("usage", "the app id must be the lane's dstack app id, 40 lower-case hex");
  if (!KMS_CA_PUBKEY_PATTERN.test(kmsCaPubkey)) throw new RelayKitError("usage", "the KMS CA public key must be the node KMS's ca_pubkey, 182 lower-case hex");
  if (appId === APP_ID_PLACEHOLDER || kmsCaPubkey === KMS_CA_PUBKEY_PLACEHOLDER) placeholders.push("lane.instances");

  ensureDirectory(directory);
  // Generate the key first, so a refusal later never leaves a half-written workspace without one.
  const key: RelayKeyFile = await generateRelayKey(relayId);
  await verifyRelayKeyPair(key);
  const keyPath = join(directory, INIT_FILES.key);
  writePrivateFile(keyPath, `${toJsonString(relayKeyValue(key))}\n`, { force: options.force === true });

  const documents: InitDocumentOptions = {
    relayId,
    schedulerUrl,
    laneOrigin,
    releaseListUrl,
    releasePublicKey,
    ...(releaseFreshnessPublicKey === undefined ? {} : { releaseFreshnessPublicKey }),
    appId,
    kmsCaPubkey,
    relayPublicKey: relayPublicKeyHex(key),
  };
  initWorkspaceInterpreter();
  const moduleBytes = decodeBase64(ALLOW_MODULE_BASE64);
  if (moduleBytes === null) throw new RelayKitError("io", "the shipped allow module is not base64");
  const policy = await prepareAndSignPolicyBundle({ relayId, version: 1n, moduleBytes, templates: [], signingKey: key.seed });
  if (!policy.ok) throw new RelayKitError("invalid_policy_bundle", `${policy.code}: ${policy.detail}`);
  const policyBundlePath = join(directory, INIT_FILES.policyBundle);
  writePrivateFile(policyBundlePath, `${toJsonString(policy.document)}\n`, { force: options.force === true });

  const configPath = join(directory, INIT_FILES.config);
  writePublicFile(configPath, initConfigText(documents), options.force === true);
  const files = [keyPath, policyBundlePath, configPath];
  mkdirSync(join(directory, INIT_FILES.registrationDir), { recursive: true, mode: 0o755 });
  mkdirSync(join(directory, "proxy"), { recursive: true, mode: 0o755 });
  for (const registration of registrationDocuments(documents)) {
    const path = join(directory, registration.fileName);
    writePublicFile(path, `${toJsonString(registration.value)}\n`, options.force === true);
    files.push(path);
  }
  for (const [relative, text] of [
    [INIT_FILES.nginx, initNginxSnippet(documents)],
    [INIT_FILES.caddy, initCaddySnippet(documents)],
  ] as const) {
    const path = join(directory, relative);
    writePublicFile(path, text, options.force === true);
    files.push(path);
  }
  return {
    directory,
    relayId,
    publicKeyHex: documents.relayPublicKey,
    keyPath,
    policyBundlePath,
    configPath,
    files,
    placeholders,
  };
}

// ---- init --pair (S57) ------------------------------------------------------------------------

/** The pairing route on Gray's API origin (`@gray/control/stack-pairing`). */
export const PAIR_PATH = "/v1/lane-stack/pair";
/** How long the pairing request may take: the agent status post's limit (agent-status-report.ts), the same route family. */
export const PAIR_TIMEOUT_MS = 20_000;
/** The largest answer read: the pairing answer is under 2 KiB. */
const MAX_PAIR_ANSWER_BYTES = 64 * 1024;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"]);
/** `stack.registry.host`'s own pattern (config.ts). */
const REGISTRY_HOST = /^[A-Za-z0-9.-]{1,247}(:[0-9]{1,5})?$/;

export interface PairWorkspaceOptions {
  readonly directory: string;
  /** The code as the operator typed or pasted it. */
  readonly code: string;
  /** Gray's API origin (`--gray`). */
  readonly gray: string;
  /** An existing relay-key.json to pair instead of a new key (`--key`). */
  readonly keyPath?: string;
  readonly force?: boolean;
  readonly timeoutMs?: number;
  /** The clock the release list is judged by; the tests' fixed time. */
  readonly nowMs?: number;
  /** The published image `init` runs from (`$GRAY_ASSISTANT_IMAGE`): then the kit gets a compose file that runs it. */
  readonly composeImage?: string;
  /**
   * The registry's pull token's user and expiry (`--registry-user`, `--registry-expires-at`; the expiry only with the
   * user, and optional since relay standard v1.7: without it the token has no known expiry), written as
   * `stack.registry.username` and `expires_at` instead of the user's placeholder; the token itself is the kit file
   * `registry-password`, which never passes through Gray.
   */
  readonly registryUser?: string;
  readonly registryExpiresAt?: string;
}

/**
 * What `init --pair` took from Gray's signed release list: the hashes it accepted, the OS images it left to the
 * operator (their texts do not prove a production image, so only `releases accept` takes one), and the list's refusal
 * code when it could not be read (then nothing is accepted and the current release waits `delay_days`).
 */
export interface PairingAcceptance {
  readonly accepted: readonly PairingAcceptedHash[];
  readonly unverifiedOsImages: readonly string[];
  readonly listError: string | null;
}

export type PairWorkspaceResult =
  | {
      readonly ok: true;
      readonly directory: string;
      readonly relayId: string;
      readonly publicKeyHex: string;
      readonly fingerprint: string;
      readonly keyPath: string;
      readonly configPath: string;
      /** The kit's compose file, when `init` ran from the published image. */
      readonly composePath: string | null;
      readonly files: readonly string[];
      /** The config members still holding a placeholder. */
      readonly placeholders: readonly string[];
      /** Whether Gray's answer named the relay's image (else `stack.relay_images` is a placeholder). */
      readonly image: boolean;
      /** What the pairing accepted from Gray's release list; null when Gray's answer names no list. */
      readonly releases: PairingAcceptance | null;
    }
  /** Gray answered with a refusal (`code` one of `PAIR_REFUSALS` or null), did not answer, or answered something else. */
  | { readonly ok: false; readonly reason: "refused" | "unreachable" | "malformed"; readonly status: number | null; readonly code: PairRefusal | null; readonly text: string };

/** `--gray`: an https origin, or http for a loopback host (the tests' fake route). Returned without a trailing slash. */
function grayOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(checkedUrl(value, "--gray", false, true));
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    throw new RelayKitError("usage", "--gray is not a URL");
  }
  if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) throw new RelayKitError("usage", "--gray must be https (http only for 127.0.0.1, ::1 or localhost)");
  return url.origin;
}

/** Refuse before any network when a file the kit writes is there already (without `--force`), so a spent code always leaves a kit. */
function assertWritable(path: string, force: boolean): void {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    return;
  }
  if (stat.isSymbolicLink()) throw new RelayKitError("io", `${path} is a symbolic link`);
  if (!force) throw new RelayKitError("io", `${path} already exists (pass --force)`);
  if (!stat.isFile()) throw new RelayKitError("io", `${path} is not a regular file`);
}

/** The answer's `{"error": {"code"}}` as a pairing refusal, or null. */
function refusalCode(body: string): PairRefusal | null {
  try {
    const error = get(parseStrict(body), "error");
    const code = isObject(error) ? get(error, "code") : undefined;
    return typeof code === "string" && Object.hasOwn(PAIR_REFUSALS, code) ? (code as PairRefusal) : null;
  } catch {
    return null;
  }
}

/** The answer through `pairAnswerSchema`; `parseStrict` reads `paired_ms` as a bigint, which the schema takes as a number. */
function readPairAnswer(body: string): PairAnswer | null {
  let value: Json;
  try {
    value = parseStrict(body);
  } catch {
    return null;
  }
  if (!isObject(value)) return null;
  const pairedMs = get(value, "paired_ms");
  const plain = typeof pairedMs === "bigint" ? { ...value, paired_ms: pairedMs <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(pairedMs) : -1 } : value;
  const parsed = pairAnswerSchema.safeParse(plain);
  return parsed.success ? parsed.data : null;
}

/** The age bound `pairedConfigText` writes (`lane.release_list_max_age`), so the list is judged as the agent will. */
const PAIRED_RELEASE_LIST_MAX_AGE = 86_400;

/**
 * The releases Gray's signed list names now, which pairing accepts: every compose release with a `git_commit` (no
 * other is ever acceptable) and every OS image whose own texts prove a production image. A dev image is never
 * accepted; one whose texts do not bind it is left to `releases accept`. A list that does not verify accepts nothing.
 */
async function pairingAcceptance(release: NonNullable<PairAnswer["release"]>, nowMs: number, timeoutMs: number): Promise<PairingAcceptance> {
  // The answer's schema checked both keys' form (64 lower-case hex).
  const publicKey = lowerHexBytes(release.public_key) as Uint8Array;
  const freshnessKey = release.freshness_public_key === null ? null : (lowerHexBytes(release.freshness_public_key) as Uint8Array);
  let verified;
  try {
    verified = await fetchReleaseList(createPlainDaemonFetch({ timeoutMs }), release.list, {
      publicKey,
      maxAgeSeconds: PAIRED_RELEASE_LIST_MAX_AGE,
      nowMs,
      freshness: freshnessKey === null ? null : { publicKey: freshnessKey, url: releaseFreshnessLocation(release.list) },
    });
  } catch (error) {
    return { accepted: [], unverifiedOsImages: [], listError: error instanceof ReleaseListError ? error.code : "fetch_failed" };
  }
  const accepted: PairingAcceptedHash[] = [];
  for (const entry of verified.list.releases) {
    if (entry.git_commit === null) continue;
    accepted.push({ hash: entry.compose_hash, kind: "release", name: printableReleaseName(entry.git_tag ?? `commit ${entry.git_commit.slice(0, 12)}`) });
  }
  const unverifiedOsImages: string[] = [];
  for (const image of verified.list.osImages) {
    const provenance = osImageProvenance(image);
    if (!provenance.ok) unverifiedOsImages.push(image.os_image_hash);
    else if (!provenance.isDev) accepted.push({ hash: image.os_image_hash, kind: "os_image", name: printableReleaseName(provenance.version ?? "unversioned") });
  }
  return { accepted: accepted.slice(0, MAX_PAIRING_ACCEPTANCES), unverifiedOsImages, listError: null };
}

/** `YYYY-MM-DDTHH:MM:SSZ`, the form the config's other instants take. */
function utcSeconds(ms: number): string {
  return `${new Date(Math.floor(ms / 1000) * 1000).toISOString().slice(0, 19)}Z`;
}

/**
 * `--registry-user` and `--registry-expires-at`, checked before any network so a wrong value does not spend the code.
 * The expiry is optional (v1.7): a token without one has no known expiry; it never comes without the user.
 */
function pairRegistryLogin(user: string | undefined, expiresAt: string | undefined, nowMs: number): { username: string; expiresAt: string | null } | null {
  if (user === undefined && expiresAt === undefined) return null;
  if (user === undefined) throw new RelayKitError("usage", "--registry-expires-at needs --registry-user: the pull token's user and its expiry");
  if (!REGISTRY_USERNAME_PATTERN.test(user) || user === REGISTRY_USERNAME_PLACEHOLDER) throw new RelayKitError("usage", "--registry-user is the pull token's user: 1-128 printable characters, no space");
  if (expiresAt === undefined) return { username: user, expiresAt: null };
  const ms = utcSecondsMs(expiresAt);
  if (ms === null) throw new RelayKitError("usage", "--registry-expires-at is the pull token's expiry, YYYY-MM-DDTHH:MM:SSZ");
  if (ms <= nowMs) throw new RelayKitError("usage", "--registry-expires-at is in the past: give the pull token's real expiry (or the date you will change a password)");
  return { username: user, expiresAt };
}

/**
 * `init --pair`: make the relay key (or read `--key`), pair its public half with Gray's code, and write the kit from
 * the answer (S57). Nothing is written unless Gray pairs the key; a refused, unanswered or unreadable pairing returns
 * `ok: false`. A wrong flag, a code that is no code, or a kit file already there (without `--force`) is refused before
 * any network.
 */
export async function pairWorkspace(options: PairWorkspaceOptions): Promise<PairWorkspaceResult> {
  const code = normalizePairingCode(options.code);
  if (code === null) throw new RelayKitError("usage", "--pair is not a pairing code (GRAY- and six groups of four characters, as the relay's page shows it)");
  const gray = grayOrigin(options.gray);
  const directory = options.directory;
  const force = options.force === true;
  const keyPath = join(directory, INIT_FILES.key);
  const configPath = join(directory, INIT_FILES.config);
  const keySource = options.keyPath === undefined ? null : resolve(options.keyPath);
  const copyKey = keySource !== resolve(keyPath);
  const composeImage = options.composeImage === undefined || options.composeImage.trim() === "" ? null : options.composeImage.trim();
  const composePath = join(directory, PAIRED_COMPOSE_FILE);
  const registryLogin = pairRegistryLogin(options.registryUser, options.registryExpiresAt, options.nowMs ?? Date.now());
  if (copyKey) assertWritable(keyPath, force);
  assertWritable(configPath, force);
  if (composeImage !== null) assertWritable(composePath, force);
  if (existsSync(directory) && !statSync(directory).isDirectory()) throw new RelayKitError("io", `${directory} is not a directory`);

  const key: RelayKeyFile =
    keySource === null ? await generateRelayKey() : await buildKeyFromText(readPrivateFile(keySource, "relay key", 64 * 1024));
  if (keySource === null) await verifyRelayKeyPair(key);
  const publicKeyHex = relayPublicKeyHex(key);
  const fingerprint = relayKeyFingerprint(publicKeyHex) as string;
  const signature = bytesToLowerHex(await ed25519Sign(key.seed, pairMessage(code, publicKeyHex)));

  let status: number;
  let body: string;
  try {
    const response = await fetch(`${gray}${PAIR_PATH}`, {
      method: "POST",
      // No header names the operator or the machine: the code, the key and the version are the whole request.
      headers: { "content-type": "application/json", accept: "application/json", "user-agent": "gray-assistant" },
      body: JSON.stringify({ code, public_key: publicKeyHex, signature, agent_version: RELAY_KIT_VERSION }),
      redirect: "error",
      signal: AbortSignal.timeout(options.timeoutMs ?? PAIR_TIMEOUT_MS),
    });
    status = response.status;
    body = await response.text();
  } catch {
    return {
      ok: false,
      reason: "unreachable",
      status: null,
      code: null,
      text: `Gray did not answer at ${gray}${PAIR_PATH}; check --gray and this machine's network, then run the command again (make a new code if the relay's page says this one was used)`,
    };
  }
  if (status < 200 || status > 299) {
    const refusal = refusalCode(body);
    return { ok: false, reason: "refused", status, code: refusal, text: refusal === null ? `Gray refused the pairing (HTTP ${status})` : PAIR_REFUSALS[refusal].text };
  }
  const answer = body.length > MAX_PAIR_ANSWER_BYTES ? null : readPairAnswer(body);
  if (answer === null) return { ok: false, reason: "malformed", status, code: null, text: `Gray's answer at ${gray}${PAIR_PATH} is not a pairing answer; upgrade gray-assistant, or tell Gray` };
  // Gray paired the key this request sent: an answer naming another is not this pairing's.
  if (answer.public_key !== publicKeyHex || answer.fingerprint !== fingerprint) {
    return { ok: false, reason: "malformed", status, code: null, text: "Gray's answer names another key than the one this command sent; tell Gray, and pair again with a new code" };
  }

  const placeholders: string[] = [];
  if (answer.release === null) placeholders.push("lane.release_list", "lane.release_public_key");
  const image = answer.image !== null && isStackRelayImage(answer.image) ? answer.image : null;
  const registryHost = answer.registry !== null && REGISTRY_HOST.test(answer.registry) ? answer.registry : image === null ? null : relayImageRegistry(image);
  if (registryHost === null) placeholders.push("stack.registry.host");
  if (image === null) placeholders.push("stack.relay_images");
  if (registryLogin === null) placeholders.push("stack.registry.username");
  // The config's own default: the tunnel's origin (`tunnel.ts` tunnelName, as config.ts derives it).
  const name = answer.tunnel === null ? null : tunnelName(answer.relay_id, answer.tunnel.zone);
  const tunnelOrigin = name === null ? null : `https://${name}`;
  const tokenUrl = answer.token_url !== null && answer.token_url !== tunnelOrigin ? answer.token_url : tunnelOrigin === null ? TOKEN_URL_PLACEHOLDER : null;
  if (tokenUrl === TOKEN_URL_PLACEHOLDER) placeholders.push("stack.token_url");
  // Gray paired the key: the code is spent. A list that cannot be read now only means nothing is accepted at pairing.
  const releases = answer.release === null ? null : await pairingAcceptance(answer.release, options.nowMs ?? Date.now(), options.timeoutMs ?? PAIR_TIMEOUT_MS);
  const text = pairedConfigText({
    relayId: answer.relay_id,
    release: answer.release === null ? null : { list: answer.release.list, publicKey: answer.release.public_key, freshnessPublicKey: answer.release.freshness_public_key },
    reportOrigin: answer.report_origin,
    tokenUrl,
    tunnel: answer.tunnel === null ? null : { server: answer.tunnel.server, zone: answer.tunnel.zone },
    relayImage: image ?? relayImagePlaceholder(registryHost ?? REGISTRY_HOST_PLACEHOLDER),
    registryHost: registryHost ?? REGISTRY_HOST_PLACEHOLDER,
    registryLogin,
    pairing: { gray, fingerprint, pairedAt: utcSeconds(answer.paired_ms) },
    acceptedAtPairing: releases?.accepted ?? [],
  });

  ensureDirectory(directory);
  const files: string[] = [];
  if (copyKey) {
    writePrivateFile(keyPath, `${toJsonString(relayKeyValue(key))}\n`, { force });
    files.push(keyPath);
  }
  // 0600 like every kit file: the host install refuses a kit file other users can read (deploy/relay/host/install.sh).
  writePrivateFile(configPath, text, { force });
  files.push(configPath);
  // Public: it names the image and the mounts, no secret, and `docker compose` reads it as the operator.
  if (composeImage !== null) {
    writePublicFile(composePath, pairedComposeText(composeImage, answer.relay_id), force);
    files.push(composePath);
  }
  return { ok: true, directory, relayId: answer.relay_id, publicKeyHex, fingerprint, keyPath, configPath, composePath: composeImage === null ? null : composePath, files, placeholders, image: image !== null, releases };
}

/** For the CLI's machine-readable line after a pairing. */
export function pairSummary(result: Extract<PairWorkspaceResult, { ok: true }>): Record<string, unknown> {
  return {
    command: "init",
    paired: true,
    relay_id: result.relayId,
    public_key: result.publicKeyHex,
    fingerprint: result.fingerprint,
    directory: result.directory,
    key_file: result.keyPath,
    config: result.configPath,
    files: [...result.files],
    placeholders: [...result.placeholders],
    accepted_at_pairing: (result.releases?.accepted ?? []).map((entry) => ({ kind: entry.kind, hash: entry.hash, name: entry.name })),
    ...(result.releases === null || result.releases.listError === null ? {} : { release_list_error: result.releases.listError }),
  };
}

/** The public key as lower-case hex; exported so the CLI prints exactly what the registration has. */
export function initPublicKeyHex(result: InitWorkspaceResult): string {
  return result.publicKeyHex;
}

/** For the CLI's machine-readable line. */
export function initSummary(result: InitWorkspaceResult): Record<string, unknown> {
  return {
    command: "init",
    relay_id: result.relayId,
    public_key: result.publicKeyHex,
    directory: result.directory,
    key_file: result.keyPath,
    policy_bundle: result.policyBundlePath,
    config: result.configPath,
    files: [...result.files],
    placeholders: [...result.placeholders],
  };
}
