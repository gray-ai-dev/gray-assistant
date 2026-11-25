/**
 * `gray-assistant init`: one directory that a relay operator can review, back up and run.
 *
 * It writes the relay key (0600), the config skeleton (every key documented, every default shown),
 * the default allow-all policy bundle signed with the relay key (the policy upload is mandatory on
 * the lane's request path), one registration document per official vendor endpoint, and the nginx
 * and Caddy snippets that terminate TLS in front of the agent's plain HTTP.
 *
 * Nothing here talks to the lane or the relay software, and plain `init` is offline by construction. `init --pair`
 * (`pairWorkspace`, S57) asks Gray's chain terms for the code, checks them against what the kit knows without Gray
 * (`../chain/trust.ts`: Gray's release keys, Base's DstackKms and its KMS), reads Gray's signed release list with a key
 * built into the kit and the chain through the terms' two endpoints, and only then signs the guardian's approvals of
 * the release Gray will deploy and makes the pairing request: the code, the key's public half, its signature and the
 * approvals, answered with the values it writes into the config.
 */
import { chmodSync, existsSync, lstatSync, mkdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { bytesToLowerHex, ed25519Sign, lowerHexBytes } from "@gray/attest";
import {
  PAIR_CHAIN_PATH,
  PAIR_REFUSALS,
  normalizePairingCode,
  pairAnswerSchema,
  pairChainAnswerSchema,
  pairGuardianSchema,
  pairMessage,
  relayKeyFingerprint,
  type PairAnswer,
  type PairChainTerms,
  type PairGuardian,
  type PairRefusal,
} from "@gray/control/stack-pairing";
import { tunnelName } from "@gray/control/tunnel";
import { get, isObject, parseStrict, toJsonString, type Json } from "@gray/json";
import { BodyTooLargeError, readCappedText } from "@gray/json/read-capped";
import { isStackRelayImage, osImageProvenance, relayImageRegistry, releaseFreshnessLocation, type ReleaseList } from "@gray/lane-verify";
import { ALLOW_MODULE_BASE64 } from "../assets/allow-module.ts";
import { decodeBase64 } from "../base64.ts";
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
  registrationDocuments,
  relayImagePlaceholder,
  utcSecondsMs,
  type InitDocumentOptions,
} from "../init.ts";
import { generateRelayKey, relayPublicKeyHex, relayKeyValue, verifyRelayKeyPair, type RelayKeyFile } from "../keys.ts";
import { prepareAndSignPolicyBundle } from "../policy-bundle.ts";
import { ensureDirectory, readFileText, readPrivateFile, writePrivateFile } from "./files.ts";
import { pairedComposeKeep } from "./upgrade.ts";
import { createPlainDaemonFetch } from "./release-list-source.ts";
import { initWorkspaceInterpreter } from "./interpreter.ts";
import { buildKeyFromText } from "./scheduler-load.ts";
import { APP_ID_PATTERN, KMS_CA_PUBKEY_PATTERN } from "../lane-binding.ts";
import { checkedAddress, releaseHash } from "../chain/app-auth.ts";
import { kitErrorIn, readDstackKmsCa } from "../chain/checks.ts";
import { PAIRING_APPROVAL_LIFETIME_SECONDS, pairingGuardianJson, pairingGuardianPart } from "../chain/guardian.ts";
import { GUARDIAN_KEY_FILE, RECOVERY_KEY_FILE, generateGuardianKey, type GuardianKeyFile } from "../chain/guardian-key.ts";
import { checkReleaseCompose } from "../chain/release-compose.ts";
import { checkedRpcUrl, rpcLabel } from "../chain/rpc.ts";
import { builtInKmsCaPubkey, isLoopbackOrigin, pairingChainVerdict, pairingReleaseKeys, pairingRpcEndpoints, type PinnedReleaseKeys } from "../chain/trust.ts";
import { readGuardianKeyFile, writeGuardianKeyFile } from "./chain.ts";

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
  if (!TOKEN.test(relayId)) throw new RelayKitError("usage", "the relay_id must match [A-Za-z0-9._:-]{1,128}");
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

/** A new pairing's release delay (owner 2026-11-11, 13.13): a day to review each Gray release. */
export const DEFAULT_RELEASE_DELAY_HOURS = 24;

/** Hours as the commands take them (a whole number, 0 to 168), in seconds: the contract's bounds, 0 to 7 days. */
export function releaseDelayFlag(hours: string, flag: string): bigint {
  if (!/^(0|[1-9][0-9]{0,2})$/.test(hours) || Number(hours) > 168) throw new RelayKitError("usage", `${flag} is the release delay in whole hours, 0 to 168 (7 days)`);
  return BigInt(hours) * 3600n;
}

/** The pairing route on Gray's API origin (`@gray/control/stack-pairing`). */
export const PAIR_PATH = "/v1/lane-stack/pair";
/** How long the pairing request may take: the agent status post's limit (agent-status-report.ts), the same route family. */
export const PAIR_TIMEOUT_MS = 20_000;
/** The largest answer read: the pairing answer is under 2 KiB. */
const MAX_PAIR_ANSWER_BYTES = 64 * 1024;

/** A pairing answer read up to MAX_PAIR_ANSWER_BYTES; a longer one is cancelled unread and comes back `oversized` (malformed). */
async function pairAnswerText(response: Response): Promise<{ body: string; oversized: boolean }> {
  try {
    return { body: await readCappedText(response, MAX_PAIR_ANSWER_BYTES), oversized: false };
  } catch (error) {
    if (error instanceof BodyTooLargeError) return { body: "", oversized: true };
    throw error;
  }
}
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
   * Phase 2: the relay's release delay in hours (`--release-delay`, 0 to 168; default 24, 13.13), which the contract is
   * initialised with: how long a Gray release waits for the relay's veto before it takes effect without its approval.
   */
  readonly releaseDelayHours?: string;
  /**
   * The registry's pull token's user and expiry (`--registry-user`, `--registry-expires-at`; the expiry only with the
   * user, and optional since relay standard v1.7: without it the token has no known expiry), written as
   * `stack.registry.username` and `expires_at` instead of the user's placeholder; the token itself is the kit file
   * `registry-password`, which never passes through Gray.
   */
  readonly registryUser?: string;
  readonly registryExpiresAt?: string;
  /**
   * The release keys to read Gray's list with for a Gray on this machine's loopback (a test's fake console): its
   * operator's `--release-public-key` and `--release-freshness-public-key`. Refused for any other Gray, whose keys are
   * built into the kit (`../chain/trust.ts`), so no command Gray hands out can name a key of Gray's choosing.
   */
  readonly releaseKeys?: PinnedReleaseKeys;
  /**
   * The two RPC endpoints the operator chose (`--rpc`, twice), which the pairing reads the chain through and writes into
   * `chain.rpc`. Without them: on Base the public endpoints built into the kit, never the ones Gray's terms name.
   */
  readonly rpc?: readonly string[];
}

/** The pairing's guardian: the address, and the kit's key file when the kit holds the key. */
export interface PairingGuardian {
  readonly address: string;
  /** `guardian-key.json` in the kit. */
  readonly keyPath: string;
  /** Whether this pairing generated the key (false: kept the kit's). */
  readonly generated: boolean;
  /**
   * Phase 2: the relay's contract this pairing approved the first release for (Gray deploys it at Deploy), with the
   * release's hashes; null for a phase-1 pairing (Gray named no chain terms).
   */
  readonly phase2: { readonly contract: string; readonly chainId: number; readonly composeHash: string; readonly osImageHash: string; readonly releaseDelaySeconds: bigint } | null;
  /**
   * Phase 2: the relay's recovery key (`recovery-key.json`, the guardian key file's format), the only key that replaces
   * the guardian or itself on the contract. Only its address goes to Gray; the relay keeps the file offline.
   */
  readonly recovery: { readonly address: string; readonly keyPath: string; readonly generated: boolean } | null;
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
      /** Gray's signed release list as the pairing verified it, and with which key (`../chain/trust.ts`). */
      readonly releaseList: { readonly url: string; readonly keySource: string };
      /** What the kit took from Gray without a value of its own to hold it to, for the operator to look at. */
      readonly warnings: readonly string[];
      /** The guardian of the relay's contract (phase 2); its approvals of the first release come with P5's pairing answer. */
      readonly guardian: PairingGuardian;
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
 * Gray's signed list at `url`, verified with `keys` (never a key Gray's answer alone names) as the agent verifies it,
 * or the refusal code when it does not verify or cannot be read.
 */
async function verifiedPairingList(url: string, keys: PinnedReleaseKeys, nowMs: number, timeoutMs: number): Promise<{ readonly ok: true; readonly list: ReleaseList } | { readonly ok: false; readonly code: string }> {
  try {
    const verified = await fetchReleaseList(createPlainDaemonFetch({ timeoutMs }), url, {
      publicKey: lowerHexBytes(keys.publicKey) as Uint8Array,
      maxAgeSeconds: PAIRED_RELEASE_LIST_MAX_AGE,
      nowMs,
      freshness: keys.freshnessPublicKey === null ? null : { publicKey: lowerHexBytes(keys.freshnessPublicKey) as Uint8Array, url: releaseFreshnessLocation(url) },
    });
    return { ok: true, list: verified.list };
  } catch (error) {
    return { ok: false, code: error instanceof ReleaseListError ? error.code : "fetch_failed" };
  }
}

/**
 * The hashes of a verified list the guardian may approve at pairing: a compose release with a `git_commit` (no other is
 * ever acceptable) and an OS image whose own texts prove a production image (never a dev image, nor one its texts do
 * not bind), as `kind:hash`.
 */
function approvableHashes(list: ReleaseList): ReadonlySet<string> {
  const hashes = new Set<string>();
  for (const entry of list.releases) if (entry.git_commit !== null) hashes.add(`release:${entry.compose_hash}`);
  for (const image of list.osImages) {
    const provenance = osImageProvenance(image);
    if (provenance.ok && !provenance.isDev) hashes.add(`os_image:${image.os_image_hash}`);
  }
  return hashes;
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
 * the answer (S57). Nothing is written unless Gray pairs the key, but a phase-2 pairing's new guardian key, kept before
 * the request that carries its approvals (a retry reuses it); a refused, unanswered or unreadable pairing returns
 * `ok: false`. A wrong flag, a code that is no code, or a kit file already there (without `--force`) is refused before
 * any network.
 */
export async function pairWorkspace(options: PairWorkspaceOptions): Promise<PairWorkspaceResult> {
  const code = normalizePairingCode(options.code);
  if (code === null) throw new RelayKitError("usage", "--pair is not a pairing code (GRAY- and six groups of four characters, as the Integration page shows it)");
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
  const releaseDelaySeconds = releaseDelayFlag(options.releaseDelayHours ?? String(DEFAULT_RELEASE_DELAY_HOURS), "--release-delay");
  const pinned = pinnedReleaseKeys(gray, options.releaseKeys ?? null);
  const givenRpc = operatorRpc(options.rpc ?? null);
  if (copyKey) assertWritable(keyPath, force);
  assertWritable(configPath, force);
  if (composeImage !== null) assertWritable(composePath, force);
  if (existsSync(directory) && !statSync(directory).isDirectory()) throw new RelayKitError("io", `${directory} is not a directory`);
  const guardianKeyPath = join(directory, GUARDIAN_KEY_FILE);
  const pairingGuardian = guardianForPairing(guardianKeyPath);
  const recoveryKeyPath = join(directory, RECOVERY_KEY_FILE);
  const pairingRecovery = guardianForPairing(recoveryKeyPath);

  const key: RelayKeyFile =
    keySource === null ? await generateRelayKey() : await buildKeyFromText(readPrivateFile(keySource, "deployment key", 64 * 1024));
  if (keySource === null) await verifyRelayKeyPair(key);
  const publicKeyHex = relayPublicKeyHex(key);
  const fingerprint = relayKeyFingerprint(publicKeyHex) as string;
  const nowMs = options.nowMs ?? Date.now();
  const timeoutMs = options.timeoutMs ?? PAIR_TIMEOUT_MS;

  // Phase 2 (docs/design/relay-no-always-on-host.md 13.3): ask Gray's chain terms for this code first, check them and
  // the release they name (`phase2Part`), then compute the relay's contract and sign the guardian's approvals of the
  // first release with the kit's guardian key, which the pairing request then carries.
  const terms = await chainTerms(gray, code, timeoutMs);
  if (!terms.ok) return terms.failure;
  // A relay runs on its own contract: Gray names no chain terms when it cannot deploy one for this relay now.
  if (terms.chain === null) {
    return { ok: false, reason: "refused", status: null, code: null, text: "Gray offers no contract for this deployment now (no chain terms for this code); tell Gray, and pair again once it does" };
  }
  const prepared = await phase2Part(terms.chain, pairingGuardian, pairingRecovery.address, releaseDelaySeconds, nowMs, timeoutMs, { gray, pinned, rpc: givenRpc });
  if (!prepared.ok) return prepared.failure;
  const phase2 = prepared.pairing;
  const signature = bytesToLowerHex(await ed25519Sign(key.seed, pairMessage(code, publicKeyHex, phase2.part)));
  // A new guardian key is on disk (0600, synced) before the request that carries its approvals: Gray may keep them even
  // when its answer is lost, and a contract naming a guardian whose key this kit lost could never be paused or vetoed.
  // A retry finds the file and signs with the same key (`guardianForPairing`).
  if (pairingGuardian.generated !== null) {
    ensureDirectory(directory);
    writeGuardianKeyFile(guardianKeyPath, pairingGuardian.generated);
  }
  // The same for the recovery key: its address is in the contract Gray deploys.
  if (pairingRecovery.generated !== null) {
    ensureDirectory(directory);
    writeGuardianKeyFile(recoveryKeyPath, pairingRecovery.generated);
  }

  let status: number;
  let body: string;
  let oversized: boolean;
  try {
    const response = await fetch(`${gray}${PAIR_PATH}`, {
      method: "POST",
      // No header names the operator or the machine: the code, the key, the version and the guardian part are the whole request.
      headers: { "content-type": "application/json", accept: "application/json", "user-agent": "gray-assistant" },
      body: JSON.stringify({ code, public_key: publicKeyHex, signature, agent_version: RELAY_KIT_VERSION, guardian: phase2.part }),
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    status = response.status;
    ({ body, oversized } = await pairAnswerText(response));
  } catch {
    return {
      ok: false,
      reason: "unreachable",
      status: null,
      code: null,
      text: `Gray did not answer at ${gray}${PAIR_PATH}; check --gray and this machine's network, then run the command again (make a new code if the Integration page says this one was used)`,
    };
  }
  if (status < 200 || status > 299) {
    const refusal = refusalCode(body);
    return { ok: false, reason: "refused", status, code: refusal, text: refusal === null ? `Gray refused the pairing (HTTP ${status})` : PAIR_REFUSALS[refusal].text };
  }
  const answer = oversized || body.length > MAX_PAIR_ANSWER_BYTES ? null : readPairAnswer(body);
  if (answer === null) return { ok: false, reason: "malformed", status, code: null, text: `Gray's answer at ${gray}${PAIR_PATH} is not a pairing answer; upgrade gray-assistant, or tell Gray` };
  // Gray paired the key this request sent: an answer naming another is not this pairing's.
  if (answer.public_key !== publicKeyHex || answer.fingerprint !== fingerprint) {
    return { ok: false, reason: "malformed", status, code: null, text: "Gray's answer names another key than the one this command sent; tell Gray, and pair again with a new code" };
  }
  // The contract's address is the relay id's: an answer for another relay than the terms named is not this pairing's.
  if (answer.relay_id !== phase2.terms.relay_id) {
    return { ok: false, reason: "malformed", status, code: null, text: "Gray's answer names another relay_id than its chain terms did; tell Gray, and pair again with a new code" };
  }

  const placeholders: string[] = [];
  const image = answer.image !== null && isStackRelayImage(answer.image) ? answer.image : null;
  const registryHost = answer.registry !== null && REGISTRY_HOST.test(answer.registry) ? answer.registry : image === null ? null : relayImageRegistry(image);
  if (registryHost === null) placeholders.push("stack.registry.host");
  if (image === null) placeholders.push("stack.relay_images");
  if (registryLogin === null) placeholders.push("stack.registry.username");
  // Written out: a phase-2 config has no `tunnel` member (no agent here keeps one), whose origin was the default. The
  // VM's measured identity names this URL (stack-boot.ts), so it stays Gray's record's (the relay tunnel's origin
  // unless the relay named its own).
  const name = answer.tunnel === null ? null : tunnelName(answer.relay_id, answer.tunnel.zone);
  const tokenUrl = answer.token_url ?? (name === null ? TOKEN_URL_PLACEHOLDER : `https://${name}`);
  if (tokenUrl === TOKEN_URL_PLACEHOLDER) placeholders.push("stack.token_url");
  // The list and keys the guardian checked the release with, not what the answer names again: they must agree.
  const release = phase2.release;
  const warnings = [...phase2.warnings];
  if (answer.release !== null && (answer.release.list !== release.list || answer.release.public_key !== release.publicKey)) {
    warnings.push(`Gray's pairing answer names another release list or key than its chain terms did; the config keeps the ones the guardian checked (${release.list})`);
  }
  const text = pairedConfigText({
    relayId: answer.relay_id,
    release: { list: release.list, publicKey: release.publicKey, freshnessPublicKey: release.freshnessPublicKey },
    reportOrigin: answer.report_origin,
    tokenUrl,
    tunnel: null,
    relayImage: image ?? relayImagePlaceholder(registryHost ?? REGISTRY_HOST_PLACEHOLDER),
    registryHost: registryHost ?? REGISTRY_HOST_PLACEHOLDER,
    registryLogin,
    pairing: { gray, fingerprint, pairedAt: utcSeconds(answer.paired_ms) },
    acceptedAtPairing: [],
    chain: {
      chainId: phase2.terms.chain_id,
      rpc: [phase2.terms.rpc[0]!, phase2.terms.rpc[1]!],
      proposer: phase2.terms.proposer,
      guardian: phase2.part.guardian,
      guardianKey: GUARDIAN_KEY_FILE,
      contract: phase2.part.contract,
      dstackKms: phase2.terms.dstack_kms,
      releaseDelaySeconds,
    },
  });

  ensureDirectory(directory);
  const files: string[] = [];
  if (copyKey) {
    writePrivateFile(keyPath, `${toJsonString(relayKeyValue(key))}\n`, { force });
    files.push(keyPath);
  }
  // 0600 like every kit file.
  writePrivateFile(configPath, text, { force });
  files.push(configPath);
  // Both were written before the request (above).
  if (pairingGuardian.generated !== null) files.push(guardianKeyPath);
  if (pairingRecovery.generated !== null) files.push(recoveryKeyPath);
  // Public: it names the image and the mounts, no secret, and `docker compose` reads it as the operator.
  if (composeImage !== null) {
    // A kit paired before (any kit, those of the old name too) keeps its project and state volume: a new pairing keeps the state.
    const keep = existsSync(composePath) ? pairedComposeKeep(readFileText(composePath, "compose file", 1024 * 1024)) : null;
    writePublicFile(composePath, pairedComposeText(composeImage, answer.relay_id, keep ?? {}), force);
    files.push(composePath);
  }
  return {
    ok: true,
    directory,
    relayId: answer.relay_id,
    publicKeyHex,
    fingerprint,
    keyPath,
    configPath,
    composePath: composeImage === null ? null : composePath,
    files,
    placeholders,
    image: image !== null,
    releaseList: { url: release.list, keySource: phase2.keySource },
    warnings,
    guardian: {
      address: pairingGuardian.address,
      keyPath: pairingGuardian.keyPath,
      generated: pairingGuardian.generated !== null,
      phase2: { contract: phase2.part.contract, chainId: phase2.terms.chain_id, composeHash: phase2.terms.compose_hash, osImageHash: phase2.terms.os_image_hash, releaseDelaySeconds },
      recovery: { address: pairingRecovery.address, keyPath: recoveryKeyPath, generated: pairingRecovery.generated !== null },
    },
  };
}

/**
 * `--release-public-key` (and its freshness key): for a Gray on loopback only, checked before any network. Any other
 * Gray's keys are built into the kit, so a command Gray hands out cannot swap in a key of its own.
 */
function pinnedReleaseKeys(gray: string, pinned: PinnedReleaseKeys | null): PinnedReleaseKeys | null {
  if (pinned === null) return null;
  if (!isLoopbackOrigin(gray)) {
    throw new RelayKitError("usage", "--release-public-key is for a test Gray on this machine's loopback only: Gray's own release keys are built into gray-assistant");
  }
  const hex = /^[0-9a-f]{64}$/;
  if (!hex.test(pinned.publicKey) || (pinned.freshnessPublicKey !== null && (!hex.test(pinned.freshnessPublicKey) || pinned.freshnessPublicKey === pinned.publicKey))) {
    throw new RelayKitError("usage", "--release-public-key and --release-freshness-public-key are two keys of 32 bytes as 64 lower-case hex");
  }
  return pinned;
}

/** `--rpc`, given twice: two endpoints the kit takes (https, or http on loopback) of different origins. Checked before any network. */
function operatorRpc(rpc: readonly string[] | null): readonly [string, string] | null {
  if (rpc === null) return null;
  if (rpc.length !== 2) throw new RelayKitError("usage", "--rpc is given twice: two RPC endpoints of different providers, which the chain checks read and must agree");
  const checked = [checkedRpcUrl(rpc[0]!, "--rpc"), checkedRpcUrl(rpc[1]!, "--rpc")] as const;
  if (new URL(checked[0]).origin === new URL(checked[1]).origin) throw new RelayKitError("usage", "--rpc names one origin twice: give two independent endpoints (two providers)");
  return checked;
}

/** A phase-2 pairing's terms, the guardian part made from them, and what the kit checked them with. */
interface Phase2Pairing {
  readonly terms: PairChainTerms;
  readonly part: PairGuardian;
  /** Gray's list as the guardian checked the release in it: the terms' URL and the keys of `../chain/trust.ts`. */
  readonly release: { readonly list: string; readonly publicKey: string; readonly freshnessPublicKey: string | null };
  /** Where those keys come from, for the operator's line. */
  readonly keySource: string;
  readonly warnings: readonly string[];
}

type PairFailure = Extract<PairWorkspaceResult, { ok: false }>;

/**
 * `POST /v1/lane-stack/pair/chain`: Gray's chain terms for the code, null for a relay not on phase 2 or a Gray that has
 * no such route yet (404 without a pairing refusal). Nothing is spent by it; a refusal of the code is the pairing's.
 */
async function chainTerms(gray: string, code: string, timeoutMs: number): Promise<{ readonly ok: true; readonly chain: PairChainTerms | null } | { readonly ok: false; readonly failure: PairFailure }> {
  let status: number;
  let body: string;
  let oversized: boolean;
  try {
    const response = await fetch(`${gray}${PAIR_CHAIN_PATH}`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", "user-agent": "gray-assistant" },
      body: JSON.stringify({ code }),
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    status = response.status;
    ({ body, oversized } = await pairAnswerText(response));
  } catch {
    return {
      ok: false,
      failure: { ok: false, reason: "unreachable", status: null, code: null, text: `Gray did not answer at ${gray}${PAIR_CHAIN_PATH}; check --gray and this machine's network, then run the command again` },
    };
  }
  if (status < 200 || status > 299) {
    const refusal = refusalCode(body);
    if (status === 404 && refusal === null) return { ok: true, chain: null };
    return { ok: false, failure: { ok: false, reason: "refused", status, code: refusal, text: refusal === null ? `Gray refused the pairing's chain terms (HTTP ${status})` : PAIR_REFUSALS[refusal].text } };
  }
  let parsed;
  try {
    parsed = oversized || body.length > MAX_PAIR_ANSWER_BYTES ? null : pairChainAnswerSchema.safeParse(parsePlainJson(body));
  } catch {
    parsed = null;
  }
  if (parsed === null || !parsed.success) {
    return { ok: false, failure: { ok: false, reason: "malformed", status, code: null, text: `Gray's answer at ${gray}${PAIR_CHAIN_PATH} is not chain terms; upgrade gray-assistant, or tell Gray` } };
  }
  return { ok: true, chain: parsed.data.chain };
}

/** JSON text as plain values, integers as numbers (the terms' chain id is one). */
function parsePlainJson(text: string): unknown {
  const value = parseStrict(text);
  const plain = (v: Json): unknown => {
    if (typeof v === "bigint") return Number.isSafeInteger(Number(v)) ? Number(v) : v;
    if (Array.isArray(v)) return v.map(plain);
    if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x as Json)]));
    return v;
  };
  return plain(value);
}

/** A hash as Gray's release list writes it: 64 lower hex, without 0x. */
const bareHash = (hash: string): string => hash.replace(/^0x/, "").toLowerCase();

/**
 * The guardian part for Gray's terms, made only once the terms hold up against what the kit knows without Gray
 * (`../chain/trust.ts`, provider review 2026-11-17 items 17 and 18), every refusal before the code is spent:
 *
 * 1. Base, unless Gray is a test's on loopback (then another chain is taken with a warning), and on Base the DstackKms
 *    built into the kit; the chain is read through the operator's `--rpc`, else on Base the kit's own public endpoints,
 *    never Gray's (`pairingRpcEndpoints`), two of different origins, which `chain.rpc` then names;
 * 2. Gray's signed release list, read with a release key built into the kit (or the one pinned for a test Gray on
 *    loopback), never one the terms alone name; terms without a list are refused;
 * 3. the release they name is in it: a compose release with a commit and a production OS image;
 * 4. the chain, through those two endpoints: both answer the terms' chain and the same DstackKms KMS key, which on Base
 *    must be the one built into the kit;
 * 5. the compose passes the checks `releases check` and `deliver` run (its published text, the closed policy with the
 *    list's image and the release keys, the KMS lease, the vault bind), with that KMS as its key provider.
 *
 * Then the contract's address for this guardian and recovery address and the approvals, signed with the kit's guardian
 * key and valid for `PAIRING_APPROVAL_LIFETIME_SECONDS`.
 */
async function phase2Part(
  terms: PairChainTerms,
  guardian: { readonly address: string; readonly keyPath: string; readonly generated: GuardianKeyFile | null },
  recovery: string,
  releaseDelaySeconds: bigint,
  nowMs: number,
  timeoutMs: number,
  trust: { readonly gray: string; readonly pinned: PinnedReleaseKeys | null; readonly rpc: readonly [string, string] | null },
): Promise<{ readonly ok: true; readonly pairing: Phase2Pairing } | { readonly ok: false; readonly failure: PairFailure }> {
  const refused = (text: string): { ok: false; failure: PairFailure } => ({ ok: false, failure: { ok: false, reason: "refused", status: null, code: null, text } });
  const malformed = (text: string): { ok: false; failure: PairFailure } => ({ ok: false, failure: { ok: false, reason: "malformed", status: null, code: null, text } });
  const warnings: string[] = [];
  const chain = pairingChainVerdict(trust.gray, terms.chain_id, terms.dstack_kms);
  if (!chain.ok) return refused(chain.text);
  if (chain.warning !== null) warnings.push(chain.warning);
  // The endpoints every chain read from now on goes through: the operator's, else on Base the kit's own, never Gray's.
  const chosen = pairingRpcEndpoints(terms.chain_id, terms.rpc, trust.rpc);
  if (chosen.note !== null) warnings.push(chosen.note);
  let rpc: [string, string];
  try {
    rpc = [checkedRpcUrl(chosen.rpc[0]!, "the first RPC endpoint"), checkedRpcUrl(chosen.rpc[1]!, "the second RPC endpoint")];
  } catch {
    return malformed("Gray's chain terms name an RPC endpoint the kit cannot use; tell Gray");
  }
  // One provider answering twice is one witness (chain/config.ts refuses such a config too).
  if (new URL(rpc[0]).origin === new URL(rpc[1]).origin) return malformed("Gray's chain terms name one RPC origin twice; the chain checks need two independent endpoints: tell Gray (the code is not spent)");

  const keys = pairingReleaseKeys(trust.gray, terms.release, trust.pinned);
  if (!keys.ok || terms.release === null) return refused(keys.ok ? "Gray's chain terms name no signed release list" : keys.text);
  const listUrl = terms.release.list;
  const listed = await verifiedPairingList(listUrl, keys, nowMs, timeoutMs);
  if (!listed.ok) return refused(`Gray's signed release list does not verify with ${keys.source} (${listed.code}), so the guardian approves nothing; run the command again, and tell Gray if it repeats (the code is not spent)`);
  const approvable = approvableHashes(listed.list);
  if (!approvable.has(`release:${bareHash(terms.compose_hash)}`)) return refused("The release Gray will deploy is not a release in its signed list, so the guardian does not approve it; tell Gray (the code is not spent)");
  if (!approvable.has(`os_image:${bareHash(terms.os_image_hash)}`)) return refused("The OS image Gray will deploy is not a production image its signed list proves, so the guardian does not approve it; tell Gray (the code is not spent)");

  // The KMS the contract's VMs take their keys from: Base's, built in, which the terms' endpoints must read as well.
  const builtIn = builtInKmsCaPubkey(terms.chain_id, terms.dstack_kms);
  let onChain: string | null;
  try {
    onChain = await readDstackKmsCa(rpc, terms.chain_id, checkedAddress(terms.dstack_kms, "Gray's DstackKms"), { timeoutMs });
  } catch (error) {
    const detail = kitErrorIn(error)?.detail ?? "they could not be read";
    return refused(`the RPC endpoints ${rpcLabel(rpc[0])} and ${rpcLabel(rpc[1])} do not read the chain as Gray's terms say (${detail}); run the command again, and tell Gray if it repeats (the code is not spent)`);
  }
  if (builtIn !== null && onChain !== builtIn) {
    return refused(
      `${rpcLabel(rpc[0])} and ${rpcLabel(rpc[1])} answer Base DstackKms's KMS key as ${onChain ?? "none"}, not the one built into gray-assistant (${builtIn.slice(-16)}): they do not read Base as it is, or Phala changed its KMS; tell Gray (the code is not spent)`,
    );
  }
  const kmsCa = builtIn ?? onChain;
  if (kmsCa === null) warnings.push(`DstackKms ${terms.dstack_kms} on chain ${terms.chain_id} publishes no KMS key, so the key provider of the release Gray will deploy is not checked here`);
  const content = checkReleaseCompose(listed.list, terms.compose_hash, {
    kmsCaPubkey: kmsCa ?? "",
    releasePublicKey: keys.publicKey,
    ...(keys.freshnessPublicKey === null ? {} : { releaseFreshnessPublicKey: keys.freshnessPublicKey }),
    preLaunchSha256: null,
  });
  const failing = content.checks.filter((check) => !check.ok && !(kmsCa === null && check.name === "key_provider"));
  if (failing.length > 0) {
    return refused(`The release Gray will deploy does not pass your checks (${failing.map((check) => `${check.name}: ${check.detail}`).join("; ")}), so the guardian does not approve it; tell Gray (the code is not spent)`);
  }

  const privateKey = guardian.generated?.privateKey ?? readGuardianKeyFile(guardian.keyPath).privateKey;
  const part = await pairingGuardianPart({
    deployment: {
      relayId: terms.relay_id,
      proposer: checkedAddress(terms.proposer, "Gray's proposer"),
      proposerRecovery: checkedAddress(terms.proposer_recovery, "Gray's proposer recovery key"),
      guardian: checkedAddress(guardian.address, "the guardian"),
      recovery: checkedAddress(recovery, "the recovery address"),
      delaySeconds: releaseDelaySeconds,
      composeHashes: [releaseHash(terms.compose_hash, "the compose hash")],
      osImageHashes: [releaseHash(terms.os_image_hash, "the OS image hash")],
    },
    chainId: terms.chain_id,
    deadline: BigInt(Math.floor(nowMs / 1000)) + PAIRING_APPROVAL_LIFETIME_SECONDS,
    privateKey,
  });
  const wire = pairGuardianSchema.parse(pairingGuardianJson(part));
  return {
    ok: true,
    pairing: { terms: { ...terms, rpc }, part: wire, release: { list: listUrl, publicKey: keys.publicKey, freshnessPublicKey: keys.freshnessPublicKey }, keySource: keys.source, warnings },
  };
}

/**
 * The pairing's guardian, decided before any network: the kit's `guardian-key.json` when there is one (kept, never
 * replaced, not even with `--force`: a contract may already name it), or a new key (written once Gray pairs).
 */
function guardianForPairing(keyPath: string): { readonly address: string; readonly keyPath: string; readonly generated: GuardianKeyFile | null } {
  let existing = false;
  try {
    lstatSync(keyPath);
    existing = true;
  } catch {
    // None yet: generate one.
  }
  if (existing) return { address: readGuardianKeyFile(keyPath).address, keyPath, generated: null };
  const generated = generateGuardianKey();
  return { address: generated.address, keyPath, generated };
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
    guardian: result.guardian.address,
    guardian_key_file: result.guardian.keyPath,
    ...(result.guardian.recovery === null ? {} : { recovery: result.guardian.recovery.address, recovery_key_file: result.guardian.recovery.keyPath }),
    ...(result.guardian.phase2 === null
      ? {}
      : { contract: result.guardian.phase2.contract, chain_id: result.guardian.phase2.chainId, release_delay_seconds: Number(result.guardian.phase2.releaseDelaySeconds), approved: { compose_hash: result.guardian.phase2.composeHash, os_image_hash: result.guardian.phase2.osImageHash } }),
    release_list: result.releaseList.url,
    release_key: result.releaseList.keySource,
    warnings: [...result.warnings],
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
