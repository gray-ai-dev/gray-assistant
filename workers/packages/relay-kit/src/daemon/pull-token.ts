/**
 * The pull-token service of a relay-stack lane (docs/confidential-lane-supply-implementation.md §4,
 * S9–S13, S11a, S11b, S51, S54): the relay's half of plan B. A boot's measured pre-launch script
 * (`deploy/tee/pre-launch.stack.sh`) measures the relay identity it was deployed with (`gray-stack-identity`),
 * asks for a nonce, binds it and a one-time RSA-3072 key into a TDX quote, and sends the quote, its event log
 * and the exact app-compose text. This service checks all of it (S11, in order, one closed code per refusal):
 * the identity must name this relay, its token service and its key. It answers with the registry credential
 * encrypted to that key (RSA-OAEP with SHA-256 and MGF1-SHA256, the envelope the shell opens with `openssl
 * pkeyutl`, S10), and with the image this relay chose for the boot and its Ed25519 signature over
 * `gray-relay-image/v1\n<nonce>\n<image>` (S51): the relay vouches for its image, which pre-launch verifies with
 * the measured key before it pulls it.
 *
 * The wire, byte for byte what pre-launch sends and reads:
 *
 *     POST /v1/pull-token/challenge  {}
 *       → {"nonce":"<64 hex>","expires_at":"YYYY-MM-DDTHH:MM:SSZ"}
 *     POST /v1/pull-token  {"nonce","spki_der_b64","quote","event_log","app_compose"}
 *       → {"ciphertext_b64":"<base64>","image":"<registry>/<repo>@sha256:<64 hex>","image_sig":"<128 hex>"}
 *
 * A refusal is `{"error":"<code>"}` and nothing else; why it failed stays in the relay's own log, and
 * no log line carries the credential, the request body or a value from the app-compose.
 *
 * Reused, not rewritten: the injected `QuoteVerifier` (the agent passes the same `@phala/dcap-qvl`
 * adapter `attestLane` loads), `@gray/lane-verify`'s event-log parser, RTMR3 replay,
 * `extractMeasurements` and `stackBootFacts` (S52), the daemon's release decision (`RelayDaemon.releaseForBoot`:
 * the rule credential intake applies, with S11b's OS image acceptance), `laneBindingChecks` (S12) and
 * `@gray/lane-compose`'s `checkSupplyAppCompose` (S7) with S55's expectation. New here: the nonce store, S9.4's
 * report_data, the identity rule, the envelope and the image signature.
 *
 * Pure code (WebCrypto and `@noble/hashes`), so it runs in Node and workerd; the issue record (S13)
 * is an injected writer, which the Node agent appends to a local file.
 */
import { isObject, parseStrict, toJsonString, type Json, type JsonObject } from "@gray/json";
import { checkSupplyAppCompose, type SupplyExpectation } from "@gray/lane-compose";
import {
  extractMeasurements,
  parseEventLogText,
  relayImageMessage,
  replayEventLog,
  stackBootFacts,
  type QuoteAppraisal,
  type QuoteMeasurements,
  type QuoteVerifier,
  type ReleaseStack,
  type StackIdentity,
} from "@gray/lane-verify";
import { bytesToHex, hexBytes, randomBytes, utf8Bytes, utf8Text } from "@gray/relay-connector";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { decodeBase64, encodeBase64 } from "../base64.ts";
import { RelayKitError } from "../errors.ts";
import { laneBindingChecks, type LaneBinding } from "../lane-binding.ts";
import type { SchedulerHttpRequest, SchedulerHttpResponse } from "../scheduler/handler.ts";
import type { StackConfig } from "./config.ts";
import { RELEASE_STATUS_PATH } from "./release-status.ts";
import type { DaemonLog, StackBindingChoice, StackReleaseDecision } from "./types.ts";

export const PULL_TOKEN_CHALLENGE_PATH = "/v1/pull-token/challenge";
export const PULL_TOKEN_PATH = "/v1/pull-token";
/** S9.4's domain separator: report_data = SHA-512(prefix || nonce_hex || "\n" || spki_der). */
export const PULL_TOKEN_REPORT_DATA_PREFIX = "gray-relay-pull-token/v1\n";
/** S11: a nonce answers one token request within this window. */
export const PULL_TOKEN_NONCE_TTL_MS = 60_000;
/** The outstanding nonces kept in memory; past it a challenge is refused rather than evicting a live one. */
export const DEFAULT_MAX_PULL_TOKEN_NONCES = 1024;
/** The largest token request read: a quote, its event log and an app-compose are tens of kilobytes. */
export const MAX_PULL_TOKEN_REQUEST_BYTES = 1024 * 1024;
/** S9.7: pre-launch refuses a decrypted credential over this many bytes. */
export const MAX_PULL_TOKEN_ENVELOPE_BYTES = 300;
/** S9.4: the one key size pre-launch makes (`rsa_keygen_bits:3072`, exponent 65537). */
export const PULL_TOKEN_RSA_BITS = 3072;

/** An RSA-3072 SubjectPublicKeyInfo is 422 bytes; anything much larger is not one. */
const MAX_SPKI_BYTES = 1024;
/** A TDX quote with its certification chain is about 5 KiB. */
const MAX_QUOTE_BYTES = 64 * 1024;
const REQUEST_MEMBERS = Object.freeze(["app_compose", "event_log", "nonce", "quote", "spki_der_b64"]);
/** The TCB statuses S11 accepts, as `verifyAttestation` does for credential intake. */
const ACCEPTED_TCB_STATUSES: readonly string[] = Object.freeze(["UpToDate"]);

/**
 * Every refusal and its HTTP status. The S11 checks run in the order listed from `nonce_unknown` to
 * `app_compose_refused`; the rest are the request itself or the service's own state. A 5xx holds the boot:
 * pre-launch waits it out and asks again, so a boot held for a release or an OS image the relay has not accepted
 * yet goes on once it is accepted, with no restart (S58, OP7). `@gray/control`'s `TOKEN_SERVICE_CODES` lists the
 * same codes (a test holds them equal).
 */
export const PULL_TOKEN_REFUSALS = Object.freeze({
  method_not_allowed: 405,
  request_too_large: 413,
  request_invalid: 400,
  spki_invalid: 400,
  challenge_capacity: 503,
  registry_credential_expired: 503,
  relay_image_unlisted: 503,
  verifier_busy: 503,
  nonce_unknown: 403,
  nonce_used: 403,
  nonce_expired: 403,
  quote_invalid: 403,
  tee_not_tdx: 403,
  tcb_not_up_to_date: 403,
  event_log_invalid: 403,
  rtmr3_mismatch: 403,
  event_log_after_system_ready: 403,
  stack_identity_missing: 403,
  stack_identity_invalid: 403,
  stack_identity_mismatch: 403,
  report_data_mismatch: 403,
  compose_hash_mismatch: 403,
  release_list_unavailable: 503,
  compose_not_listed: 403,
  release_rejected: 403,
  release_not_accepted: 503,
  os_image_missing: 403,
  os_image_not_listed: 403,
  os_image_rejected: 403,
  os_image_dev: 403,
  os_image_unverified: 403,
  os_image_not_accepted: 503,
  os_image_retiring: 403,
  os_image_measurements: 403,
  app_id_mismatch: 403,
  key_provider_mismatch: 403,
  release_not_stack: 403,
  pre_launch_not_pinned: 403,
  app_compose_refused: 403,
  issue_record_failed: 500,
} as const);

export type PullTokenRefusal = keyof typeof PULL_TOKEN_REFUSALS;

/** Whether a refusal holds the boot rather than stopping it: a 5xx or 429, which pre-launch waits out. */
export function pullTokenRefusalHolds(code: PullTokenRefusal): boolean {
  const status: number = PULL_TOKEN_REFUSALS[code];
  return status >= 500 || status === 429;
}

/** The refusals about the boot's release or OS image: the latest refusal names the compose hash for these (S58). */
const RELEASE_REFUSALS: ReadonlySet<PullTokenRefusal> = new Set<PullTokenRefusal>([
  "compose_not_listed",
  "release_rejected",
  "release_not_accepted",
  "release_not_stack",
  "pre_launch_not_pinned",
  "os_image_missing",
  "os_image_not_listed",
  "os_image_rejected",
  "os_image_dev",
  "os_image_unverified",
  "os_image_not_accepted",
  "os_image_retiring",
  "os_image_measurements",
]);

/**
 * S58: what the token service last answered a booting VM, the agent status's `boot` (`@gray/control/stack-agent`):
 * the refusal, whether it held the boot, when it first and last answered so and how often, and the compose hash
 * when the code is about a release or an OS image and the boot got that far. Null once a token is issued after it.
 */
export interface PullTokenBoot {
  readonly code: PullTokenRefusal;
  readonly held: boolean;
  readonly firstMs: number;
  readonly lastMs: number;
  readonly count: number;
  readonly composeHash: string | null;
}

/** What a boot that passes S11 receives (S9.7), before encryption. */
export interface PullTokenCredential {
  readonly registry: string;
  readonly username: string;
  readonly password: string;
  /**
   * `YYYY-MM-DDTHH:MM:SSZ`, or null for a token with no known expiry (v1.7). The member is always in the envelope:
   * pre-launch (deploy/tee/pre-launch.stack.sh) takes exactly these four keys and reads only the user and password.
   */
  readonly expiresAt: string | null;
}

/** S13: one issue as the append-only record keeps it. Never the credential. */
export interface PullTokenIssue {
  /** A fresh id per issue (`i` and 32 hex), so a report to Gray can be sent again without counting twice. */
  readonly issueId: string;
  readonly atMs: number;
  readonly composeHash: string;
  /** SHA-256 of the raw quote bytes (not of their hex). */
  readonly quoteSha256: string;
  /** S54: the boot's challenge nonce, which its `gray-relay-image` event names; credential intake looks it up. */
  readonly nonce: string;
  /** S51: the image this issue named for the boot (the current image then). */
  readonly relayImage: string;
  /** The token's expiry, null when it has no known one (v1.7). */
  readonly expiresAt: string | null;
  readonly expiresAtMs: number | null;
}

export interface PullTokenServiceOptions {
  /** The config's `relay_id`: what the boot's `gray-stack-identity` must name (S54). */
  readonly relayId: string;
  readonly stack: StackConfig;
  /** S54: the relay key's public half, 64 lower hex, which the identity must name (the key the image signature verifies with). */
  readonly relayPublicKey: string;
  /** S51: Ed25519 with the relay's key over `message` (`relayImageMessage`); 64 bytes. */
  readonly signImage: (message: Uint8Array) => Promise<Uint8Array>;
  /**
   * S53: the image boots get now (control.json's `stack_current_image`, else the config's); checked against
   * `stack.relay_images` at every request. Defaults to `stack.currentImage`.
   */
  readonly currentImage?: () => string;
  /**
   * S53: brings `currentImage` up to date (the daemon re-reads control.json) before a token request names its image,
   * so a rollout written just before the boot asked is the one it gets, however busy the daemon's tick is. Its
   * failure keeps the image the daemon holds.
   */
  readonly refreshImages?: () => Promise<void>;
  /** The registry token from `stack.registry.password_file`. */
  readonly password: string;
  readonly quoteVerifier: QuoteVerifier;
  /** The daemon's release decision for a boot (`RelayDaemon.releaseForBoot`). */
  readonly releaseForBoot: (composeHash: string, osImageHash: string | null) => StackReleaseDecision;
  /**
   * S12/P12: the binding a quote with this app-id event and key-provider CA is checked against
   * (`RelayDaemon.stackBindingFor`: the held instance, or Gray's candidate that the quote would prove; rule 4 asks Gray
   * first when it names none). Null refuses `app_id_mismatch`. Defaults to the config's `stack.instance`.
   */
  readonly stackBinding?: (appId: string | null, kmsCaPubkey: string | null) => Promise<StackBindingChoice | null>;
  /**
   * P12 rule 3: a candidate this request's quote proved, with every other S11 check passed (the release decision, the
   * identity naming this relay); the daemon adopts it (`RelayDaemon.adoptStackCandidate`). Its failure issues anyway.
   */
  readonly adoptCandidate?: (binding: LaneBinding) => Promise<void>;
  /** Append one issue to the S13 record; when it throws, nothing is issued. */
  readonly record: (issue: PullTokenIssue) => Promise<void>;
  readonly log: DaemonLog;
  /** Wall-clock Unix milliseconds. */
  readonly now: () => number;
  readonly random?: (length: number) => Uint8Array;
  readonly maxNonces?: number;
  /**
   * How many token requests may be in the quote verification at once; one more is refused with
   * `verifier_busy` before its nonce is spent. The Node agent passes `os.availableParallelism()`:
   * a DCAP verification is CPU work, and that is how many it can run side by side. Default 1.
   */
  readonly maxVerifications?: number;
  /**
   * The relay's signed acceptance status (`release-status.ts`), served on `GET /v1/releases/status`
   * beside the token routes so Gray's release tooling can read it through the same public origin.
   */
  readonly releaseStatus?: () => Promise<JsonObject>;
  /**
   * S58: called when a refusal on the token routes starts a new latest refusal (`boot()`: the first one, or another
   * code than the last), so the agent sends its status at once; the same code again only updates the record, which the
   * status's own spacing sends.
   */
  readonly onRefusal?: (boot: PullTokenBoot) => void;
}

export interface PullTokenService {
  /** Answer a request on one of the two routes; null for any other path, which the caller serves. */
  handle(request: SchedulerHttpRequest): Promise<SchedulerHttpResponse | null>;
  /** How many nonces the store holds now (live or used, until they expire). */
  outstanding(): number;
  /** S58: the latest refusal of a booting VM, or null (none yet, or a token issued since). */
  boot(): PullTokenBoot | null;
}

/** The record's count stops here (the agent status's bound). */
const MAX_BOOT_COUNT = 1_000_000_000;

/** S9.4: the 64 bytes pre-launch asks the guest agent to put in the quote. */
export function pullTokenReportData(nonceHex: string, spkiDer: Uint8Array): Uint8Array {
  const prefix = utf8Bytes(`${PULL_TOKEN_REPORT_DATA_PREFIX}${nonceHex}\n`);
  const preimage = new Uint8Array(prefix.length + spkiDer.length);
  preimage.set(prefix, 0);
  preimage.set(spkiDer, prefix.length);
  return sha512(preimage);
}

/** S9.7: the envelope's plaintext, exactly the four members in the plan's order. */
export function pullTokenEnvelopeText(credential: PullTokenCredential): string {
  return JSON.stringify({
    registry: credential.registry,
    username: credential.username,
    password: credential.password,
    expires_at: credential.expiresAt,
  });
}

/** The credential the service seals for `stack` with `password`, the registry token file's one line. */
function pullTokenCredential(stack: Pick<StackConfig, "registry">, password: string): PullTokenCredential {
  return { registry: stack.registry.host, username: stack.registry.username, password, expiresAt: stack.registry.expiresAt };
}

/**
 * Why `password` cannot be the token service's credential, or null: it must be one token of
 * printable characters, and S9.7's envelope must fit pre-launch's RSA-OAEP block. The agent refuses
 * to start on it; `doctor` and the host install's config check say so first. Names members only.
 */
export function pullTokenCredentialProblem(stack: Pick<StackConfig, "registry">, password: string): string | null {
  if (!/^[\x21-\x7e]{1,256}$/.test(password)) return "stack.registry.password_file must hold one token of printable characters, no space";
  if (utf8Bytes(pullTokenEnvelopeText(pullTokenCredential(stack, password))).length > MAX_PULL_TOKEN_ENVELOPE_BYTES) {
    return `stack.registry: the credential envelope is over ${MAX_PULL_TOKEN_ENVELOPE_BYTES} bytes (S9.7); use a shorter username or token`;
  }
  return null;
}

/**
 * Import pre-launch's one-time key, or null. Only an RSA-3072 key with exponent 65537 is taken, and
 * only in its canonical DER: the bytes S9.4 binds into the quote must be the key the envelope is for.
 */
export async function importPullTokenKey(spkiDer: Uint8Array): Promise<CryptoKey | null> {
  if (spkiDer.length === 0 || spkiDer.length > MAX_SPKI_BYTES) return null;
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("spki", spkiDer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
  } catch {
    return null;
  }
  // Read structurally: Node and workerd type `publicExponent` differently (Uint8Array, ArrayBuffer).
  const algorithm = key.algorithm as { readonly modulusLength?: unknown; readonly publicExponent?: unknown };
  if (algorithm.modulusLength !== PULL_TOKEN_RSA_BITS) return null;
  const exponent = algorithm.publicExponent;
  const exponentBytes = exponent instanceof Uint8Array ? exponent : exponent instanceof ArrayBuffer ? new Uint8Array(exponent) : null;
  if (exponentBytes === null || bytesToHex(exponentBytes).replace(/^(00)+/, "") !== "010001") return null;
  let exported: Uint8Array;
  try {
    exported = new Uint8Array((await crypto.subtle.exportKey("spki", key)) as ArrayBuffer);
  } catch {
    return null;
  }
  return sameBytes(exported, spkiDer) ? key : null;
}

/** RSA-OAEP (SHA-256, MGF1-SHA256, no label) of the envelope text: WebCrypto uses the OAEP hash for MGF1. */
export async function sealPullTokenEnvelope(key: CryptoKey, text: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, utf8Bytes(text)));
}

/** The validated token request. */
interface TokenRequest {
  readonly nonce: string;
  readonly spkiDer: Uint8Array;
  readonly quote: Uint8Array;
  readonly eventLog: string;
  readonly appCompose: string;
}

type Verdict =
  | { readonly ok: true; readonly composeHash: string; readonly candidate: LaneBinding | null }
  | { readonly ok: false; readonly code: PullTokenRefusal; readonly composeHash?: string; readonly problems?: string };

interface NonceEntry {
  readonly expiresAtMs: number;
  used: boolean;
}

/** Build the service. Throws `RelayKitError` (usage) when the credential cannot make a valid envelope. */
export function createPullTokenService(options: PullTokenServiceOptions): PullTokenService {
  const stack = options.stack;
  const problem = pullTokenCredentialProblem(stack, options.password);
  if (problem !== null) throw new RelayKitError("usage", problem);
  const envelopeText = pullTokenEnvelopeText(pullTokenCredential(stack, options.password));
  const random = options.random ?? randomBytes;
  const currentImage = options.currentImage ?? (() => stack.currentImage);
  const stackBinding = options.stackBinding ?? (async (): Promise<StackBindingChoice | null> => (stack.instance === null ? null : { binding: stack.instance, candidate: false }));
  /** S51/S53: the image boots get now, or null when it is not one of the relay's (the operator's to fix). */
  const issuableImage = (): string | null => {
    const image = currentImage();
    return stack.relayImages.includes(image) ? image : null;
  };
  const maxNonces = options.maxNonces ?? DEFAULT_MAX_PULL_TOKEN_NONCES;
  const maxVerifications = options.maxVerifications ?? 1;
  const nonces = new Map<string, NonceEntry>();
  let verifying = 0;

  const sweep = (nowMs: number): void => {
    for (const [nonce, entry] of nonces) if (entry.expiresAtMs <= nowMs) nonces.delete(nonce);
  };

  let latest: PullTokenBoot | null = null;
  /** S58: the same code again counts on; another code starts a new record (and tells the agent). */
  const recordRefusal = (code: PullTokenRefusal, composeHash: string | undefined): void => {
    const nowMs = options.now();
    const hash = RELEASE_REFUSALS.has(code) ? (composeHash ?? null) : null;
    if (latest !== null && latest.code === code) {
      latest = { ...latest, lastMs: Math.max(latest.lastMs, nowMs), count: Math.min(latest.count + 1, MAX_BOOT_COUNT), composeHash: hash ?? latest.composeHash };
      return;
    }
    latest = { code, held: pullTokenRefusalHolds(code), firstMs: nowMs, lastMs: nowMs, count: 1, composeHash: hash };
    options.onRefusal?.(latest);
  };

  const refuse = (code: PullTokenRefusal, detail: { composeHash?: string; quoteSha256?: string; problems?: string } = {}, record = true): SchedulerHttpResponse => {
    options.log({
      level: "warn",
      event: "pull_token_refused",
      code,
      compose_hash: detail.composeHash,
      quote_sha256: detail.quoteSha256,
      problems: detail.problems,
    });
    if (record) recordRefusal(code, detail.composeHash);
    return answer(PULL_TOKEN_REFUSALS[code], { error: code });
  };

  const challenge = (body: Uint8Array): SchedulerHttpResponse => {
    const value = readJson(body);
    if (!isObject(value) || Object.keys(value).length !== 0) return refuse("request_invalid");
    const nowMs = options.now();
    if (stack.registry.expiresAtMs !== null && nowMs >= stack.registry.expiresAtMs) return refuse("registry_credential_expired");
    if (issuableImage() === null) return refuse("relay_image_unlisted");
    sweep(nowMs);
    if (nonces.size >= maxNonces) return refuse("challenge_capacity");
    const nonce = bytesToHex(random(32));
    const expiresAtMs = nowMs + PULL_TOKEN_NONCE_TTL_MS;
    nonces.set(nonce, { expiresAtMs, used: false });
    return answer(200, { nonce, expires_at: utcSeconds(expiresAtMs) });
  };

  /** S11, after the nonce: the quote, the event log, the release, the instance and the compose. */
  const checkBoot = async (request: TokenRequest): Promise<Verdict> => {
    const reportData = pullTokenReportData(request.nonce, request.spkiDer);
    let appraisal: QuoteAppraisal;
    try {
      appraisal = await options.quoteVerifier({ quote: request.quote, reportData, teeType: "tdx", evidence: {} });
    } catch {
      return { ok: false, code: "quote_invalid" };
    }
    if (appraisal.ok !== true) return { ok: false, code: "quote_invalid" };
    if (appraisal.teeType !== "tdx") return { ok: false, code: "tee_not_tdx" };
    if (appraisal.tcbStatus === undefined || !ACCEPTED_TCB_STATUSES.includes(appraisal.tcbStatus)) return { ok: false, code: "tcb_not_up_to_date" };

    const parsed = parseEventLogText(request.eventLog);
    if (!parsed.ok) return { ok: false, code: "event_log_invalid" };
    const replay = replayEventLog(parsed.events);
    if (!replay.ok) return { ok: false, code: "event_log_invalid" };
    if (appraisal.rtmr3 === undefined || !sameBytes(appraisal.rtmr3, replay.rtmr3)) return { ok: false, code: "rtmr3_mismatch" };
    // S11/S54: the boot stands at pre-launch's quote: after system-ready exactly its own identity event (the
    // seal and the image event of S52 make every later quote fail here), and the identity names this relay.
    const facts = stackBootFacts(parsed.events);
    if (!facts.ok) return { ok: false, code: facts.code === "stack_identity_invalid" ? "stack_identity_invalid" : "event_log_after_system_ready" };
    if (facts.facts === null) return { ok: false, code: "stack_identity_missing" };
    if (facts.facts.phase !== "pre_launch") return { ok: false, code: "event_log_after_system_ready" };
    if (!namesThisRelay(facts.facts.identity)) return { ok: false, code: "stack_identity_mismatch" };
    if (appraisal.reportData === undefined || !sameBytes(appraisal.reportData, reportData)) return { ok: false, code: "report_data_mismatch" };

    const measured = extractMeasurements(parsed.events);
    if (!measured.ok) return { ok: false, code: "event_log_invalid" };
    const boot = measured.measurements;
    const composeHash = boot.composeHash;
    if (bytesToHex(sha256(utf8Bytes(request.appCompose))) !== composeHash) return { ok: false, code: "compose_hash_mismatch", composeHash };

    const release = options.releaseForBoot(composeHash, boot.osImageHash);
    if (!release.ok) return { ok: false, code: release.code, composeHash };
    // D20: the list's MRTD/RTMR0-2 for that image are the quote's own (credential intake's rule).
    if (release.osImage.measurements === null || appraisal.measurements === undefined || !sameMeasurements(release.osImage.measurements, appraisal.measurements)) {
      return { ok: false, code: "os_image_measurements", composeHash };
    }

    // P12: the held instance, or Gray's candidate, which this quote proves only by passing every check here and below.
    const held = await stackBinding(boot.appId, boot.keyProvider?.id ?? null);
    if (held === null) return { ok: false, code: "app_id_mismatch", composeHash };
    for (const check of laneBindingChecks(boot, held.binding)) {
      if (check.status === "fail") return { ok: false, code: check.id === "app_id" ? "app_id_mismatch" : "key_provider_mismatch", composeHash };
    }

    // S11a/S55: the release is a stack release and names the public parts of its compose, which every relay's
    // boots share; whom this boot serves is the identity's (above).
    const entry: ReleaseStack | null = release.entry.stack;
    if (entry === null) return { ok: false, code: "release_not_stack", composeHash };
    if (stack.preLaunchSha256 !== null && entry.pre_launch_sha256 !== stack.preLaunchSha256) return { ok: false, code: "pre_launch_not_pinned", composeHash };
    const expectation: SupplyExpectation = { grayImages: [entry.gray_image], preLaunchSha256: entry.pre_launch_sha256 };
    const problems = checkSupplyAppCompose(request.appCompose, expectation);
    if (problems.length > 0) {
      // Codes and member paths only: the policy never puts a value from the input in a problem.
      return { ok: false, code: "app_compose_refused", composeHash, problems: problems.map((problem) => `${problem.code}@${problem.path}`).join(",") };
    }
    return { ok: true, composeHash, candidate: held.candidate ? held.binding : null };
  };

  /** S54: the identity a boot measured names this relay's id, its token service and its key. */
  const namesThisRelay = (identity: StackIdentity): boolean =>
    identity.relayId === options.relayId && identity.tokenUrl === stack.tokenUrl && identity.publicKey === options.relayPublicKey;

  const token = async (body: Uint8Array): Promise<SchedulerHttpResponse> => {
    const request = readTokenRequest(body);
    if (request === null) return refuse("request_invalid");
    const key = await importPullTokenKey(request.spkiDer);
    if (key === null) return refuse("spki_invalid");
    const nowMs = options.now();
    if (stack.registry.expiresAtMs !== null && nowMs >= stack.registry.expiresAtMs) return refuse("registry_credential_expired");
    // S53: the image this boot gets, read once after control.json was read again: a rollout landing during the check
    // names it to the next boot.
    await options.refreshImages?.().catch(() => undefined);
    const image = issuableImage();
    if (image === null) return refuse("relay_image_unlisted");
    // A full verifier refuses before the nonce is looked at, so the boot can retry with the same one.
    if (verifying >= maxVerifications) return refuse("verifier_busy");
    // Single use: the nonce is spent before the first await on the quote, whatever the outcome.
    const entry = nonces.get(request.nonce);
    if (entry === undefined) return refuse("nonce_unknown");
    if (entry.used) return refuse("nonce_used");
    if (nowMs >= entry.expiresAtMs) return refuse("nonce_expired");
    entry.used = true;

    const quoteSha256 = bytesToHex(sha256(request.quote));
    verifying += 1;
    let verdict: Verdict;
    try {
      verdict = await checkBoot(request);
    } finally {
      verifying -= 1;
    }
    if (!verdict.ok) {
      return refuse(verdict.code, {
        quoteSha256,
        ...(verdict.composeHash === undefined ? {} : { composeHash: verdict.composeHash }),
        ...(verdict.problems === undefined ? {} : { problems: verdict.problems }),
      });
    }
    // P12 rule 3: the boot is the VM Gray named for this relay; intake seals to it after its own attestation at the origin.
    if (verdict.candidate !== null) await options.adoptCandidate?.(verdict.candidate).catch(() => undefined);
    const ciphertext = await sealPullTokenEnvelope(key, envelopeText);
    // S51: the relay vouches for the image it names, bound to this boot's nonce.
    const imageSig = bytesToHex(await options.signImage(relayImageMessage(request.nonce, image)));
    const issue: PullTokenIssue = {
      issueId: `i${bytesToHex(random(16))}`,
      atMs: options.now(),
      composeHash: verdict.composeHash,
      quoteSha256,
      nonce: request.nonce,
      relayImage: image,
      expiresAt: stack.registry.expiresAt,
      expiresAtMs: stack.registry.expiresAtMs,
    };
    try {
      await options.record(issue);
    } catch {
      return refuse("issue_record_failed", { composeHash: verdict.composeHash, quoteSha256 });
    }
    latest = null;
    options.log({
      level: "info",
      event: "pull_token_issued",
      compose_hash: issue.composeHash,
      quote_sha256: issue.quoteSha256,
      relay_image: issue.relayImage,
      expires_at: issue.expiresAt,
    });
    return answer(200, { ciphertext_b64: encodeBase64(ciphertext), image, image_sig: imageSig });
  };

  return {
    async handle(request: SchedulerHttpRequest): Promise<SchedulerHttpResponse | null> {
      if (request.path === RELEASE_STATUS_PATH && options.releaseStatus !== undefined) {
        // Gray's release tooling, not a booting VM: not the boot's refusal.
        if (request.method !== "GET") return refuse("method_not_allowed", {}, false);
        return { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" }, body: utf8Bytes(toJsonString(await options.releaseStatus())) };
      }
      if (request.path !== PULL_TOKEN_CHALLENGE_PATH && request.path !== PULL_TOKEN_PATH) return null;
      if (request.method !== "POST") return refuse("method_not_allowed");
      if (request.body.length > MAX_PULL_TOKEN_REQUEST_BYTES) return refuse("request_too_large");
      return request.path === PULL_TOKEN_CHALLENGE_PATH ? challenge(request.body) : token(request.body);
    },
    outstanding(): number {
      return nonces.size;
    },
    boot(): PullTokenBoot | null {
      return latest;
    },
  };
}

/** The token request in its one shape: exactly the five string members, each in its own form. */
function readTokenRequest(body: Uint8Array): TokenRequest | null {
  const value = readJson(body);
  if (!isObject(value)) return null;
  const members = Object.keys(value).sort();
  if (members.length !== REQUEST_MEMBERS.length || members.some((member, index) => member !== REQUEST_MEMBERS[index])) return null;
  const { nonce, spki_der_b64: spkiText, quote: quoteText, event_log: eventLog, app_compose: appCompose } = value as Record<string, Json>;
  if (typeof nonce !== "string" || !/^[0-9a-f]{64}$/.test(nonce)) return null;
  if (typeof spkiText !== "string" || typeof quoteText !== "string" || typeof eventLog !== "string" || typeof appCompose !== "string") return null;
  const spkiDer = decodeBase64(spkiText);
  if (spkiDer === null || spkiDer.length === 0) return null;
  if (quoteText.length === 0 || quoteText.length > MAX_QUOTE_BYTES * 2) return null;
  const quote = hexBytes(quoteText);
  if (quote === null) return null;
  if (eventLog.length === 0 || appCompose.length === 0) return null;
  return { nonce, spkiDer, quote, eventLog, appCompose };
}

/** A strict JSON value from strict UTF-8, or undefined. */
function readJson(body: Uint8Array): Json | undefined {
  try {
    return parseStrict(utf8Text(body));
  } catch {
    return undefined;
  }
}

function answer(status: number, value: Record<string, string>): SchedulerHttpResponse {
  return {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: utf8Bytes(JSON.stringify(value)),
  };
}

/** `YYYY-MM-DDTHH:MM:SSZ`, rounded down to the second. */
function utcSeconds(ms: number): string {
  return `${new Date(Math.floor(ms / 1000) * 1000).toISOString().slice(0, 19)}Z`;
}

function sameMeasurements(expected: QuoteMeasurements, actual: QuoteMeasurements): boolean {
  return (["mrtd", "rtmr0", "rtmr1", "rtmr2"] as const).every((member) => {
    const want = expected[member].toLowerCase();
    return /^[0-9a-f]{96}$/.test(want) && want === actual[member].toLowerCase();
  });
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= (left[index] as number) ^ (right[index] as number);
  return difference === 0;
}
