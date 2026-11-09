/**
 * The reference scheduler's HTTP surface, as a pure function of one request: the same code runs
 * behind Node's `https` in production and behind an in-memory fetch in the tests (Node and workerd).
 *
 * Authentication is `@gray/relay-connector`'s signed-call scheme, unchanged: the TEE signs the
 * method, path, relay id, key id, millisecond timestamp, a single-use nonce and SHA-256(body) with a
 * per-boot Ed25519 key; the relay verifies it against the keys of **every currently verified
 * replica** and answers signed under **key id = the configured relay id** (whatever id the relay's
 * key file carries). Nothing the request carries is trusted before that check, and the relay's
 * answer is signed over the status, the request's nonce, its own timestamp and SHA-256(body).
 *
 * The route set is the scheduler protocol (`/v1/pick`, `/v1/report`, `/v1/lease`) plus one operator
 * route (`/v1/admin/reset`) that is not part of the TEE protocol and is served only when the
 * configuration names an admin token.
 *
 * State shared by every route and every replica:
 * - one nonce window per handler (the `replay_cap` configuration bounds it), so a nonce cannot be
 *   replayed through another verified replica;
 * - one key resolver, replaced atomically by `setKeyFor` after an attestation. A request that is
 *   already verifying keeps the resolver it started with; the next request sees the new one.
 */
import { sha256BareHex, type WorkloadKeyset } from "@gray/attest";
import { asU64, get, isObject, parseStrict, toJsonString, type Json, type JsonObject } from "@gray/json";
import {
  HEADER,
  MAX_REPORTS_PER_BATCH,
  REPORT_BATCH_ID,
  SCHEDULER_MAX_SKEW_MS,
  leaseTableValue,
  parseOutcomeReport,
  parsePickRequest,
  signSchedulerResponse,
  hexBytes,
  utf8Bytes,
  utf8Text,
  verifySchedulerRequest,
  type Ed25519KeyMaterial,
  type HeaderReader,
  type PickDecision,
  type PickRequest,
  type SchedulerRequestProblem,
} from "@gray/relay-connector";
import { SCHEDULER_ENDPOINTS } from "../endpoints.ts";
import { MAX_RETRY_AFTER_MS, type SchedulerOutcomeReport, type SchedulerPool } from "./policy.ts";
import { DEFAULT_REPLAY_CAP, SchedulerNonceWindow } from "./replay.ts";

/** The part of an HTTP request the handler reads. */
export interface SchedulerHttpRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: HeaderReader;
  readonly body: Uint8Array;
}

/** The answer the Node adapter writes; headers are already the signed ones. */
export interface SchedulerHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}

/**
 * One verified replica's candidate signing key. Several replicas (different boots) can publish the
 * same key id; verification tries each key and the one that verifies identifies the replica.
 */
export interface SchedulerCandidateKey {
  readonly replicaId: string;
  readonly publicKey: Uint8Array;
  /** The replica's keyset `not_after` (Unix seconds); at or after it the key is not trusted. */
  readonly notAfter?: bigint;
}

/**
 * Every candidate key for a key id, across the replicas the daemon has verified. Returning an empty
 * array is an unknown key: the request is refused and `onUnknownKey` fires so the daemon re-attests.
 */
export type SchedulerKeyResolver = (keyId: string) => readonly SchedulerCandidateKey[];

/** Why no candidate key verified a request; the daemon maps this to re-attestation. */
export type SchedulerUnknownKeyReason = "no_candidate" | "expired_keyset" | SchedulerRequestProblem;

/** What `onVerifiedRequest` receives: no body, no header value beyond the signed timestamp. */
export interface SchedulerVerifiedRequestEvent {
  readonly replicaId: string;
  readonly path: string;
  readonly method: string;
  /** The TEE's signed `x-gray-timestamp`, Unix milliseconds. */
  readonly timestampMs: number;
  /** The relay's wall clock when the signature verified. */
  readonly nowMs: number;
  /**
   * The scheduler API version the call carried (`x-gray-api-version`, one of `SCHEDULER_API_VERSIONS`),
   * which `gray-assistant status` shows as the version that replica's TEE uses (D116(b)). The header is not
   * signed: the bridge forwards it, so this is what arrived, not an authenticated claim.
   */
  readonly apiVersion: number;
}

/** One pick's structured log line (D111(c)): scheduling metadata only, never a body or a model. */
export interface SchedulerPickEvent {
  readonly replicaId: string;
  readonly decision: "account" | "retry_after" | "unavailable";
  readonly accountId?: string;
  readonly durationMs: number;
  /** A short SHA-256 digest of the pick's request_ref, never the ref itself. */
  readonly requestRefDigest: string;
}

/**
 * One refused report batch from a verified TEE (D116(b)): the status the relay answered and the kind
 * of batch it was, read from the body as far as it parses. Never a report, an account id or a body.
 */
export interface SchedulerReportRefusedEvent {
  readonly replicaId: string;
  readonly status: number;
  /** `release` or `account` for a batch of one kind; `mixed` (a TEE from before D116); `unknown`. */
  readonly kind: "release" | "account" | "mixed" | "unknown";
  /** The refusal's fixed code, as the answer carries it. */
  readonly code: string;
}

/** One report batch's structured log line (D111(c)): a count and outcome counts, no account ids. */
export interface SchedulerReportEvent {
  readonly replicaId: string;
  readonly count: number;
  /** Sorted `outcome:count` pairs, e.g. `ok:2,upstream_error:1`; no account id, usage or content. */
  readonly outcomes: string;
}

/** What `onUnknownKey` receives. It never contains a request body or a credential. */
export interface SchedulerUnknownKeyEvent {
  readonly keyId: string;
  readonly path: string;
  readonly method: string;
  readonly reason: SchedulerUnknownKeyReason;
}

export interface SchedulerHandlerOptions {
  /** The relay id the TEE signs the canonical request with, and the key id every answer uses. */
  readonly relayId: string;
  /** The candidate keys of every currently verified replica. Replaced by `setKeyFor`. */
  readonly keyFor: SchedulerKeyResolver;
  /** The relay's own seed (or signer), used to sign every answer. */
  readonly signingKey: Ed25519KeyMaterial;
  /** The pool (pick, report, release, lease table). */
  readonly pool: SchedulerPool;
  readonly now: () => number;
  readonly maxSkewMs?: number;
  /** The handler's one shared nonce window cap; `replay_cap` in the config. */
  readonly replayCap?: number;
  /** A pre-built window (tests); when given, `replayCap` is not used. */
  readonly replayWindow?: SchedulerNonceWindow;
  /** When true, every pick answers `unavailable`; reports and lease pulls still work. */
  readonly paused?: () => boolean;
  /** Called when a request verifies under no candidate key (the daemon re-attests). */
  readonly onUnknownKey?: (event: SchedulerUnknownKeyEvent) => void;
  /**
   * Called after a signed request verifies. The TEE's timestamp and the relay's own clock at that
   * moment give a free, signed wall-clock-skew sample (K4-7); the daemon exports the last one.
   */
  readonly onVerifiedRequest?: (event: SchedulerVerifiedRequestEvent) => void;
  /** One line per pick (D111(c)); the daemon maps it to its logger. */
  readonly onPick?: (event: SchedulerPickEvent) => void;
  /** One line per applied report batch (D111(c)); the daemon maps it to its logger. */
  readonly onReport?: (event: SchedulerReportEvent) => void;
  /** One line per report batch a verified TEE sent and the relay refused (D116(b)). */
  readonly onReportRefused?: (event: SchedulerReportRefusedEvent) => void;
  readonly adminToken?: string | null;
  readonly maxPickBytes?: number;
  readonly maxReportBytes?: number;
  /** How many accepted batch ids are remembered for deduplication. Default 4096. */
  readonly maxDedupedBatches?: number;
}

/** The handler plus the one mutable piece: the key resolver, swapped after an attestation. */
export interface SchedulerHandler {
  (request: SchedulerHttpRequest): Promise<SchedulerHttpResponse>;
  /** Replace the resolver atomically. In-flight requests keep the resolver they started with. */
  setKeyFor(keyFor: SchedulerKeyResolver): void;
}

/** The default body caps: a pick is one small object, a report batch is metadata for a second. */
export const DEFAULT_MAX_PICK_BYTES = 64 * 1024;
export const DEFAULT_MAX_REPORT_BYTES = 4 * 1024 * 1024;

/** The resolver over one verified keyset, as the standalone scheduler server builds it. */
export function keysetKeyResolver(keyset: WorkloadKeyset, replicaId: string): SchedulerKeyResolver {
  const keys = new Map<string, SchedulerCandidateKey[]>();
  for (const key of keyset.receipt_signing_keys) {
    if (key.algo !== "ed25519") continue;
    const bytes = hexBytes(key.public_key, 32);
    if (bytes === null) continue;
    const candidates = keys.get(key.key_id) ?? [];
    candidates.push({ replicaId, publicKey: bytes, notAfter: keyset.not_after });
    keys.set(key.key_id, candidates);
  }
  return (keyId) => keys.get(keyId) ?? [];
}

/** Build the handler for one configured relay and its verified replicas. */
export function createSchedulerHandler(options: SchedulerHandlerOptions): SchedulerHandler {
  let keyFor = options.keyFor;
  const maxSkewMs = options.maxSkewMs ?? SCHEDULER_MAX_SKEW_MS;
  // The nonce memory must outlive the whole window a signed timestamp is accepted in: a captured
  // request replayed after the nonce TTL but inside ±maxSkewMs would otherwise verify again. The
  // extra millisecond covers the exact late edge: a request first accepted at `timestamp − skew`
  // would otherwise have its nonce expire at `timestamp + skew`, where the signature still verifies
  // (R25).
  const replayWindow = options.replayWindow ?? new SchedulerNonceWindow({ windowMs: 2 * maxSkewMs + 1, maxEntries: options.replayCap ?? DEFAULT_REPLAY_CAP });
  const maxPickBytes = options.maxPickBytes ?? DEFAULT_MAX_PICK_BYTES;
  const maxReportBytes = options.maxReportBytes ?? DEFAULT_MAX_REPORT_BYTES;
  const adminToken = options.adminToken ?? null;
  // A report batch is delivered at least once: a resend after a timed-out acknowledgement must not
  // apply the same outcomes twice. The id is the TEE's, and the answer repeats the original count so
  // the client can clear the batch it already sent. Bounded: the oldest ids are forgotten first.
  // Dedupe is on (batch_id, body hash), not the id alone: the same id with a different body is a
  // new batch that was never applied, so it is refused with 409 rather than acknowledged with the
  // old count. Only a byte-identical resend replays the original answer.
  const acceptedByBatch = new Map<string, { readonly bodySha256: string; readonly accepted: bigint }>();
  const maxDedupedBatches = options.maxDedupedBatches ?? 4096;

  function rememberBatch(batchId: string, bodySha256: string, accepted: bigint): void {
    acceptedByBatch.set(batchId, { bodySha256, accepted });
    while (acceptedByBatch.size > maxDedupedBatches) {
      const oldest = acceptedByBatch.keys().next().value;
      if (oldest === undefined) break;
      acceptedByBatch.delete(oldest);
    }
  }

  /**
   * The answer to a report batch a verified TEE sent and the relay cannot apply, with its log line
   * (D116(b)); the TEE logs the same refusal on its side.
   */
  function reportRefused(replicaId: string, status: number, code: string, kind: SchedulerReportRefusedEvent["kind"]): SchedulerHttpResponse {
    try {
      options.onReportRefused?.({ replicaId, status, kind, code });
    } catch {
      // A log line is a diagnostic, not part of the protocol: its failure never changes the answer.
    }
    return error(status, code);
  }

  function unknownKey(event: SchedulerUnknownKeyEvent): void {
    try {
      options.onUnknownKey?.(event);
    } catch {
      // The hook is a daemon signal, not part of the protocol: its failure must not change the
      // refusal the caller already earned.
    }
  }

  async function signed(requestNonce: string, value: JsonObject): Promise<SchedulerHttpResponse> {
    const body = utf8Bytes(toJsonString(value));
    const headers = await signSchedulerResponse({
      status: 200,
      requestNonce,
      // The TEE pins `schedulerKeyId = lane.relay_id` (gateway `lane/remote/snapshot.ts:131-133`).
      // The key file's own id is metadata and never reaches the wire.
      relayKeyId: options.relayId,
      timestampMs: options.now(),
      body,
      signingKey: options.signingKey,
    });
    return { status: 200, headers, body };
  }

  /**
   * Verify one signed request against every candidate key. The resolver is read once, so a swap
   * that happens while the Ed25519 checks await does not mix keysets between candidates.
   */
  async function authorized(request: SchedulerHttpRequest, limit: number): Promise<{ readonly ok: true; readonly replicaId: string } | { readonly ok: false; readonly response: SchedulerHttpResponse }> {
    if (request.body.length > limit) return { ok: false, response: error(413, "too_large") };
    const nowMs = options.now();
    const keyId = request.headers.get(HEADER.keyId);
    if (keyId === null || keyId.length === 0) return { ok: false, response: error(401, "unauthorized") };
    const candidates = keyFor(keyId);
    if (candidates.length === 0) {
      unknownKey({ keyId, path: request.path, method: request.method, reason: "no_candidate" });
      return { ok: false, response: error(401, "unauthorized") };
    }
    const nowSecs = BigInt(Math.floor(nowMs / 1000));
    let lastReason: SchedulerUnknownKeyReason = "no_candidate";
    let sawReplica = false;
    for (const candidate of candidates) {
      if (candidate.notAfter !== undefined && nowSecs >= candidate.notAfter) {
        lastReason = "expired_keyset";
        continue;
      }
      sawReplica = true;
      const verified = await verifySchedulerRequest({
        method: request.method,
        path: request.path,
        relayId: options.relayId,
        headers: request.headers,
        body: request.body,
        nowMs,
        keyFor: () => candidate.publicKey,
        maxSkewMs,
      });
      if (!verified.ok) {
        lastReason = verified.reason;
        // A timestamp or shape problem is not fixed by another key; stop before hashing the body
        // again for every candidate.
        if (verified.reason !== "bad_signature" && verified.reason !== "unknown_key") break;
        continue;
      }
      if (!replayWindow.accept(verified.nonce, nowMs)) return { ok: false, response: error(401, "unauthorized") };
      try {
        // The verifier accepted the header, so it is one of the known versions' digits (unsigned; see
        // `SchedulerVerifiedRequestEvent.apiVersion`).
        const apiVersion = Number(request.headers.get(HEADER.apiVersion));
        options.onVerifiedRequest?.({ replicaId: candidate.replicaId, path: request.path, method: request.method, timestampMs: verified.timestampMs, nowMs, apiVersion });
      } catch {
        // A diagnostic sample is not part of the protocol: its failure never changes the answer.
      }
      return { ok: true, replicaId: candidate.replicaId };
    }
    unknownKey({ keyId, path: request.path, method: request.method, reason: sawReplica ? lastReason : "expired_keyset" });
    return { ok: false, response: error(401, "unauthorized") };
  }

  const handler = async (request: SchedulerHttpRequest): Promise<SchedulerHttpResponse> => {
    if (request.path === SCHEDULER_ENDPOINTS.doctorEcho) {
      if (request.method !== "POST") return error(405, "method_not_allowed");
      if (request.body.length > 64 * 1024) return error(413, "too_large");
      // Echo only the fixed signed header set and a body digest: never the body itself, never an
      // arbitrary header. The doctor verifies the echoed signature with its own key.
      return {
        status: 200,
        headers: { "content-type": "application/json", "cache-control": "no-store" },
        body: utf8Bytes(
          toJsonString({
            echo: {
              method: request.method,
              path: request.path,
              api_version: request.headers.get(HEADER.apiVersion),
              key_id: request.headers.get(HEADER.keyId),
              timestamp: request.headers.get(HEADER.timestamp),
              nonce: request.headers.get(HEADER.nonce),
              signature: request.headers.get(HEADER.signature),
              relay_key_id: request.headers.get(HEADER.relayKeyId),
              body_sha256: sha256BareHex(request.body),
            },
          }),
        ),
      };
    }
    if (request.path === SCHEDULER_ENDPOINTS.adminReset) {
      if (request.method !== "POST" || adminToken === null) return error(404, "not_found");
      return adminReset(request, adminToken, options.pool);
    }
    if (request.path === SCHEDULER_ENDPOINTS.pick) {
      if (request.method !== "POST") return error(405, "method_not_allowed");
      const auth = await authorized(request, maxPickBytes);
      if (!auth.ok) return auth.response;
      let pick: PickRequest;
      const nonce = request.headers.get(HEADER.nonce) as string;
      try {
        pick = parsePickRequest(parseBody(request.body));
      } catch {
        return error(400, "bad_request");
      }
      // Pause is an availability state, not a content decision: the TEE gets the same shape as a
      // pool with nothing eligible, and reports/lease pulls keep working so a resume is seamless.
      // D111(c): one line per pick, including a paused one, with the decision, the account id it chose
      // (if any), the time the decision took on the injected clock, and a digest of the request_ref
      // (never the ref itself).
      const startedAtMs = options.now();
      const paused = options.paused?.() === true;
      const decision: PickDecision = paused ? { kind: "unavailable" } : options.pool.pick(pick, auth.replicaId);
      const durationMs = Math.max(0, options.now() - startedAtMs);
      try {
        options.onPick?.({
          replicaId: auth.replicaId,
          decision: decision.kind,
          ...(decision.kind === "account" ? { accountId: decision.account_id } : {}),
          durationMs,
          requestRefDigest: sha256BareHex(utf8Bytes(pick.request_ref)).slice(0, 12),
        });
      } catch {
        // A log line is a diagnostic, not part of the protocol: its failure never changes the answer.
      }
      if (paused) return signed(nonce, { unavailable: true });
      if (decision.kind === "account") {
        // Belt and braces for non-reference pools: an answer may only name an account the asking
        // replica holds (the TEE refuses anything else with `scheduler_unknown_account`).
        if (!options.pool.accountsFor(auth.replicaId).includes(decision.account_id)) return signed(nonce, { unavailable: true });
        return signed(nonce, { account_id: decision.account_id });
      }
      if (decision.kind === "retry_after") return signed(nonce, { retry_after_ms: decision.retry_after_ms });
      return signed(nonce, { unavailable: true });
    }
    if (request.path === SCHEDULER_ENDPOINTS.report) {
      if (request.method !== "POST") return error(405, "method_not_allowed");
      const auth = await authorized(request, maxReportBytes);
      if (!auth.ok) return auth.response;
      const nonce = request.headers.get(HEADER.nonce) as string;
      let batch: { readonly batchId: string | null; readonly reports: readonly SchedulerOutcomeReport[] };
      try {
        batch = parseReportBatch(parseBody(request.body));
      } catch {
        return reportRefused(auth.replicaId, 400, "bad_request", batchKindOf(request.body));
      }
      if (batch.batchId !== null) {
        const previous = acceptedByBatch.get(batch.batchId);
        if (previous !== undefined) {
          if (previous.bodySha256 !== sha256BareHex(request.body)) return reportRefused(auth.replicaId, 409, "batch_id_conflict", kindOfOutcomes(batch.reports.map((report) => report.outcome)));
          return signed(nonce, { accepted: previous.accepted });
        }
      }
      // D50: the pool receives the asking replica and applies only that replica's installed
      // accounts. Its answer may also carry `rejected`/`reason` for a foreign entry, but the signed
      // wire answer is `{accepted}` only: `@gray/relay-connector`'s reportAccepted schema is strict,
      // and an extra member would make the TEE treat a healthy answer as bad and retry.
      const { accepted } = options.pool.report(batch.reports, auth.replicaId);
      if (batch.batchId !== null) rememberBatch(batch.batchId, sha256BareHex(request.body), accepted);
      try {
        const counts = new Map<string, number>();
        for (const report of batch.reports) counts.set(report.outcome, (counts.get(report.outcome) ?? 0) + 1);
        const outcomes = [...counts.entries()]
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([outcome, count]) => `${outcome}:${count}`)
          .join(",");
        options.onReport?.({ replicaId: auth.replicaId, count: batch.reports.length, outcomes });
      } catch {
        // Same rule as a pick's line: logging never changes the signed answer.
      }
      return signed(nonce, { accepted });
    }
    if (request.path === SCHEDULER_ENDPOINTS.lease) {
      if (request.method !== "GET") return error(405, "method_not_allowed");
      const auth = await authorized(request, 0);
      if (!auth.ok) return auth.response;
      const nonce = request.headers.get(HEADER.nonce) as string;
      return signed(nonce, leaseTableValue(options.pool.leaseTable(auth.replicaId)));
    }
    return error(404, "not_found");
  };
  handler.setKeyFor = (next: SchedulerKeyResolver): void => {
    keyFor = next;
  };
  return handler as SchedulerHandler;
}

function parseBody(body: Uint8Array): Json {
  return parseStrict(utf8Text(body));
}

/** The kind of a batch whose outcomes these are (D116(b)): only the release is `not_sent`. */
function kindOfOutcomes(outcomes: readonly unknown[]): SchedulerReportRefusedEvent["kind"] {
  const releases = outcomes.filter((outcome) => outcome === "not_sent").length;
  if (outcomes.length === 0) return "unknown";
  if (releases === outcomes.length) return "release";
  return releases === 0 ? "account" : "mixed";
}

/** The kind of a refused body, as far as it parses: the entries' `outcome` members, nothing else. */
function batchKindOf(body: Uint8Array): SchedulerReportRefusedEvent["kind"] {
  try {
    const value = parseBody(body);
    const reports = isObject(value) ? get(value, "reports") : undefined;
    if (!Array.isArray(reports)) return "unknown";
    return kindOfOutcomes(reports.map((entry) => (isObject(entry) ? get(entry, "outcome") : undefined)));
  } catch {
    return "unknown";
  }
}

/**
 * The report batch, with this package's forward-compatible `retry_after_ms` extension: the TEE's
 * strict schema does not carry one today, so the field is validated here and removed before the
 * shared strict report parser sees the object. When `@gray/relay-connector` adds the member, this
 * stops being an extension and the reference scheduler already honours it.
 */
function parseReportBatch(value: Json): { readonly batchId: string | null; readonly reports: readonly SchedulerOutcomeReport[] } {
  if (!isObject(value)) throw new Error("report batch is not an object");
  if (!Object.keys(value).every((key) => key === "batch_id" || key === "reports")) throw new Error("report batch members");
  const batchIdValue = get(value, "batch_id");
  let batchId: string | null = null;
  if (batchIdValue !== undefined) {
    if (typeof batchIdValue !== "string" || !REPORT_BATCH_ID.test(batchIdValue)) throw new Error("batch_id");
    batchId = batchIdValue;
  }
  const reports = get(value, "reports");
  if (!Array.isArray(reports) || reports.length > MAX_REPORTS_PER_BATCH) throw new Error("reports");
  const out: SchedulerOutcomeReport[] = [];
  for (const entry of reports) {
    if (!isObject(entry)) throw new Error("report");
    const retry = get(entry, "retry_after_ms");
    let retryAfter: bigint | undefined;
    if (retry !== undefined) {
      const parsed = asU64(retry);
      if (parsed === undefined || parsed < 1n || parsed > MAX_RETRY_AFTER_MS) throw new Error("retry_after_ms");
      retryAfter = parsed;
    }
    const base: JsonObject = {};
    for (const key of Object.keys(entry)) {
      if (key === "retry_after_ms") continue;
      base[key] = (entry as JsonObject)[key] as Json;
    }
    const report = parseOutcomeReport(base as Json);
    out.push({
      ...(report.account_id === undefined ? {} : { account_id: report.account_id }),
      ...(report.request_ref === undefined ? {} : { request_ref: report.request_ref }),
      outcome: report.outcome,
      ...(retryAfter === undefined ? {} : { retry_after_ms: retryAfter }),
    });
  }
  return { batchId, reports: out };
}

async function adminReset(request: SchedulerHttpRequest, token: string, pool: SchedulerPool): Promise<SchedulerHttpResponse> {
  const authorization = request.headers.get("authorization");
  if (authorization === null || !authorization.toLowerCase().startsWith("bearer ")) return error(401, "unauthorized");
  if (!constantTimeEqual(authorization.slice(7), token)) return error(401, "unauthorized");
  if (request.body.length > 4096) return error(413, "too_large");
  let accountId: string;
  try {
    const value = parseBody(request.body);
    if (!isObject(value) || Object.keys(value).length !== 1) throw new Error("body");
    const id = get(value, "account_id");
    if (typeof id !== "string" || id.length === 0) throw new Error("account_id");
    accountId = id;
  } catch {
    return error(400, "bad_request");
  }
  const changed = pool.reset(accountId);
  return { status: 200, headers: { "content-type": "application/json" }, body: utf8Bytes(toJsonString({ reset: changed > 0 })) };
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function error(status: number, code: string): SchedulerHttpResponse {
  return { status, headers: { "content-type": "application/json" }, body: utf8Bytes(toJsonString({ error: code })) };
}