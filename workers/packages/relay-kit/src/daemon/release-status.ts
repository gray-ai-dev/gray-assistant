/**
 * The relay's public, signed acceptance status (`GET <token_url>/v1/releases/status`): which compose
 * releases and OS images of Gray's signed list this relay has seen and accepts, and whether its agent is
 * ready. Gray's release tooling (deploy/tee/release/release.mjs `accept`) polls it for a third-party
 * relay's stack app instead of logging in to the relay's machine.
 *
 *     {"status": {"relay_id", "issued_ms", "ready",
 *                 "replicas": [{"origin", "phase", "keyset_digest"}],
 *                 "releases": [{"compose_hash", "git_commit", "first_seen_ms", "acceptable_at_ms",
 *                               "acceptable", "accepted_at_ms", "rejected"}],
 *                 "os_images": [{"os_image_hash", "first_seen_ms", "acceptable_at_ms", "acceptable",
 *                                "refusal", "accepted_at_ms", "rejected", "provenance"}]},
 *      "signature": "<128 hex>"}
 *
 * The signature is the relay's own Ed25519 key, the one its lane record publishes as
 * `signing_public_key` (`gray-assistant init` registers the relay key as both lane keys), over
 * `"gray-relay-release-status/v1\n" || JCS(status)`. Integers are JSON integers (JCS refuses floats).
 * Everything here is public already (hashes from Gray's list, times, a readiness flag, and each replica's attested
 * keyset digest, which the lane's own attestation report names to anyone); no secret. `replicas` is what lets Gray
 * tell "ready on this boot" from "ready": across a CVM restart `ready` still describes the previous boot until the
 * agent re-attests, and only the keyset digest (a new receipt key and, since D133, a new TLS key each boot) changes
 * with the boot. Readers that predate it ignore the member (verifyReleaseStatusText checks only the envelope).
 */
import { bytesToLowerHex, ed25519Sign, ed25519Verify, jcsBytes, lowerHexBytes } from "@gray/attest";
import { get, isObject, parseStrict, type Json, type JsonObject } from "@gray/json";
import type { DaemonHealth, DaemonStatus } from "./types.ts";

export const RELEASE_STATUS_PATH = "/v1/releases/status";
export const RELEASE_STATUS_DOMAIN = "gray-relay-release-status/v1";

const ms = (value: number | null): bigint | null => (value === null ? null : BigInt(Math.trunc(value)));

/** The unsigned document from the daemon's own view. */
export function releaseStatusDocument(relayId: string, nowMs: number, status: DaemonStatus, health: DaemonHealth): JsonObject {
  return {
    relay_id: relayId,
    issued_ms: BigInt(Math.trunc(nowMs)),
    ready: health.ready,
    replicas: status.replicas.map((replica) => ({ origin: replica.origin, phase: replica.phase, keyset_digest: replica.keysetDigest })),
    releases: status.releases.map((release) => ({
      compose_hash: release.composeHash,
      git_commit: release.gitCommit,
      first_seen_ms: ms(release.firstSeenMs),
      acceptable_at_ms: ms(release.acceptableAtMs),
      acceptable: release.acceptable,
      accepted_at_ms: ms(release.acceptedAtMs),
      rejected: release.rejected,
    })),
    os_images: status.osImages.map((image) => ({
      os_image_hash: image.osImageHash,
      first_seen_ms: ms(image.firstSeenMs),
      acceptable_at_ms: ms(image.acceptableAtMs),
      acceptable: image.acceptable,
      refusal: image.refusal,
      accepted_at_ms: ms(image.acceptedAtMs),
      rejected: image.rejected,
      provenance: image.provenance,
    })),
  };
}

/** The bytes the relay signs. */
export function releaseStatusMessage(status: Json): Uint8Array {
  const body = jcsBytes(status);
  const prefix = new TextEncoder().encode(`${RELEASE_STATUS_DOMAIN}\n`);
  const message = new Uint8Array(prefix.length + body.length);
  message.set(prefix, 0);
  message.set(body, prefix.length);
  return message;
}

/** The answer body: the document and the relay key's signature over it. */
export async function signReleaseStatus(status: JsonObject, seed: Uint8Array): Promise<JsonObject> {
  return { status, signature: bytesToLowerHex(await ed25519Sign(seed, releaseStatusMessage(status))) };
}

export type ReleaseStatusRefusal = "not_json" | "malformed" | "bad_signature" | "relay_mismatch" | "stale" | "future";

export type VerifiedReleaseStatus = { readonly ok: true; readonly status: JsonObject } | { readonly ok: false; readonly code: ReleaseStatusRefusal };

export interface VerifyReleaseStatusOptions {
  /** The relay's `signing_public_key`, 64 lower-case hex. */
  readonly publicKey: string;
  readonly relayId: string;
  readonly nowMs: number;
  /** How old a document may be; the reader's choice (release.mjs: its own poll window). */
  readonly maxAgeMs: number;
  /** How far in the future `issued_ms` may be (clock skew). */
  readonly maxFutureMs: number;
}

/** Verify an answer's text: the signature over exactly the document, the relay it names, and its age. */
export async function verifyReleaseStatusText(text: string, options: VerifyReleaseStatusOptions): Promise<VerifiedReleaseStatus> {
  let value: Json;
  try {
    value = parseStrict(text);
  } catch {
    return { ok: false, code: "not_json" };
  }
  if (!isObject(value) || Object.keys(value).sort().join(",") !== "signature,status") return { ok: false, code: "malformed" };
  const status = get(value, "status");
  const signature = get(value, "signature");
  const key = lowerHexBytes(options.publicKey);
  const signatureBytes = typeof signature === "string" && /^[0-9a-f]{128}$/.test(signature) ? lowerHexBytes(signature) : null;
  if (!isObject(status) || signatureBytes === null || key === null || key.length !== 32) return { ok: false, code: "malformed" };
  let message: Uint8Array;
  try {
    message = releaseStatusMessage(status);
  } catch {
    return { ok: false, code: "malformed" };
  }
  if (!(await ed25519Verify(key, message, signatureBytes))) return { ok: false, code: "bad_signature" };
  if (get(status, "relay_id") !== options.relayId) return { ok: false, code: "relay_mismatch" };
  const issued = get(status, "issued_ms");
  if (typeof issued !== "bigint") return { ok: false, code: "malformed" };
  const issuedMs = Number(issued);
  if (issuedMs > options.nowMs + options.maxFutureMs) return { ok: false, code: "future" };
  if (options.nowMs - issuedMs > options.maxAgeMs) return { ok: false, code: "stale" };
  return { ok: true, status };
}
