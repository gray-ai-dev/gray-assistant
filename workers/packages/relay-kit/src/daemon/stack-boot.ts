/**
 * What the daemon holds a verified attestation to before it talks to the replica, shared with the CLI commands that
 * talk to the relay's stack VM themselves (`gray-assistant debug get`), so the two cannot disagree on which boot is the
 * relay's. Verification itself (the quote, the replay, the release pinning, the instance) is `DaemonAttest`'s; these
 * are the comparisons after it.
 */
import type { StackBootFacts } from "@gray/lane-verify";
import { tunnelOriginOf } from "../lane-origin.ts";
import type { StackConfig } from "./config.ts";
import type { DaemonAttestation, StackIssueRecord } from "./types.ts";

/** Why a verified attestation is not this origin's boot, as the replica's `attest_*` error; null when it is. */
export type AttestationMismatch = "attest_origin_mismatch" | "attest_relay_mismatch" | "attest_keyset_mismatch" | "attest_spki_mismatch";

/**
 * The report is the origin's, its keyset and TLS key are the ones it signed, and through Gray's entry
 * (docs/design/relay-outbound-only.md §5), where the origin names the entry and not the VM, the tunnel's relay and the
 * boot's identity are both this relay.
 */
export function attestationMismatch(result: DaemonAttestation, origin: string, relayId: string): AttestationMismatch | null {
  if (result.checked.file.origin !== origin) return "attest_origin_mismatch";
  const tunnel = tunnelOriginOf(origin);
  if (tunnel !== null && (tunnel.relayId !== relayId || result.stackBoot?.identity.relayId !== relayId)) return "attest_relay_mismatch";
  if (result.keysetDigest !== result.checked.file.verification.keysetDigest) return "attest_keyset_mismatch";
  if (result.tlsSpkiSha256 !== result.checked.file.verification.tlsSpkiSha256) return "attest_spki_mismatch";
  return null;
}

/**
 * S54: a relay-stack boot is the relay's when pre-launch sealed it, its identity names this relay, its token service
 * and its key, its image is one of `stack.relay_images`, and this relay's own pull-token record issued that image to
 * that boot (its nonce) for the same compose. The code is the replica's error without its `attest_` prefix.
 */
export async function stackBootDecision(input: {
  readonly facts: StackBootFacts | null;
  readonly composeHash: string | null;
  readonly relayId: string;
  /** The relay's Ed25519 public key, 64 lower hex; null before the daemon derived it. */
  readonly relayPublicKeyHex: string | null;
  readonly stack: StackConfig | null;
  readonly stackIssue: ((nonce: string) => Promise<StackIssueRecord | null>) | undefined;
}): Promise<{ readonly ok: true; readonly image: string } | { readonly ok: false; readonly code: string }> {
  const { facts, stack } = input;
  if (stack === null) return { ok: false, code: "stack_not_configured" };
  if (facts === null) return { ok: false, code: "stack_boot_missing" };
  if (facts.phase !== "sealed") return { ok: false, code: "stack_boot_not_sealed" };
  const identity = facts.identity;
  if (identity.relayId !== input.relayId || identity.tokenUrl !== stack.tokenUrl || identity.publicKey !== input.relayPublicKeyHex) {
    return { ok: false, code: "stack_identity_mismatch" };
  }
  const image = facts.image.image;
  if (!stack.relayImages.includes(image)) return { ok: false, code: "relay_image_unlisted" };
  let issued: StackIssueRecord | null;
  try {
    issued = input.stackIssue === undefined ? null : await input.stackIssue(facts.image.nonce);
  } catch {
    return { ok: false, code: "relay_image_issue_log_unreadable" };
  }
  if (issued === null || issued.relayImage !== image || issued.composeHash !== input.composeHash) return { ok: false, code: "relay_image_not_issued" };
  return { ok: true, image };
}
