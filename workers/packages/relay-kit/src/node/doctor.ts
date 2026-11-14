/**
 * `gray-assistant doctor`: one plain-language line per check, exit 0 only when every check that must
 * pass does. It is the installer's preflight, not a metrics endpoint.
 *
 * Checks, in order:
 *  1. the config parses and no `init` placeholder is left;
 *  2. every secret file is a regular 0600 file (the key, the accounts file, the source token, the
 *     admin token), and the policy bundle/state directory are usable;
 *  3. the source software is detected, a live credential is read, and every account is classified
 *     (parked accounts are listed with the daemon's own reasons);
 *  4. the signed release list verifies against the pinned key and is fresh;
 *  5. every origin attests and its release is accepted, or is reported pending with the remaining
 *     delay;
 *  6. the TEE's clock (the `/healthz` Date header) is within 10 s;
 *  7. the registered scheduler URL's certificate is valid and not about to expire;
 *  8. a signed echo through the TLS proxy arrives byte for byte (`/v1/doctor/echo`);
 *  9. the scheduler API version each replica's TEE uses, as the running agent recorded it (D116(b)); not applicable
 *     on the relay-stack origin, which never calls the scheduler;
 * 10. with a `stack` section: its files (the registry token 0600, the issue log's directory), the
 *     registry token's expiry, the stack instance (the config's, or with `stack.instance: "gray"` the one adopted
 *     from Gray, P12; every origin line includes the adopted origin), and the pull-token service through the public
 *     `token_url`: one challenge (no quote is sent) and the signed release status, verified with the relay key;
 * 11. with a `tunnel` section (docs/relay-tunnel.md): whether the rendezvous holds the relay's name (the running
 *     agent's status), the certificate the local terminator serves for it, whether the public name answers with
 *     that same key from here, and the CT monitor's verdict.
 *
 * Phase 2 (a config with a `chain`) runs no agent on the host. With no fresh status snapshot (`agentRunning`, the rule
 * `status` uses), every line that only a running agent serves or records (the scheduler's, the lane registration, the
 * agent status, the pull-token routes, the sealed accounts, the tunnel) is SKIP with that reason, and a snapshot left
 * from before the move is named stale with its age (`phase2Idle`).
 *
 * No secret is ever printed. A line names a path, a mode, a UID, the software name, an origin, a
 * digest or a fixed reason; it never names a token, a password or a body.
 */
import { accessSync, constants, lstatSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { connect as tlsConnect } from "node:tls";
import { isIP } from "node:net";
import { sha256BareHex } from "@gray/attest";
import { get, isObject, parsePlain, parseStrictBytes, type JsonObject } from "@gray/json";
import { SCHEDULER_API_VERSIONS, bytesToHex, randomBytes, verifySchedulerRequest, signSchedulerRequest } from "@gray/relay-connector";
import { policyOrigins, releasePinningProblem, stackPlaceholderProblem, type StackConfig } from "../daemon/config.ts";
import { STACK_ID_PATTERN } from "@gray/control";
import { stackInstanceAnswerSchema, type StackInstanceAnswer } from "@gray/control/stack-provision";
import { relayKeyFingerprint } from "@gray/control/stack-pairing";
import { RELAY_UNKNOWN_RETRY_MS, STACK_ACCOUNT_ID_RULE } from "../daemon/daemon.ts";
import { credentialFormatHint, credentialParkReason, metadataParkReason, planAccount } from "../daemon/eligibility.ts";
import { PULL_TOKEN_CHALLENGE_PATH, pullTokenCredentialProblem } from "../daemon/pull-token.ts";
import { RELEASE_STATUS_PATH, verifyReleaseStatusText } from "../daemon/release-status.ts";
import { fetchReleaseList, ReleaseListError, type VerifiedReleaseList } from "../daemon/releases.ts";
import { SCHEDULER_ENDPOINTS } from "../endpoints.ts";
import { RelayKitError } from "../errors.ts";
import { RELAY_ID_PLACEHOLDER } from "../init.ts";
import { attestLane, loadQuoteVerifier } from "./attest.ts";
import { configArgumentFor, loadRelayConfigFile, type LoadedRelayConfig } from "./config-file.ts";
import { isGroupOrOtherReadable, readPrivateFile } from "./files.ts";
import { httpsRequestOnce } from "./https.ts";
import { probePeerTunnel } from "./peer-tunnel.ts";
import { tunnelOriginOf, type TunnelOrigin } from "../lane-origin.ts";
import { createPlainDaemonFetch } from "./release-list-source.ts";
import { readControlView, type ControlView } from "./control.ts";
import { controlFileBeside } from "./daemon/control-file.ts";
import { agentRunning, readDaemonStatusFile } from "./daemon/status-file.ts";
import { accountAliasesPath, readAccountAliasesFile } from "./daemon/account-aliases-file.ts";
import { ACCOUNT_ALIAS_VENDOR_WORDS } from "../daemon/account-aliases.ts";
import { agentStatusVerdict } from "./daemon/agent-status-report.ts";
import { buildKeyFromText } from "./scheduler-load.ts";
import type { RelayKeyFile } from "../keys.ts";
import { osImageProvenance, type QuoteVerifier, type StackBootResult } from "@gray/lane-verify";
import { createHash } from "node:crypto";
import type { Hex } from "viem";
import type { ChainCheckResult } from "../chain/checks.ts";
import type { ReleaseState } from "../chain/releases.ts";
import type { TunnelConfig } from "../daemon/config.ts";
import type { LaneBinding } from "../lane-binding.ts";
import type { DaemonStackInstance } from "../daemon/types.ts";
import { normalizeHttpsOrigin } from "../verified-report.ts";
import { probeServedCertificate } from "./tunnel/supervisor.ts";

export type DoctorStatus = "ok" | "warn" | "fail" | "skip";

export interface DoctorLine {
  readonly id: string;
  readonly status: DoctorStatus;
  readonly message: string;
}

export interface DoctorReport {
  /** True only when no line is `fail`. `warn` does not fail the run. */
  readonly ok: boolean;
  readonly lines: readonly DoctorLine[];
}

export interface DoctorOptions {
  readonly configPath: string;
  /** A private trust anchor for the lane, the scheduler and the release list. */
  readonly ca?: string;
  /** Test-only quote verifier module (the same seam `attest` has). */
  readonly verifierModule?: string;
  readonly pccs?: string;
  /** A fixed clock, for the tests. Defaults to `Date.now`. */
  readonly nowMs?: number;
  /**
   * Phase 2: the relay's contract's answer for an attested compose and OS image hash (the check `deliver` makes).
   * Defaults to reading the config's `chain` RPCs; the tests pass a fixed answer.
   */
  readonly chainCheck?: (composeHash: Hex, osImageHash: Hex | null) => Promise<ChainCheckResult>;
  /**
   * Phase 2: which of these releases of Gray's signed list wait for the guardian on the relay's contract (proposed, not
   * yet effective, neither vetoed nor removed). Defaults to reading the config's `chain` RPCs (`pendingReleasesFor`);
   * the tests pass a fixed answer.
   */
  readonly pendingReleases?: (candidates: PendingCandidates) => Promise<PendingReleases>;
  /** Where the compose container has the kit directory (`KIT_MOUNT`); the tests name another. */
  readonly kitMount?: string;
  /**
   * Gray's unread messages for the relay (`./messages.ts` `readKitMessages`, one signed request to `stack.report_origin`);
   * `clock` reads this host's time when the answer arrives. The tests pass a fixed answer.
   */
  readonly messages?: (clock: () => number) => Promise<import("./messages.ts").MessagesRead>;
}

/** Gray's listed compose and OS image hashes, as `0x` hex. */
export interface PendingCandidates {
  readonly compose: readonly Hex[];
  readonly osImage: readonly Hex[];
}

/** The releases that wait for the guardian, at the block both RPCs have. */
export interface PendingReleases {
  readonly block: bigint;
  readonly pending: readonly ReleaseState[];
}

/** What a missing or unreadable accounts file of the `file` source is fixed with (`./accounts-import.ts`). */
export const ACCOUNTS_IMPORT_HINT =
  "put your accounts.json in the kit directory and run `gray-assistant accounts import /run/secrets/accounts.json` (the container sees the kit directory there), or pipe it: `docker compose run --rm --no-deps -T agent accounts import - < accounts.json`; it is checked and written here as 0600";

const DAY_MS = 86_400_000;
const CLOCK_SKEW_LIMIT_MS = 10_000;
const CERTIFICATE_WARN_DAYS = 14;

class Doctor {
  readonly lines: DoctorLine[] = [];

  add(id: string, status: DoctorStatus, message: string): void {
    this.lines.push({ id, status, message });
  }

  get failed(): boolean {
    return this.lines.some((line) => line.status === "fail");
  }
}

function modeText(mode: number): string {
  return (mode & 0o7777).toString(8).padStart(4, "0");
}

function ownerText(stat: { uid: number; gid: number }): string {
  return `uid ${stat.uid} gid ${stat.gid}`;
}

/** Check one secret file against the loader's rule and print what it is and what it must be. */
function checkSecretFile(doctor: Doctor, id: string, path: string, what: string, missing: string | null = null): void {
  try {
    const stat = lstatSync(path);
    const actual = `${what} ${path}: mode ${modeText(stat.mode)}, ${ownerText(stat)}`;
    const required = `required 0600, owned by uid ${typeof process.getuid === "function" ? process.getuid() : "the agent's user"}, no symlink`;
    if (stat.isSymbolicLink()) return doctor.add(id, "fail", `${actual}; it is a symbolic link (${required})`);
    if (!stat.isFile()) return doctor.add(id, "fail", `${actual}; not a regular file (${required})`);
    if (isGroupOrOtherReadable(stat.mode)) return doctor.add(id, "fail", `${actual}; group/other readable (${required})`);
    doctor.add(id, "ok", `${actual}; ${required}`);
  } catch {
    doctor.add(id, "fail", `${what} ${path}: missing (required 0600, owned by the agent's user)${missing === null ? "" : `; ${missing}`}`);
  }
}

interface OriginCheck {
  readonly origin: string;
  readonly ok: boolean;
  readonly spkiSha256: string | null;
  readonly composeHash: string | null;
  readonly tlsSpki: string | null;
}

async function releasePendingText(
  config: LoadedRelayConfig,
  composeHash: string | null,
  nowMs: number,
  firstSeen: Readonly<Record<string, number>>,
  accepted: readonly string[],
  acceptedAtMs: Readonly<Record<string, number>>,
  atPairing: readonly string[] = [],
): Promise<{ readonly accepted: boolean; readonly text: string }> {
  if (composeHash === null) return { accepted: false, text: "the report names no compose hash; the TEE is unpinned" };
  const first = firstSeen[composeHash];
  const acceptedAt = acceptedAtMs[composeHash];
  // R05: an explicit acceptance is the documented emergency override in both modes. R27: it counts
  // only when it is at or after the hash's current first sight, so a withdrawn release that a
  // replayed list re-lists still waits a new delay.
  if (accepted.includes(composeHash) && acceptedAt !== undefined && (first === undefined || acceptedAt >= first)) {
    return { accepted: true, text: atPairing.includes(composeHash) ? "accepted at pairing" : "accepted manually" };
  }
  if (config.daemon.releases.accept === "manual") {
    return { accepted: false, text: "manual acceptance required: run `gray-assistant releases accept <id>`" };
  }
  if (first === undefined) {
    return { accepted: false, text: `pending: first seen now, acceptable in ${config.daemon.releases.delayDays}d from first sight (the relay's own clock)` };
  }
  const at = first + config.daemon.releases.delayDays * DAY_MS;
  if (nowMs >= at) return { accepted: true, text: "accepted after the first-sight delay" };
  const remaining = at - nowMs;
  const hours = Math.ceil(remaining / 3_600_000);
  return { accepted: false, text: `pending: acceptable in ${hours}h (${config.daemon.releases.delayDays}d from first sight)` };
}

/**
 * Through Gray's entry the origin names the entry, not the VM (docs/design/relay-outbound-only.md section 5): the
 * agent's rule, the identity's relay is this relay (`attest_relay_mismatch`), is doctor's too. The failure's text for a
 * tunnel origin whose verified boot names another relay or none; null for a direct origin or this relay's VM.
 */
export function tunnelRelayProblem(origin: string, stackBoot: StackBootResult | null, relayId: string): string | null {
  if (tunnelOriginOf(origin) === null) return null;
  const attested = stackBoot !== null && stackBoot.ok && stackBoot.facts !== null ? stackBoot.facts.identity.relayId : null;
  if (attested === relayId) return null;
  return `${origin}: the VM behind the tunnel names ${attested === null ? "no relay" : `relay ${attested}`}, not this relay (${relayId}); gray-assistant sends it nothing (attest_relay_mismatch)`;
}

async function checkOrigin(
  doctor: Doctor,
  config: LoadedRelayConfig,
  release: VerifiedReleaseList | null,
  quoteVerifier: QuoteVerifier,
  controlView: ControlView,
  origin: string,
  nowMs: number,
  ca: string | undefined,
  chainCheck: ((composeHash: Hex, osImageHash: Hex | null) => Promise<ChainCheckResult>) | null = null,
): Promise<OriginCheck> {
  const nowSecs = BigInt(Math.floor(nowMs / 1000));
  if (release === null) {
    // R01: no signed release list means no pinning at all. Never attest with the unpinned flags
    // (an OS image that was never checked must not be reported as accepted).
    doctor.add(`origin:${origin}`, "skip", `${origin}: skipped: the signed release list is unavailable; not attested`);
    return { origin, ok: false, spkiSha256: null, composeHash: null, tlsSpki: null };
  }
  const expectedInstance = config.daemon.lane.instances.get(origin) ?? adoptedBinding(config, controlView, origin);
  if (expectedInstance === undefined) {
    // The config loader refuses an origin without an entry; this keeps the check honest regardless.
    doctor.add(`origin:${origin}`, "fail", `${origin}: lane.instances has no app_id and kms_ca_pubkey for this origin`);
    return { origin, ok: false, spkiSha256: null, composeHash: null, tlsSpki: null };
  }
  const nonce = bytesToHex(randomBytes(32));
  let result;
  try {
    result = await attestLane({
      origin,
      release: release.list,
      allowUnpinned: false,
      acceptUnpinned: false,
      acceptOsUnpinned: false,
      nonce,
      nowSecs,
      ca,
      quoteVerifier,
      expectedInstance,
    });
  } catch {
    doctor.add(`origin:${origin}`, "fail", `${origin}: the attestation request failed (network or TLS)`);
    return { origin, ok: false, spkiSha256: null, composeHash: null, tlsSpki: null };
  }
  if (!result.ok) {
    const stage = result.stage === "report" ? "the lane served no ACI report" : result.stage === "verification" ? "the report did not verify" : `verdict ${result.verdict}`;
    doctor.add(`origin:${origin}`, "fail", `${origin}: ${stage}`);
    return { origin, ok: false, spkiSha256: result.stage === "report" ? null : result.spkiSha256, composeHash: null, tlsSpki: null };
  }
  const composeHash = result.verification.composeHash;
  const otherRelay = tunnelRelayProblem(origin, result.verification.stackBoot, config.daemon.relayId);
  if (otherRelay !== null) {
    doctor.add(`origin:${origin}`, "fail", otherRelay);
    return { origin, ok: false, spkiSha256: result.spkiSha256, composeHash, tlsSpki: result.verification.tlsSpkiSha256 };
  }
  const listed = composeHash !== null && (release?.list.composeHashes.includes(composeHash) ?? false);
  if (!listed) {
    doctor.add(
      `origin:${origin}`,
      "fail",
      `${origin}: attested keyset ${(result.verification.keysetDigest ?? "missing").slice(0, 16)}…, compose ${composeHash ?? "missing"}; the signed release list does not name it`,
    );
    return { origin, ok: false, spkiSha256: result.spkiSha256, composeHash, tlsSpki: result.verification.tlsSpkiSha256 };
  }
  if (chainCheck !== null) {
    // Phase 2: the relay's contract decides which releases run, not the host's first-sight delay (no agent here).
    const osImage = result.verification.osImageHash === null ? null : (`0x${result.verification.osImageHash}` as Hex);
    let chain: ChainCheckResult | null = null;
    try {
      chain = await chainCheck(`0x${composeHash}` as Hex, osImage);
    } catch {
      chain = null;
    }
    const verdict = chain === null
      ? { status: "fail" as const, text: "the relay's contract could not be read" }
      : chain.ok
        ? { status: "ok" as const, text: `allowed by the relay's contract (block ${chain.block})` }
        : { status: "fail" as const, text: `the relay's contract does not allow it (${chain.reason}: ${chain.detail})` };
    doctor.add(`origin:${origin}`, verdict.status, `${origin}: attested, compose ${composeHash.slice(0, 16)}…, release ${verdict.text}`);
    return { origin, ok: true, spkiSha256: result.spkiSha256, composeHash, tlsSpki: result.verification.tlsSpkiSha256 };
  }
  const accepted = await releasePendingText(
    config,
    composeHash,
    nowMs,
    controlView.releaseFirstSeen,
    controlView.control.acceptedReleases,
    controlView.control.acceptedAtMs ?? {},
    controlView.control.acceptedAtPairing ?? [],
  );
  doctor.add(
    `origin:${origin}`,
    accepted.accepted ? "ok" : "fail",
    `${origin}: attested, compose ${composeHash.slice(0, 16)}…, release ${accepted.text}`,
  );
  return { origin, ok: true, spkiSha256: result.spkiSha256, composeHash, tlsSpki: result.verification.tlsSpkiSha256 };
}

/**
 * What `init --pair` accepted (`releases.accepted_at_pairing`): each hash by name, and whether the agent has taken it
 * (control.json's `accepted_at_pairing`), will take it at its first sight, or no longer can (rejected, or gone from
 * Gray's list). A paired config without one is a warning: its first release waits the delay.
 */
function checkPairingReleases(doctor: Doctor, config: LoadedRelayConfig, release: VerifiedReleaseList | null, controlView: ControlView): void {
  const hashes = config.daemon.releases.acceptedAtPairing;
  const pairing = config.daemon.pairing;
  if (hashes.length === 0) {
    if (pairing === null) return;
    const delay = config.daemon.releases.delayDays;
    doctor.add(
      "release_pairing",
      "warn",
      `the pairing at ${pairing.pairedAt} recorded no release of Gray's list (it could not be read then), so the current release waits ${delay}d from the agent's first sight; to run it now, accept its compose hash and its OS image hash with gray-assistant releases accept once gray-assistant status lists them`,
    );
    return;
  }
  const taken = new Set(controlView.control.acceptedAtPairing ?? []);
  const rejected = new Set(controlView.control.rejectedReleases ?? []);
  const parts = hashes.map((hash) => {
    const entry = release?.list.releases.find((candidate) => candidate.compose_hash === hash);
    const image = entry === undefined ? release?.list.osImages.find((candidate) => candidate.os_image_hash === hash) : undefined;
    const provenance = image === undefined ? null : osImageProvenance(image);
    const name = entry !== undefined
      ? `release ${entry.git_tag ?? entry.git_commit?.slice(0, 12) ?? "untagged"} ${hash.slice(0, 16)}…`
      : image !== undefined
        ? `OS image ${provenance?.ok === true ? (provenance.version ?? "unversioned") : "unverified"} ${hash.slice(0, 16)}…`
        : `${hash.slice(0, 16)}…`;
    const state = rejected.has(hash)
      ? "rejected by you"
      : taken.has(hash)
        ? "accepted"
        : release !== null && entry === undefined && image === undefined
          ? "no longer in Gray's list"
          : "accepted when the agent first reads the list";
    return `${name} ${state}`;
  });
  const source = pairing === null ? "init --pair" : `the pairing at ${pairing.pairedAt}`;
  doctor.add("release_pairing", "ok", `${source} accepted the releases Gray listed then: ${parts.join("; ")}; later releases wait ${config.daemon.releases.delayDays}d from the agent's first sight`);
}

/**
 * The two steps before a tunnel origin's attestation (docs/design/relay-outbound-only.md §5): Gray's entry answers
 * (its certificate checked with WebPKI), and it opens the tunnel to this relay's VM. False when either fails.
 */
export async function checkPeerTunnel(doctor: { add(id: string, status: DoctorStatus, message: string): void }, origin: string, tunnel: TunnelOrigin, ca: string | undefined): Promise<boolean> {
  const entryHost = new URL(tunnel.entry).host;
  try {
    await probePeerTunnel(tunnel, { ...(ca === undefined ? {} : { ca }), timeoutMs: 10_000 });
  } catch (error) {
    if (error instanceof RelayKitError && error.code === "tunnel_refused") {
      doctor.add(`entry:${origin}`, "ok", `Gray's entry ${entryHost} answers`);
      doctor.add(`tunnel:${origin}`, "fail", error.message);
      return false;
    }
    const message = error instanceof RelayKitError ? error.message : `Gray's entry ${entryHost} is unreachable`;
    doctor.add(`entry:${origin}`, "fail", `${message}; check this host's DNS, outbound HTTPS and clock`);
    doctor.add(`tunnel:${origin}`, "skip", "not tried: the entry is unreachable");
    return false;
  }
  doctor.add(`entry:${origin}`, "ok", `Gray's entry ${entryHost} answers`);
  doctor.add(`tunnel:${origin}`, "ok", `the entry opened a tunnel to relay ${tunnel.relayId}'s VM`);
  return true;
}

/** This host's clock against Gray's (the `Date` of Gray's answer to the messages request): the clock lines' third reference. */
export interface GrayClock {
  /** This host's clock minus Gray's, in ms, when Gray's answer arrived (an HTTP date is whole seconds, so up to a second high). */
  readonly hostAheadMs: number;
}

/** A host clock within this of Gray's is right: an HTTP date's second, the answer's way back, and room. */
const HOST_CLOCK_LIMIT_MS = 5_000;

/**
 * What a clock sample means (kit 1.6.2). `skewMs` is this host's clock minus the VM's, both read when the VM's answer
 * arrived; `gray` is this host's clock against Gray's, null when Gray's clock was not read; `refusedBeyondS` is the
 * difference at which something is refused (the limits the VM and the scheduler really apply; `CLOCK_SKEW_LIMIT_MS` is
 * only this line's own early warning).
 *
 * - Within ±10 s: OK.
 * - Past it with this host's clock right by Gray's: the VM's clock is off. A WARN, not the relay's FAIL: the relay
 *   cannot set a VM's clock and has nothing to do.
 * - Past it with this host's clock off Gray's: a FAIL that says how to set it.
 * - Past it with no reading of Gray's clock: a FAIL as before, that says how to tell which side it is.
 */
export function clockVerdict(origin: string, skewMs: number, gray: GrayClock | null, refusedBeyondS: number): { readonly status: DoctorStatus; readonly message: string } {
  const seconds = (ms: number): string => (Math.abs(ms) / 1000).toFixed(1);
  const within = `nothing is refused for it: a delivery, a sign-in or a signed call is refused only when the two clocks are more than ${refusedBeyondS} s apart, and customers' requests do not depend on it`;
  if (Math.abs(skewMs) <= CLOCK_SKEW_LIMIT_MS) return { status: "ok", message: `${origin}: relay clock − TEE clock = ${Math.round(skewMs)} ms (limit ±${CLOCK_SKEW_LIMIT_MS} ms)` };
  const past = Math.abs(skewMs) > refusedBeyondS * 1000;
  if (gray === null) {
    return {
      status: "fail",
      message: `${origin}: relay clock − TEE clock = ${Math.round(skewMs)} ms (limit ±${CLOCK_SKEW_LIMIT_MS} ms), and Gray's clock could not be read to tell which side is off. Check this host's clock first (timedatectl status, or date -u against a clock you trust; turn NTP on: timedatectl set-ntp true). If this host is right, it is the VM's clock, not yours: nothing for you to do, and do not restart the VM for it. ${past ? `The two are more than ${refusedBeyondS} s apart, so the VM refuses this host's deliveries and sign-ins as stale until the clock that is off is set right` : `Until then ${within}`}`,
    };
  }
  // The VM's clock against Gray's, from the two samples this host took.
  const vmAheadMs = gray.hostAheadMs - skewMs;
  const hostRight = Math.abs(gray.hostAheadMs) <= HOST_CLOCK_LIMIT_MS;
  if (hostRight) {
    return {
      status: "warn",
      message: `${origin}: the VM's clock is ${seconds(vmAheadMs)} s ${vmAheadMs > 0 ? "ahead of" : "behind"} Gray's, and this host's agrees with Gray's (within ${seconds(gray.hostAheadMs)} s): the VM's clock, not yours; nothing for you to do, and do not restart the VM for it. ${past ? `It is more than ${refusedBeyondS} s off, so the VM refuses deliveries and sign-ins as stale until Gray sets it right: tell Gray` : `${within[0]!.toUpperCase()}${within.slice(1)}`}`,
    };
  }
  const vmToo = Math.abs(vmAheadMs) > CLOCK_SKEW_LIMIT_MS ? ` The VM's clock is ${seconds(vmAheadMs)} s ${vmAheadMs > 0 ? "ahead of" : "behind"} Gray's as well; that one is not yours to set.` : "";
  return {
    status: "fail",
    message: `${origin}: this host's clock is ${seconds(gray.hostAheadMs)} s ${gray.hostAheadMs > 0 ? "ahead of" : "behind"} Gray's (relay clock − TEE clock = ${Math.round(skewMs)} ms, limit ±${CLOCK_SKEW_LIMIT_MS} ms): set this host's clock right, then run doctor again. Turn NTP on (timedatectl set-ntp true; with chrony: chronyc makestep); in a VM, WSL or Docker Desktop, sync the machine under it. ${past ? `The two clocks are more than ${refusedBeyondS} s apart: the VM refuses this host's deliveries and sign-ins as stale until it is set` : `Until then ${within}`}.${vmToo}`,
  };
}

/** Where a clock sample is judged: this host's clock now (not the run's start), Gray's clock, and the refusal window. */
interface ClockContext {
  readonly hostNow: () => number;
  readonly gray: GrayClock | null;
  readonly refusedBeyondS: number;
}

/** True when a request pinned to the attested key answered: the clock sample doubles as the tunnel's pin check. */
async function checkClock(doctor: Doctor, origin: string, spkiSha256: string | null, clock: ClockContext, ca: string | undefined): Promise<RelayKitError | null> {
  if (spkiSha256 === null) {
    doctor.add(`clock:${origin}`, "skip", `${origin}: no verified TLS key, clock not sampled`);
    return new RelayKitError("tls_spki_mismatch", "no verified TLS key");
  }
  try {
    const response = await httpsRequestOnce({
      url: `${origin}/healthz`,
      method: "GET",
      headers: { accept: "application/json" },
      ...(ca === undefined ? {} : { ca }),
      expectedSpkiSha256: spkiSha256,
      timeoutMs: 10_000,
      maxResponseBytes: 64 * 1024,
    });
    // This host's clock when the answer arrived: the run began seconds ago (the source, the release list, the
    // attestation), and comparing the VM's date with the run's start made every VM look that much ahead.
    const hostMs = clock.hostNow();
    const date = response.headers["date"];
    const text = Array.isArray(date) ? date[0] : date;
    const teeMs = typeof text === "string" ? Date.parse(text) : Number.NaN;
    if (!Number.isFinite(teeMs)) {
      // Gray's lane answers /healthz without a Date header today: nothing the relay can change, so a skip, not a warning.
      doctor.add(`clock:${origin}`, "skip", `${origin}: /healthz carried no parseable Date header, so the TEE clock was not compared (Gray's side; no action needed)`);
      return null;
    }
    const verdict = clockVerdict(origin, hostMs - teeMs, clock.gray, clock.refusedBeyondS);
    doctor.add(`clock:${origin}`, verdict.status, verdict.message);
    return null;
  } catch (error) {
    const code = error instanceof RelayKitError ? error.code : "io";
    doctor.add(`clock:${origin}`, "fail", `${origin}: cannot sample the TEE clock (${code})`);
    return error instanceof RelayKitError ? error : new RelayKitError("io", "the pinned request failed");
  }
}

interface CertificateInfo {
  readonly validToMs: number;
  readonly subject: string;
}

function readCertificate(url: string, ca: string | undefined): Promise<CertificateInfo> {
  const target = new URL(url);
  const port = target.port === "" ? 443 : Number(target.port);
  return new Promise<CertificateInfo>((resolve, reject) => {
    const socket = tlsConnect({
      host: target.hostname,
      port,
      ...(isIP(target.hostname) === 0 ? { servername: target.hostname } : {}),
      ...(ca === undefined ? {} : { ca }),
      rejectUnauthorized: true,
    });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("timeout"));
    }, 10_000);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      const certificate = socket.getPeerCertificate(false);
      socket.end();
      if (certificate === null || certificate === undefined || typeof certificate.valid_to !== "string") {
        reject(new Error("no certificate"));
        return;
      }
      resolve({
        validToMs: Date.parse(certificate.valid_to),
        subject: typeof certificate.subject?.CN === "string" ? certificate.subject.CN : target.hostname,
      });
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function checkSchedulerEcho(doctor: Doctor, config: LoadedRelayConfig, key: RelayKeyFile, nowMs: number, ca: string | undefined): Promise<void> {
  const publicUrl = config.daemon.scheduler.publicUrl;
  if (publicUrl === null) {
    doctor.add("scheduler_echo", "fail", "scheduler.public_url is not configured; the TEE has no URL to call");
    return;
  }
  const base = new URL(publicUrl);
  const prefix = base.pathname === "/" ? "" : base.pathname.replace(/\/+$/u, "");
  const path = `${prefix}${SCHEDULER_ENDPOINTS.doctorEcho}`;
  const requestUrl = `${base.origin}${path}`;
  const nonce = bytesToHex(randomBytes(16));
  const body = new TextEncoder().encode(JSON.stringify({ nonce, marker: bytesToHex(randomBytes(16)) }));
  const headers = await signSchedulerRequest({
    method: "POST",
    path,
    relayId: config.daemon.relayId,
    keyId: "doctor",
    timestampMs: nowMs,
    nonce,
    body,
    signingKey: key.seed,
  });
  try {
    const response = await httpsRequestOnce({
      url: requestUrl,
      method: "POST",
      headers: { ...headers, "content-type": "application/json", accept: "application/json" },
      body,
      ...(ca === undefined ? {} : { ca }),
      timeoutMs: 15_000,
      maxResponseBytes: 64 * 1024,
    });
    if (response.status !== 200) {
      doctor.add("scheduler_echo", "fail", `${publicUrl}: the echo route answered ${response.status}; check the proxy path and that the agent is current`);
      return;
    }
    let value: unknown;
    try {
      value = parsePlain(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(response.body));
    } catch {
      doctor.add("scheduler_echo", "fail", `${publicUrl}: the echo answer is not JSON`);
      return;
    }
    const echo = isObject(value as never) ? get(value as never, "echo") : undefined;
    if (!isObject(echo)) {
      doctor.add("scheduler_echo", "fail", `${publicUrl}: the echo answer has no echo object`);
      return;
    }
    const echoed: Readonly<Record<string, string | null>> = {
      method: get(echo, "method") === "POST" ? "POST" : null,
      path: get(echo, "path") === path ? path : null,
      api_version: get(echo, "api_version") === headers["x-gray-api-version"] ? (headers["x-gray-api-version"] as string) : null,
      key_id: get(echo, "key_id") === headers["x-gray-key-id"] ? (headers["x-gray-key-id"] as string) : null,
      timestamp: get(echo, "timestamp") === headers["x-gray-timestamp"] ? (headers["x-gray-timestamp"] as string) : null,
      nonce: get(echo, "nonce") === headers["x-gray-nonce"] ? (headers["x-gray-nonce"] as string) : null,
      signature: get(echo, "signature") === headers["x-gray-signature"] ? (headers["x-gray-signature"] as string) : null,
    };
    const changed = Object.entries(echoed).filter(([, value]) => value === null).map(([name]) => name);
    const bodySha = get(echo, "body_sha256");
    const bodyIntact = bodySha === sha256BareHex(body);
    if (changed.length > 0 || !bodyIntact) {
      doctor.add("scheduler_echo", "fail", `${publicUrl}: the proxy changed ${[...changed, ...(bodyIntact ? [] : ["body"])].join(", ")}`);
      return;
    }
    const verified = await verifySchedulerRequest({
      method: "POST",
      path,
      relayId: config.daemon.relayId,
      headers: { get: (name) => headers[name] ?? null },
      body,
      nowMs,
      keyFor: () => key.publicKey,
    });
    if (!verified.ok) {
      doctor.add("scheduler_echo", "fail", `${publicUrl}: the echoed signed headers do not verify (${verified.reason})`);
      return;
    }
    doctor.add("scheduler_echo", "ok", `${publicUrl}: signed headers and body arrived unchanged (echo verified)`);
  } catch (error) {
    const code = error instanceof RelayKitError ? error.code : "io";
    doctor.add("scheduler_echo", "fail", `${publicUrl}: unreachable through the proxy (${code})`);
  }
}

/**
 * D116(b): the scheduler API version each configured replica's TEE uses. The doctor never calls the
 * scheduler as the TEE, so it reads what the running agent recorded from the TEE's verified calls
 * (its status file): the version header those calls carried, which is not part of the signed string.
 * A TEE whose version this relay-kit does not accept is refused on every call, which the agent logs
 * as `scheduler_unknown_key` (reason `bad_api_version`): upgrade the relay-kit.
 *
 * The relay-stack origin (`stack.lane_origin`, or the adopted instance's) never calls this scheduler: the lane hands
 * each request to the relay's own software in the VM, which picks the account (deploy/tee/compose.stack.yaml,
 * `LANE_STACK_RELAY_ADDRESS`; the bridge's `scheduler.forward`, which no stack relay uses). There a missing version is
 * not a wait but "not applicable", said so; a version the agent did record is still reported, and every other origin
 * of the same config keeps the wait.
 */
function checkSchedulerApi(doctor: Doctor, config: LoadedRelayConfig, origins: readonly string[], stackOrigin: string | null): void {
  const accepted = SCHEDULER_API_VERSIONS.join(", ");
  const byOrigin = statusReplicas(config);
  for (const origin of origins) {
    const replica = byOrigin.get(origin);
    const version = replica === undefined ? undefined : get(replica, "scheduler_api_version");
    if (typeof version === "number" || typeof version === "bigint") {
      doctor.add(`scheduler_api:${origin}`, "ok", `${origin}: the TEE uses scheduler API version ${String(version)}; this relay-kit accepts ${accepted}`);
    } else if (origin === stackOrigin) {
      doctor.add(
        `scheduler_api:${origin}`,
        "skip",
        `${origin}: not applicable: on the relay-stack origin your software in the VM picks the account and the lane never calls this scheduler, so no version is recorded (stack_accounts and served requests show the stack's health)`,
      );
    } else {
      doctor.add(`scheduler_api:${origin}`, "skip", `${origin}: no verified scheduler call recorded yet (gray-assistant run records the version the TEE uses); this relay-kit accepts ${accepted}`);
    }
  }
}

/** The relay-stack origin: the config's `stack.lane_origin`, or the adopted instance's (P12); null without a stack or before adoption. */
function stackLaneOrigin(config: LoadedRelayConfig, controlView: ControlView): string | null {
  const stack = config.daemon.stack;
  if (stack === null) return null;
  return stack.laneOrigin ?? adoptedStack(config, controlView)?.laneOrigin ?? null;
}

/**
 * P12: the stack instance adopted from Gray (control.json's `stack_instance`) with `stack.instance: "gray"`; null with
 * `config` or before the first adoption.
 */
function adoptedStack(config: LoadedRelayConfig, controlView: ControlView): DaemonStackInstance | null {
  return config.daemon.stack?.instanceSource === "gray" ? (controlView.control.stackInstance ?? null) : null;
}

/** The adopted stack instance's binding when `origin` is its origin. */
function adoptedBinding(config: LoadedRelayConfig, controlView: ControlView, origin: string): LaneBinding | undefined {
  const adopted = adoptedStack(config, controlView);
  return adopted === null || adopted.laneOrigin !== origin ? undefined : { appId: adopted.appId, kmsCaPubkey: adopted.kmsCaPubkey };
}

/** The lane origins doctor checks: the config's, and the adopted stack instance's (P12). */
function doctorOrigins(config: LoadedRelayConfig, controlView: ControlView): readonly string[] {
  const adopted = adoptedStack(config, controlView);
  const origins = config.daemon.lane.origins;
  return adopted === null || origins.includes(adopted.laneOrigin) ? origins : [...origins, adopted.laneOrigin];
}

/** The running agent's replicas from its status file, by origin; empty when it has not written one. */
function statusReplicas(config: LoadedRelayConfig): Map<string, JsonObject> {
  const snapshot = readDaemonStatusFile(config.daemon.statusFile);
  const status = snapshot === null ? undefined : get(snapshot, "status");
  const replicas = isObject(status as never) ? get(status as never, "replicas") : undefined;
  const byOrigin = new Map<string, JsonObject>();
  for (const replica of Array.isArray(replicas) ? replicas : []) {
    if (!isObject(replica)) continue;
    const origin = get(replica, "origin");
    if (typeof origin === "string") byOrigin.set(origin, replica);
  }
  return byOrigin;
}

/**
 * Whether each lane lists this relay, as the running agent last saw it (its status file). A lane
 * that keeps answering `unknown_relay` (403) does not hold this relay in the registry it reads from
 * Gray's signed snapshot; the agent retries at the snapshot's pace and this line names the refusal.
 */
function checkLaneRegistration(doctor: Doctor, config: LoadedRelayConfig, origins: readonly string[]): void {
  const byOrigin = statusReplicas(config);
  for (const origin of origins) {
    const replica = byOrigin.get(origin);
    if (replica === undefined) {
      doctor.add(`lane_registration:${origin}`, "skip", `${origin}: no status recorded yet (gray-assistant run records whether the lane lists this relay)`);
      continue;
    }
    const reasons = get(replica, "reasons");
    if (!Array.isArray(reasons) || !reasons.includes("relay_unknown")) {
      doctor.add(`lane_registration:${origin}`, "ok", `${origin}: no standing unknown_relay refusal`);
      continue;
    }
    const next = get(replica, "next_attempt_at_ms");
    const retry = typeof next === "number" ? `; next attempt ${new Date(next).toISOString()}` : "";
    doctor.add(
      `lane_registration:${origin}`,
      "fail",
      `${origin}: the lane refuses this relay as unknown_relay (403): it does not list relay ${config.daemon.relayId}; check the registration with Gray (the agent retries every ${RELAY_UNKNOWN_RETRY_MS / 60_000} minutes${retry})`,
    );
  }
}

/** A pairing without a contract (no `chain` member): what `doctor` and `upgrade` say about it. */
export const PHASE1_TEXT =
  "this relay is still on phase 1 (its pairing made no release contract: the config has no chain member) and must pair again to phase 2; its VM cannot connect to Gray until then. Delete the relay's VM if it has one (the console's VM tab, Delete VM; the relay's settings stay), apply the relay-stack document with relay_stack.registry_user for a pairing code, and run the answer's pairing.command from the directory that holds this kit directory (relay-workspace): it pairs again with this relay-key.json (relay-stack.md section 10)";

/**
 * Phase 2 with no agent on this host: a config with a `chain` and no fresh status snapshot (`agentRunning`). Returns the
 * reason the host agent's lines are skipped, naming a snapshot left from before the move stale with its age; null while
 * an agent runs, and before phase 2.
 */
export function phase2Idle(config: LoadedRelayConfig, nowMs: number): string | null {
  if ((config.daemon.chain ?? null) === null) return null;
  const snapshot = readDaemonStatusFile(config.daemon.statusFile);
  if (agentRunning(snapshot, config.daemon.tickMs, nowMs)) return null;
  const written = snapshot === null ? undefined : get(snapshot, "written_at_ms");
  const ageMinutes = typeof written === "number" ? Math.max(0, Math.floor((nowMs - written) / 60_000)) : null;
  const stale = ageMinutes === null ? "" : `; the status file is stale (written ${Math.floor(ageMinutes / 60)} h ${ageMinutes % 60} min ago, before the move)`;
  return `phase 2: no agent runs on this host${stale}`;
}

/** Phase 2's release check: the test seam, else the config's contract over its RPCs; null before phase 2. */
function chainCheckOf(options: DoctorOptions, config: LoadedRelayConfig): ((composeHash: Hex, osImageHash: Hex | null) => Promise<ChainCheckResult>) | null {
  if ((config.daemon.chain ?? null) === null) return null;
  if (options.chainCheck !== undefined) return options.chainCheck;
  return async (composeHash, osImageHash) => {
    const { chainChecksFor, readChainContext } = await import("./chain.ts");
    const context = readChainContext(options.configPath);
    if (context === null) throw new RelayKitError("usage", "the config has no chain member");
    return (await chainChecksFor(context, composeHash, osImageHash)).result;
  };
}

/**
 * Phase 2: the guardian key where the guardian's commands read it (`readContextGuardianKey`: beside the config, else
 * under the kit's mount). Without it `releases approve|reject|delay`, `pause` and `unpause` sign nothing, so a key that
 * is missing, unsafe, not a guardian key or not `chain.guardian`'s is a FAIL with the command's own refusal.
 */
async function checkGuardianKey(doctor: Doctor, options: DoctorOptions): Promise<void> {
  try {
    const { readChainContext, readContextGuardianKey } = await import("./chain.ts");
    const context = readChainContext(options.configPath, options.kitMount);
    if (context === null) return;
    const key = readContextGuardianKey(context);
    doctor.add("guardian_key", "ok", `guardian key ${context.guardianKeyPath}: ${key.address}, the config's chain.guardian; releases approve, reject and delay, pause and unpause sign with it`);
  } catch (error) {
    const reason = error instanceof RelayKitError ? (error.detail ?? error.code) : "the guardian key could not be read";
    doctor.add("guardian_key", "fail", `${reason}; until it is readable, releases approve, reject and delay, pause and unpause cannot sign`);
  }
}

/**
 * Phase 2: the releases of Gray's signed list that wait for the guardian on the relay's contract, in one line with the
 * commands that check and approve each. A contract that cannot be read is a warning that says so, never a FAIL: the
 * origin lines judge the release that runs.
 */
async function checkPendingReleases(doctor: Doctor, options: DoctorOptions, release: VerifiedReleaseList, nowMs: number): Promise<void> {
  const hex = (hash: string): Hex => `0x${hash}` as Hex;
  const candidates: PendingCandidates = { compose: release.list.composeHashes.map(hex), osImage: release.list.osImageHashes.map(hex) };
  let answer: PendingReleases;
  try {
    if (options.pendingReleases !== undefined) answer = await options.pendingReleases(candidates);
    else {
      const { pendingReleasesFor, readChainContext } = await import("./chain.ts");
      const context = readChainContext(options.configPath, options.kitMount);
      if (context === null) return;
      answer = await pendingReleasesFor(context, candidates, { nowMs });
    }
  } catch (error) {
    const reason = error instanceof RelayKitError ? `${error.code}${error.detail === null ? "" : `: ${error.detail}`}` : "an RPC endpoint could not be read";
    doctor.add("releases_pending", "warn", `the relay's contract could not be read (${reason}), so whether a release waits for your approval is not known; gray-assistant releases check <hash> reads one`);
    return;
  }
  if (answer.pending.length === 0) {
    doctor.add("releases_pending", "ok", `no release of Gray's signed list waits for your approval on the relay's contract (block ${answer.block})`);
    return;
  }
  const config = configArgumentFor(options.configPath);
  const each = answer.pending.map((state) => {
    const kind = state.kind === "os_image" ? " --kind os_image" : "";
    const at = new Date(Number(state.effectiveAt) * 1000).toISOString();
    return `${state.kind === "compose" ? "compose" : "OS image"} ${state.hash} takes effect at ${at} unless you veto it: check it with \`gray-assistant releases check ${state.hash}${kind}${config}\`, let it in now with \`gray-assistant releases approve ${state.hash}${kind}${config}\``;
  });
  doctor.add("releases_pending", "warn", `${answer.pending.length === 1 ? "1 release Gray proposed waits" : `${answer.pending.length} releases Gray proposed wait`} for your approval on the relay's contract (block ${answer.block}): ${each.join("; ")}`);
}

/** Run every check. It never throws for a failed check; only a programming error would escape. */
export async function runDoctor(options: DoctorOptions): Promise<DoctorReport> {
  const doctor = new Doctor();
  const nowMs = options.nowMs ?? Date.now();
  // This host's clock at any later moment of the run (a clock sample is taken seconds after the run began); a fixed
  // clock (`--now`, the tests) stays fixed.
  const hostNow = options.nowMs !== undefined ? (): number => nowMs : (): number => Date.now();
  let config: LoadedRelayConfig;
  try {
    config = loadRelayConfigFile(options.configPath);
  } catch (error) {
    const code = error instanceof RelayKitError ? error.code : "usage";
    // The loader's messages name a member or a path and never echo a config value; keep the member
    // visible here so an unset `lane.release_list` still names the key to fill (K5-1).
    const detail = error instanceof RelayKitError ? `: ${error.message}` : "";
    doctor.add("config", "fail", `the config does not load (${code})${detail}; see gray-assistant init`);
    return { ok: false, lines: doctor.lines };
  }
  const placeholder = config.daemon.relayId === RELAY_ID_PLACEHOLDER || (config.daemon.scheduler.publicUrl ?? "").includes("scheduler.example") || config.daemon.relayId.includes("REPLACE");
  if (placeholder) {
    doctor.add("config", "fail", `the config is the init skeleton: replace relay_id and scheduler.public_url with Gray's registration values`);
  } else {
    doctor.add("config", "ok", `config ${config.path}: relay ${config.daemon.relayId}, source ${config.source.kind}`);
  }

  // K5-1: the placeholder is a FAIL line. K5-8: doctor still runs every check that does not need
  // the release key/list, and those lines say why they were skipped.
  const pinning = releasePinningProblem(config.daemon);
  const releasePlaceholderSkip = "skipped: release key/list not configured";
  const controlFile = controlFileBeside(config.daemon.stateFile);
  const controlView = await readControlView(config.daemon.stateFile, controlFile);
  const idle = phase2Idle(config, nowMs);

  // The key is needed for the scheduler echo and every origin check; a bad key stops those.
  let key: RelayKeyFile | null = null;
  checkSecretFile(doctor, "key_permissions", config.daemon.keyPath, "relay key");
  try {
    const text = readPrivateFile(config.daemon.keyPath, "relay key", 64 * 1024);
    key = await buildKeyFromText(text);
  } catch (error) {
    const code = error instanceof RelayKitError ? error.code : "io";
    doctor.add("key_content", "fail", `relay key ${config.daemon.keyPath}: ${code}`);
  }
  // Gray's messages for the relay, read now: the answer's Date is Gray's clock, which the clock lines below compare
  // this host's with; the `messages` line itself is the run's last.
  const messages = await readMessages(options, config, key, nowMs, hostNow);
  if (config.source.kind === "file") {
    checkSecretFile(doctor, "accounts_permissions", config.source.path, "accounts file", ACCOUNTS_IMPORT_HINT);
  } else {
    checkSecretFile(doctor, "token_permissions", config.source.tokenFile, "source token file");
  }
  if (config.daemon.scheduler.adminTokenFile !== null) {
    checkSecretFile(doctor, "admin_token_permissions", config.daemon.scheduler.adminTokenFile, "admin token file");
  }
  if ((config.daemon.chain ?? null) !== null) await checkGuardianKey(doctor, options);
  // S23: the relay-stack origin runs no policy module; a relay with no other origin needs no bundle.
  const policyPath = policyOrigins(config.daemon).length === 0 ? null : config.daemon.policyBundlePath;
  if (policyPath === null) {
    doctor.add("policy_bundle", "skip", "no policy bundle needed: the only lane origin is the relay-stack app (stack.lane_origin), which runs no policy module");
  } else {
    try {
      const stat = statSync(policyPath);
      doctor.add("policy_bundle", stat.isFile() ? "ok" : "fail", `policy bundle ${policyPath}: ${stat.isFile() ? "regular file" : "not a regular file"}`);
    } catch {
      doctor.add("policy_bundle", "fail", `policy bundle ${policyPath}: missing`);
    }
  }
  const stateDirectory = config.daemon.stateFile.replace(/\/[^/]*$/u, "") || ".";
  try {
    if (!statSync(stateDirectory).isDirectory()) throw new Error("not a directory");
    accessSync(stateDirectory, constants.W_OK);
    doctor.add("state_permissions", "ok", `state directory ${stateDirectory}: writable`);
  } catch {
    doctor.add("state_permissions", "fail", `state directory ${stateDirectory}: not a writable directory`);
  }
  if (pinning !== null) {
    doctor.add("release_key", "fail", pinning.message);
  } else {
    doctor.add("release_key", "ok", `release key ${bytesToHex(config.daemon.lane.releasePublicKey).slice(0, 16)}… pinned`);
  }
  // S57: what `init --pair` left for the relay, refused by `run` as the release placeholders are.
  const stackPlaceholder = stackPlaceholderProblem(config.daemon);
  if (stackPlaceholder !== null) doctor.add("stack_placeholders", "fail", stackPlaceholder.message);
  // S57: where the values came from, and whether the key is still the one Gray paired.
  const pairing = config.daemon.pairing;
  if (pairing !== null) {
    const fingerprint = key === null ? null : relayKeyFingerprint(bytesToHex(key.publicKey));
    if (fingerprint !== null && fingerprint !== pairing.fingerprint) {
      doctor.add("pairing", "fail", `values from Gray's pairing at ${pairing.pairedAt} (${pairing.gray}) for key ${pairing.fingerprint}, but ${config.daemon.keyPath} is key ${fingerprint}: pair this key (gray-assistant init --pair <code> --key <relay-key.json>) or restore the paired one`);
    } else if ((config.daemon.chain ?? null) === null) {
      // Phase 1 (no contract of its own): kits from 1.4.6 run nothing on the host, and Gray runs relays on phase 2, so
      // the VM cannot connect until the relay pairs again (rehearsal of 2026-11-13: a kit-1.1.1 relay read "pairing OK").
      doctor.add("pairing", "fail", `${PHASE1_TEXT} (paired at ${pairing.pairedAt}, key ${pairing.fingerprint})`);
    } else {
      doctor.add("pairing", "ok", `values from Gray's pairing at ${pairing.pairedAt} (${pairing.gray}), key ${pairing.fingerprint}`);
    }
  }

  // The source: software, one live credential, and the parked list.
  const { createSourceAdapter } = await import("./source/config.ts");
  const source = createSourceAdapter(config.source);
  try {
    const probe = await source.probe(AbortSignal.timeout(config.source.probeTimeoutMs));
    const unsupported = probe.software === "unknown" || probe.software === "new-api" || probe.software === "one-api";
    const label = `${probe.software}${probe.version === null ? "" : ` ${probe.version}`}`;
    doctor.add(
      "source_detected",
      unsupported ? "fail" : "ok",
      unsupported
        ? `detected ${label}; gray-assistant has no built-in source for it: add the standard's two account routes to it and use the http source`
        : `detected ${label}; unattended credential read: ${probe.credentialReadable ? "yes" : "no"}`,
    );
    if (unsupported) {
      doctor.add("source_credential", "skip", "no built-in source for this software; add the two account routes and use the http source");
    } else {
      let snapshot: Awaited<ReturnType<typeof source.list>> | null = null;
      try {
        snapshot = await source.list(AbortSignal.timeout(config.source.requestTimeoutMs));
      } catch (error) {
        const code = error instanceof RelayKitError ? error.code : "io";
        // The file source with no file yet (a kit just paired) or one that does not read: the import puts it in place.
        const importHint = config.source.kind === "file" && (code === "io" || code === "unsafe_key_file") ? `; ${ACCOUNTS_IMPORT_HINT}` : "";
        doctor.add("source_accounts", "fail", `the source answered the probe but its account list failed (${code})${importHint}`);
        doctor.add("source_credential", "skip", "the source list failed; no credential was read");
      }
      if (snapshot !== null) {
        let readable = 0;
        let parked = 0;
        const aliases = config.daemon.stack === null ? [] : readAccountAliasesFile(accountAliasesPath(config.daemon.stateFile));
        for (const account of snapshot.accounts) {
          const planned = planAccount(config.daemon.relayId, config.source.kind, account);
          // The relay-stack origin seals under the panel id (S59): the source's own id, or the plain alias the agent
          // gave an id that cannot be one; doctor names both here, on the relay's own machine only.
          if (config.daemon.stack !== null && !STACK_ID_PATTERN.test(account.sourceId)) {
            const alias = aliases === null ? undefined : aliases.find((a) => a.vendor === account.vendor && a.sourceId === account.sourceId);
            if (alias !== undefined) {
              doctor.add(`stack_account:${planned.accountId}`, "ok", `source account ${JSON.stringify(account.sourceId)} (${account.vendor}) is ${alias.panelId} in the panel`);
            } else if (aliases === null) {
              doctor.add(`stack_account:${planned.accountId}`, "fail", `source account ${JSON.stringify(account.sourceId)} (${account.vendor}) is not sealed to the relay-stack origin: ${accountAliasesPath(config.daemon.stateFile)} does not read, so the agent gives it no panel id; restore or remove the file (removing it gives the accounts new ids)`);
            } else {
              doctor.add(`stack_account:${planned.accountId}`, "skip", `source account ${JSON.stringify(account.sourceId)} (${account.vendor}) gets a plain panel id (${ACCOUNT_ALIAS_VENDOR_WORDS[account.vendor]}-<n>) when the agent next reads the source; gray-assistant accounts lists it then`);
            }
          }
          const metadataReason = metadataParkReason(account);
          if (metadataReason !== null) {
            parked += 1;
            doctor.add(`parked:${planned.accountId}`, "warn", `${planned.accountId} (${account.vendor}) parked: ${metadataReason}`);
            continue;
          }
          try {
            const read = await source.credential(account.sourceId, AbortSignal.timeout(config.source.requestTimeoutMs));
            const reason = credentialParkReason(account.vendor, read.credential);
            if (reason !== null) {
              parked += 1;
              const hint = reason === "invalid_credential_format" ? ` (${credentialFormatHint(account.vendor, read.credential.type)})` : "";
              doctor.add(`parked:${planned.accountId}`, "warn", `${planned.accountId} (${account.vendor}) parked: ${reason}${hint}`);
            } else {
              readable += 1;
            }
          } catch {
            parked += 1;
            doctor.add(`parked:${planned.accountId}`, "warn", `${planned.accountId} (${account.vendor}) parked: credential_unreadable`);
          }
        }
        doctor.add(
          "source_credential",
          readable > 0 ? "ok" : "fail",
          `${readable} account(s) with a live, readable credential, ${parked} parked of ${snapshot.accounts.length} selected`,
        );
        if (snapshot.accounts.length === 0) doctor.add("source_accounts", "fail", "the source selected no accounts");
      }
    }
  } catch (error) {
    const code = error instanceof RelayKitError ? error.code : "io";
    // A probe that throws is not a detection: say what failed and point at the two first-class
    // sources, rather than guessing which software answered (K4-4).
    doctor.add("source_detected", "fail", `the source could not be probed (${code}); for software without a built-in source, add the standard's two account routes and use the http source`);
    doctor.add("source_credential", "skip", "no source probe");
  }
  // The http source: the two routes against the standard's "Account source", as `gray-assistant source check` runs them.
  if (config.source.kind === "http") {
    const { checkSourceContract } = await import("./source/config.ts");
    try {
      const check = await checkSourceContract(config.source);
      const failed = check.lines.filter((line) => line.status === "fail");
      const warned = check.lines.filter((line) => line.status === "warn");
      if (failed.length > 0) {
        doctor.add("source_contract", "fail", `${failed.length} check(s) of the two account routes fail, first ${failed[0]?.id}: ${failed[0]?.message}; gray-assistant source check lists each`);
      } else if (warned.length > 0) {
        doctor.add("source_contract", "warn", `the two account routes answer the standard, with ${warned.length} warning(s), first ${warned[0]?.id}: ${warned[0]?.message}`);
      } else {
        doctor.add("source_contract", "ok", `the two account routes answer the standard (${check.lines.length} checks; gray-assistant source check lists them)`);
      }
    } catch (error) {
      doctor.add("source_contract", "fail", `the account routes could not be checked (${error instanceof RelayKitError ? error.code : "io"})`);
    }
  }

  // The signed release list, then every origin. A placeholder keyset skips both with one fixed
  // sentence; a failed verification of a real URL fails `release_list` and skips the origins.
  let release: VerifiedReleaseList | null = null;
  let releaseSkip = releasePlaceholderSkip;
  if (pinning !== null) {
    doctor.add("release_list", "skip", releasePlaceholderSkip);
  } else {
    try {
      release = await fetchReleaseList(createPlainDaemonFetch({ ...(options.ca === undefined ? {} : { ca: options.ca }) }), config.daemon.lane.releaseList, {
        publicKey: config.daemon.lane.releasePublicKey,
        maxAgeSeconds: config.daemon.lane.releaseListMaxAgeSeconds,
        nowMs,
        freshness: config.daemon.lane.releaseFreshness,
      });
      doctor.add("release_list", "ok", `signed release list verified (${release.list.composeHashes.length} release(s), issued ${new Date(Number(release.issuedAt) * 1000).toISOString()})`);
      // D137: what keeps it current and until when. Without the freshness key a list lapses a day after
      // it was issued; with it, a document that is not usable while the list's own window ends within
      // 12 h is a warning: it is what will keep the relay serving.
      const until = new Date(Number(release.currentUntil) * 1000).toISOString();
      const expires = release.expiresAt === null ? "no expires_at" : `expires ${new Date(Number(release.expiresAt) * 1000).toISOString()}`;
      const ownEndMs = (Number(release.issuedAt) + config.daemon.lane.releaseListMaxAgeSeconds + 1) * 1000;
      const freshness = config.daemon.lane.releaseFreshness;
      const status = freshness === null || release.freshness.state === "ok" || ownEndMs - nowMs > 12 * 3_600_000 ? "ok" : "warn";
      const detail = freshness === null
        ? "no lane.release_freshness_public_key: the list must be re-signed within a day"
        : `freshness document ${release.freshness.state}${release.freshness.message === null ? "" : ` (${release.freshness.message})`}`;
      doctor.add("release_freshness", status, `current until ${until} by ${release.currentBy}, ${expires}; ${detail}`);
    } catch (error) {
      const code = error instanceof ReleaseListError ? error.code : error instanceof RelayKitError ? error.code : "io";
      const staleness = error instanceof ReleaseListError && error.staleness !== null ? `, ${error.staleness}` : "";
      doctor.add("release_list", "fail", `the signed release list did not verify (${code}${staleness})`);
      releaseSkip = "skipped: the signed release list did not verify; not attested";
    }
  }
  checkPairingReleases(doctor, config, release, controlView);
  if (release !== null && (config.daemon.chain ?? null) !== null) await checkPendingReleases(doctor, options, release, nowMs);
  let quoteVerifier: QuoteVerifier | null = null;
  try {
    quoteVerifier = await loadQuoteVerifier({ ...(options.verifierModule === undefined ? {} : { verifierModule: options.verifierModule }), ...(options.pccs === undefined ? {} : { pccs: options.pccs }) });
  } catch {
    doctor.add("quote_verifier", "fail", "the quote verifier could not be loaded");
  }
  const origins = doctorOrigins(config, controlView);
  for (const origin of origins) {
    // Through Gray's entry: first that the entry answers and opens the tunnel, then the attestation inside it.
    const tunnel = tunnelOriginOf(origin);
    if (tunnel !== null && !(await checkPeerTunnel(doctor, origin, tunnel, options.ca))) {
      doctor.add(`origin:${origin}`, "skip", `${origin}: not attested: the tunnel did not open`);
      doctor.add(`vm_pin:${origin}`, "skip", "not checked: the tunnel did not open");
      continue;
    }
    if (release === null) {
      doctor.add(`origin:${origin}`, "skip", `${origin}: ${releaseSkip}`);
      if (tunnel !== null) doctor.add(`vm_pin:${origin}`, "skip", "not checked: the VM was not attested");
      continue;
    }
    if (key === null || quoteVerifier === null) {
      doctor.add(`origin:${origin}`, "skip", `${origin}: the relay key or quote verifier is unavailable; not attested`);
      if (tunnel !== null) doctor.add(`vm_pin:${origin}`, "skip", "not checked: the VM was not attested");
      continue;
    }
    const checked = await checkOrigin(doctor, config, release, quoteVerifier, controlView, origin, nowMs, options.ca, chainCheckOf(options, config));
    const pinned = checked.ok ? await checkClock(doctor, origin, checked.spkiSha256, { hostNow, gray: messages.gray, refusedBeyondS: (config.daemon.chain ?? null) !== null ? 300 : 60 }, options.ca) : null;
    if (tunnel === null) continue;
    if (!checked.ok) {
      doctor.add(`vm_pin:${origin}`, "fail", "the TLS key inside the tunnel is not bound by a valid attestation report of this relay's VM; gray-assistant sends it nothing");
    } else if (pinned !== null) {
      const why = pinned.code === "tls_spki_mismatch" ? "the VM's TLS key changed since its attestation (a reboot?); run doctor again" : pinned.message;
      doctor.add(`vm_pin:${origin}`, "fail", `a request pinned to the attested TLS key failed: ${why}`);
    } else {
      doctor.add(`vm_pin:${origin}`, "ok", `TLS inside the tunnel ends in your VM: its key ${(checked.spkiSha256 ?? "").slice(0, 16)}… is the one its attestation binds (no WebPKI step; the entry sees ciphertext only)`);
    }
  }

  // The scheduler's certificate and its signed echo through the TLS proxy.
  const publicUrl = config.daemon.scheduler.publicUrl;
  if (idle !== null) {
    // Phase 2: the VM picks the account itself, and nothing on this host serves or records what these lines read.
    for (const id of ["scheduler_tls", "scheduler_echo", ...origins.flatMap((origin) => [`scheduler_api:${origin}`, `lane_registration:${origin}`]), "agent_status"]) doctor.add(id, "skip", idle);
  } else if (publicUrl === null) {
    doctor.add("scheduler_tls", "fail", "scheduler.public_url is not configured");
  } else {
    try {
      const certificate = await readCertificate(publicUrl, options.ca);
      if (!Number.isFinite(certificate.validToMs)) throw new Error("certificate validity");
      const days = Math.floor((certificate.validToMs - nowMs) / DAY_MS);
      doctor.add(
        "scheduler_tls",
        days < 0 ? "fail" : days < CERTIFICATE_WARN_DAYS ? "warn" : "ok",
        `${publicUrl}: certificate for ${certificate.subject} ${days < 0 ? `expired ${-days}d ago` : `expires in ${days}d`}`,
      );
    } catch (error) {
      const code = error instanceof RelayKitError ? error.code : "io";
      doctor.add("scheduler_tls", "fail", `${publicUrl}: TLS could not be validated (${code})`);
    }
  }
  if (idle === null) {
    if (key !== null) {
      await checkSchedulerEcho(doctor, config, key, nowMs, options.ca);
    } else {
      doctor.add("scheduler_echo", "skip", "the relay key is unavailable; the echo was not signed");
    }
    checkSchedulerApi(doctor, config, origins, stackLaneOrigin(config, controlView));
    checkLaneRegistration(doctor, config, origins);
    checkAgentStatus(doctor, config, nowMs);
  }
  await checkStack(doctor, config, key, nowMs, options.ca, controlView, idle);
  if (idle === null) await checkTunnel(doctor, config, nowMs, options.ca);
  else if (config.daemon.tunnel !== null) doctor.add("tunnel", "skip", idle);
  if (messages.line !== null) doctor.add("messages", messages.line.status, messages.line.message);
  return { ok: !doctor.failed, lines: doctor.lines };
}

/**
 * Gray's unread messages for the relay (`./messages.ts`, kit 1.6.2), for the `messages` line: WARN with the count and
 * the newest one's title when something is unread, OK with none, and a SKIP that says why when they could not be read
 * (never a FAIL: the relay's VM serves without them). No line without a `stack` section. Also this host's clock against
 * the `Date` of Gray's answer, whatever the answer was.
 */
async function readMessages(options: DoctorOptions, config: LoadedRelayConfig, key: RelayKeyFile | null, nowMs: number, hostNow: () => number): Promise<{ readonly line: { readonly status: DoctorStatus; readonly message: string } | null; readonly gray: GrayClock | null }> {
  if (config.daemon.stack === null) return { line: null, gray: null };
  if (key === null) return { line: { status: "skip", message: "the relay key is unavailable, so Gray's messages for the relay were not read" }, gray: null };
  const { readKitMessages, unreadSummary } = await import("./messages.ts");
  const read = await (options.messages ?? ((clock) => readKitMessages({ config, seed: key.seed, nowMs }, clock)))(hostNow);
  const gray = read.grayDateMs === null || read.receivedMs === null ? null : { hostAheadMs: read.receivedMs - read.grayDateMs };
  if (!read.ok) return { line: { status: "skip", message: `Gray's messages for the relay could not be read (${read.reason}); \`gray-assistant messages\` reads them, and the relay's Messages page in Gray's console lists them` }, gray };
  if (read.answer.unread === 0) return { line: { status: "ok", message: "no unread message from Gray for the relay" }, gray };
  return { line: { status: "warn", message: `${unreadSummary(read.answer)}: run \`gray-assistant messages\`, tell the relay's operator what they say, then \`gray-assistant messages --seen\`` }, gray };
}

/** The SHA-256 of the SPKI the public name presents from here, through DNS and the rendezvous; rejects when TLS fails. */
function publicSpkiSha256(tunnel: TunnelConfig, ca: string | undefined): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({ host: tunnel.name, port: 443, servername: tunnel.name, ...(ca === undefined ? {} : { ca }), rejectUnauthorized: true, ALPNProtocols: ["http/1.1"] });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("timeout"));
    }, 15_000);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      const certificate = socket.getPeerX509Certificate();
      socket.destroy();
      if (certificate === undefined) return reject(new Error("no certificate"));
      resolve(createHash("sha256").update(certificate.publicKey.export({ type: "spki", format: "der" })).digest("hex"));
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

/**
 * The relay tunnel's lines (a `tunnel` section only): `tunnel` from the running agent's status, `tunnel_certificate`
 * from the terminator over 127.0.0.1 (doctor runs beside the agent, in its container), `tunnel_public` from the
 * public name as anyone reaches it, and `tunnel_ct` from the CT monitor. `tunnel_public` with another key than the
 * terminator's is a FAIL: from this host, something between the internet and the relay presents its own
 * certificate for the name.
 */
async function checkTunnel(doctor: Doctor, config: LoadedRelayConfig, nowMs: number, ca: string | undefined): Promise<void> {
  const tunnel = config.daemon.tunnel;
  if (tunnel === null) return;
  const snapshot = readDaemonStatusFile(config.daemon.statusFile);
  const status = snapshot === null ? undefined : get(snapshot, "tunnel");
  if (!isObject(status as never)) {
    doctor.add("tunnel", "skip", `${tunnel.name}: no status recorded yet (gray-assistant run keeps the tunnel to ${tunnel.server.host}:${tunnel.server.port} and records it in its status file)`);
  } else {
    const state = get(status as JsonObject, "state");
    const since = get(status as JsonObject, "since_ms");
    const sinceText = typeof since === "number" ? ` since ${new Date(since).toISOString()}` : "";
    if (state === "connected") doctor.add("tunnel", "ok", `${tunnel.name}: connected to ${tunnel.server.host}:${tunnel.server.port}${sinceText}; the relay needs no public address`);
    else doctor.add("tunnel", "fail", `${tunnel.name}: down${sinceText}; the rendezvous ${tunnel.server.host}:${tunnel.server.port} does not hold the name (see the tunnel_* and frpc: lines of the agent's log)`);
  }
  const served = await probeServedCertificate(tunnel).catch(() => null);
  if (served === null) {
    doctor.add("tunnel_certificate", "fail", `${tunnel.name}: the local terminator (127.0.0.1:${tunnel.tlsPort}) serves no certificate yet; it obtains one by TLS-ALPN-01 once the tunnel is connected (see the caddy: lines of the agent's log)`);
  } else {
    const days = Math.floor((served.notAfterMs - nowMs) / DAY_MS);
    doctor.add("tunnel_certificate", days < 14 ? "warn" : "ok", `${tunnel.name}: key ${served.spkiSha256.slice(0, 16)}…, ${served.issuer}, expires in ${days}d${days < 14 ? " (the terminator renews 30 days ahead; a renewal is failing)" : ""}`);
  }
  if (served !== null) {
    try {
      const presented = await publicSpkiSha256(tunnel, ca);
      if (presented === served.spkiSha256) doctor.add("tunnel_public", "ok", `https://${tunnel.name}: answers from here with this relay's own key`);
      else doctor.add("tunnel_public", "fail", `https://${tunnel.name}: answers from here with key ${presented.slice(0, 16)}…, not this relay's (${served.spkiSha256.slice(0, 16)}…): something between the internet and this relay holds another certificate for the name; do not use the page through the tunnel`);
    } catch (error) {
      doctor.add("tunnel_public", "fail", `https://${tunnel.name}: unreachable from here (${error instanceof Error && "code" in error ? String((error as { code: unknown }).code) : "io"})`);
    }
  } else {
    doctor.add("tunnel_public", "skip", "no local certificate to compare the public name's with yet");
  }
  const ct = isObject(status as never) ? get(status as JsonObject, "ct") : undefined;
  const pollMinutes = Math.round(tunnel.ct.pollMs / 60_000);
  // Until its first check ends the monitor reports `unknown` (ct.ts ctView: no source has answered yet), which is no
  // warning: the first check starts a minute after gray-assistant does, and a slow CT source can take a few minutes more.
  const firstCheck = `${tunnel.name}: the CT monitor has not finished its first check (it starts a minute after gray-assistant starts and can take a few minutes while a CT source is slow; then every ${pollMinutes} min)`;
  if (!isObject(ct as never)) {
    doctor.add("tunnel_ct", "skip", firstCheck);
    return;
  }
  const ctState = get(ct as JsonObject, "state");
  const checkedMs = get(ct as JsonObject, "checked_ms");
  const findings = get(ct as JsonObject, "findings");
  if (ctState === "alert" && Array.isArray(findings)) {
    const listed = findings
      .filter((f) => isObject(f))
      .map((f) => `${String(get(f as JsonObject, "issuer"))} key ${String(get(f as JsonObject, "pubkey_sha256")).slice(0, 16)}… (${String(get(f as JsonObject, "source"))} ${String(get(f as JsonObject, "id"))})`)
      .join("; ");
    doctor.add("tunnel_ct", "fail", `${tunnel.name}: CT lists a certificate whose key this relay never served: ${listed}; see docs on the tunnel's trust, then gray-assistant tunnel ack <cert_sha256>`);
  } else if (ctState === "ok") {
    doctor.add("tunnel_ct", "ok", `${tunnel.name}: every certificate CT lists for the name has this relay's key (${tunnel.ct.sources.join(", ")})`);
  } else if (typeof checkedMs !== "number") {
    doctor.add("tunnel_ct", "skip", firstCheck);
  } else {
    const nextPoll = new Date(checkedMs + tunnel.ct.pollMs).toISOString();
    doctor.add("tunnel_ct", "warn", `${tunnel.name}: no CT source answered in the last two polls (${tunnel.ct.sources.join(", ")}); the next poll is at ${nextPoll}; see the ct_checked lines of the agent's log`);
  }
}

/**
 * S45: what the running agent last reported to Gray's console (its status file's `agent_status`), which the panel's
 * credentials list reads. Only a relay stack reports one (`stack.report_origin`).
 */
function checkAgentStatus(doctor: Doctor, config: LoadedRelayConfig, nowMs: number): void {
  const stack = config.daemon.stack;
  if (stack === null) {
    doctor.add("agent_status", "skip", "not configured: only a relay stack (a stack section) reports the agent's status to Gray");
    return;
  }
  const snapshot = readDaemonStatusFile(config.daemon.statusFile);
  const value = snapshot === null ? undefined : get(snapshot, "agent_status");
  if (!isObject(value as never)) {
    doctor.add("agent_status", "skip", `no report recorded yet (gray-assistant run reports the agent's status to ${stack.reportOrigin} and records it in its status file)`);
    return;
  }
  const verdict = agentStatusVerdict(value as JsonObject, nowMs);
  doctor.add("agent_status", verdict.status, `${stack.reportOrigin}: ${verdict.message}`);
}

/** P12 rule 3: the deployments whose named instance gray-assistant adopts once its quote proves it. */
const LIVE_DEPLOYMENTS: readonly string[] = ["deploying", "running", "restarting"];

/** The lane instance Gray's last answer named, as the running agent recorded it (its status file); null for none. */
function namedStackInstance(config: LoadedRelayConfig): StackInstanceAnswer | null {
  const snapshot = readDaemonStatusFile(config.daemon.statusFile);
  const agent = snapshot === null ? undefined : get(snapshot, "agent_status");
  const value = isObject(agent as never) ? get(agent as never, "instance") : undefined;
  const parsed = stackInstanceAnswerSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/**
 * P12's `stack_instance`: the instance the relay-stack app is (the config's, or the one adopted from Gray and when), or
 * that gray-assistant waits for the VM's quote; a warning when Gray's last answer (`named`) names another app than the
 * adopted one (`lane_instance_changed`: it is adopted only once a boot of it proves it). An answer naming the entry's
 * tunnel to another relay's VM than `relayId`'s (docs/design/relay-outbound-only.md section 5) is never adopted
 * (`lane_instance_tunnel_other_relay`), so the line says that instead of a wait: a failure before any adoption, a warning
 * beside an adopted instance that still serves.
 */
export function stackInstanceLine(
  stack: StackConfig,
  adopted: DaemonStackInstance | null,
  named: StackInstanceAnswer | null,
  relayId: string,
): { readonly status: DoctorStatus; readonly message: string } {
  if (stack.instanceSource === "config") {
    return { status: "ok", message: `stack instance: ${stack.instance?.appId ?? "-"} at ${stack.laneOrigin ?? "-"} (from the config's lane.instances)` };
  }
  const live = named !== null && named.app_id !== null && named.lane_origin !== null && LIVE_DEPLOYMENTS.includes(named.deployment) ? named : null;
  const tunnel = live === null ? null : tunnelOriginOf(live.lane_origin as string);
  const otherRelay =
    live !== null && tunnel !== null && tunnel.relayId !== relayId
      ? `Gray names app ${live.app_id} at ${live.lane_origin}, the entry's tunnel to relay ${tunnel.relayId}'s VM, not this relay's (${relayId}): gray-assistant refuses it (lane_instance_tunnel_other_relay); ask Gray to correct the relay's lane instance`
      : null;
  if (adopted === null) {
    if (otherRelay !== null) return { status: "fail", message: `stack instance: none adopted; ${otherRelay}` };
    return live === null
      ? { status: "skip", message: "stack instance: waiting for the VM's quote (Gray names no running VM for this relay yet; Deploy it in the panel)" }
      : { status: "warn", message: `stack instance: waiting for the VM's quote (Gray names app ${live.app_id} at ${live.lane_origin}, ${live.deployment}; it is adopted when that VM asks for its pull token)` };
  }
  const text = `stack instance: ${adopted.appId} at ${adopted.laneOrigin} (from Gray, adopted ${new Date(adopted.adoptedMs).toISOString()})`;
  if (otherRelay !== null) return { status: "warn", message: `${text}; ${otherRelay}` };
  let liveOrigin: string | null = null;
  try {
    liveOrigin = live === null ? null : normalizeHttpsOrigin(live.lane_origin as string);
  } catch {
    liveOrigin = null;
  }
  if (live !== null && (live.app_id !== adopted.appId || live.kms_ca_pubkey !== adopted.kmsCaPubkey || liveOrigin !== adopted.laneOrigin)) {
    return { status: "warn", message: `${text}; Gray now names app ${live.app_id} at ${live.lane_origin} (lane_instance_changed): gray-assistant keeps sealing to the adopted one until a boot of the new one proves it` };
  }
  return { status: "ok", message: text };
}

function checkStackInstance(doctor: Doctor, config: LoadedRelayConfig, stack: StackConfig, controlView: ControlView, idle: string | null): void {
  // Phase 2 with no agent: a status file left from before the move names the old VM; `deliver` adopts the new one.
  const line = stackInstanceLine(stack, adoptedStack(config, controlView), idle === null ? namedStackInstance(config) : null, config.daemon.relayId);
  doctor.add("stack_instance", line.status, line.message);
}

/** Days of registry-token validity under which `stack_registry` warns. */
const REGISTRY_WARN_DAYS = 14;

/**
 * The `stack` section's checks that need no network, no running agent and no state volume, as `run`
 * applies them at start: the registry token file is private and holds one token the S9.7 envelope
 * fits (`stack_files`), and the token has not expired, with a warning inside 14 days
 * (`stack_registry`). The host install's `check-config.mjs` runs the same before it installs a kit.
 * The credential problem names members only, never the file's path or bytes.
 */
export function stackCredentialProblem(stack: StackConfig): string | null {
  let password: string;
  try {
    password = readPrivateFile(stack.registry.passwordFile, "registry password", 4096).trim();
  } catch (error) {
    return error instanceof RelayKitError && error.code === "unsafe_key_file"
      ? "stack.registry.password_file is not a private regular file (mode 0600, not a symbolic link)"
      : "stack.registry.password_file is unreadable or larger than 4096 bytes";
  }
  return pullTokenCredentialProblem(stack, password);
}

/** `stack_registry`: the registry token's expiry against `nowMs`. */
export function stackRegistryExpiry(stack: StackConfig, nowMs: number): { readonly status: "ok" | "warn" | "fail"; readonly message: string } {
  // v1.7: no `expires_at` is a token with no known expiry; nothing to warn about ahead, a refused pull says it ended.
  if (stack.registry.expiresAt === null || stack.registry.expiresAtMs === null) {
    return { status: "ok", message: `the registry token for ${stack.registry.host} has no expiry set (stack.registry.expires_at); a pull the registry refuses means it ended` };
  }
  if (stack.registry.expiresAtMs <= nowMs) {
    return { status: "fail", message: `the registry token for ${stack.registry.host} expired at ${stack.registry.expiresAt}; no pull token is issued` };
  }
  const days = Math.floor((stack.registry.expiresAtMs - nowMs) / DAY_MS);
  return { status: days < REGISTRY_WARN_DAYS ? "warn" : "ok", message: `the registry token for ${stack.registry.host} expires at ${stack.registry.expiresAt} (in ${days}d)` };
}

/**
 * The relay-stack pull-token service (S9–S13), when the config has a `stack` section: what the agent
 * reads at start, and the two public routes as a booting CVM and Gray's release tooling reach them.
 * The challenge creates one nonce the agent forgets in 60 s; no quote and no credential is involved.
 */
async function checkStack(doctor: Doctor, config: LoadedRelayConfig, key: RelayKeyFile | null, nowMs: number, ca: string | undefined, controlView: ControlView, idle: string | null): Promise<void> {
  const stack = config.daemon.stack;
  if (stack === null) return;
  const credential = stackCredentialProblem(stack);
  const logDirectory = dirname(stack.issueLog);
  if (credential !== null) {
    doctor.add("stack_files", "fail", `${stack.registry.passwordFile}: ${credential}`);
  } else {
    try {
      accessSync(logDirectory, constants.W_OK);
      doctor.add("stack_files", "ok", `${stack.registry.passwordFile} is private and holds one token; ${logDirectory} is writable for the issue log`);
    } catch {
      doctor.add("stack_files", "fail", `${logDirectory} is not a writable directory for the issue log`);
    }
  }
  const expiry = stackRegistryExpiry(stack, nowMs);
  doctor.add("stack_registry", expiry.status, expiry.message);
  checkStackInstance(doctor, config, stack, controlView, idle);
  // P12: the config's stack origin, or the adopted instance's; none before the first adoption.
  const stackOrigin = stack.laneOrigin ?? adoptedStack(config, controlView)?.laneOrigin ?? null;
  // S53: the image new boots get (control.json's after a rollout, else the config's) must be one the agent names.
  const replica = stackOrigin === null || idle !== null ? undefined : statusReplicas(config).get(stackOrigin);
  const current = controlView.control.stackCurrentImage ?? stack.currentImage;
  const running = replica === undefined ? undefined : get(replica, "relay_image");
  const runningText = typeof running === "string" ? `the attested VM runs ${running}` : idle !== null ? "deliver attests what the VM runs" : "no attested stack boot in the status file";
  if (stack.relayImages.includes(current)) {
    doctor.add("stack_image", "ok", `boots get ${current}; ${runningText}`);
  } else {
    doctor.add("stack_image", "fail", `the current image ${current} is not in stack.relay_images: the token service names it to no boot; add it, or roll out a listed one (gray-assistant stack rollout)`);
  }
  // What the running agent sealed to the stack app, by the ids the panel must list (its status file).
  const sealed = replica === undefined ? undefined : get(replica, "sealed_account_ids");
  const refused = replica === undefined ? undefined : get(replica, "refused_account_ids");
  const phase = replica === undefined ? undefined : get(replica, "phase");
  if (idle !== null) {
    doctor.add("stack_accounts", "skip", `${idle}; deliver and accounts push print what they seal`);
    doctor.add("stack_challenge", "skip", `${idle}; a phase-2 VM takes its registry login from the boot box, not a pull token`);
    doctor.add("stack_release_status", "skip", idle);
    return;
  } else if (stackOrigin === null) {
    doctor.add("stack_accounts", "skip", "no stack instance adopted yet, so nothing is sealed to the relay-stack app (the stack_instance line)");
  } else if (!Array.isArray(sealed)) {
    doctor.add("stack_accounts", "skip", `${stackOrigin}: no status recorded yet (gray-assistant run lists the account ids it sealed to the relay-stack origin)`);
  } else if (Array.isArray(refused) && refused.length > 0) {
    doctor.add("stack_accounts", "fail", `${stackOrigin}: ${refused.length} account(s) not sealed (lane ids ${refused.join(", ")}; the stack_account lines name them): ${STACK_ACCOUNT_ID_RULE}; sealed: ${sealed.length === 0 ? "none" : sealed.join(", ")}`);
  } else if (sealed.length === 0) {
    doctor.add("stack_accounts", "skip", `${stackOrigin}: no account sealed yet (phase ${String(phase)})`);
  } else {
    doctor.add("stack_accounts", "ok", `${stackOrigin}: sealed under ${sealed.join(", ")}; each must be an account id in the panel`);
  }
  try {
    const response = await httpsRequestOnce({
      url: `${stack.tokenUrl}${PULL_TOKEN_CHALLENGE_PATH}`,
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: new TextEncoder().encode("{}"),
      ...(ca === undefined ? {} : { ca }),
      timeoutMs: 15_000,
      maxResponseBytes: 64 * 1024,
    });
    let nonce: unknown = null;
    try {
      // The agent's own answer, read as verifyReleaseStatusText reads its other route's (parseStrict).
      nonce = get(parseStrictBytes(response.body), "nonce");
    } catch {
      nonce = null;
    }
    if (response.status === 200 && typeof nonce === "string" && /^[0-9a-f]{64}$/.test(nonce)) {
      doctor.add("stack_challenge", "ok", `${stack.tokenUrl}: the pull-token challenge answers through the public URL`);
    } else {
      doctor.add("stack_challenge", "fail", `${stack.tokenUrl}: the pull-token challenge answered ${response.status}; check the proxy forwards /v1/pull-token/* to the agent`);
    }
  } catch (error) {
    doctor.add("stack_challenge", "fail", `${stack.tokenUrl}: unreachable (${error instanceof RelayKitError ? error.code : "io"}); a CVM of this relay cannot boot`);
  }
  if (key === null) {
    doctor.add("stack_release_status", "skip", "the relay key is unavailable; the release status's signature was not checked");
    return;
  }
  try {
    const response = await httpsRequestOnce({
      url: `${stack.tokenUrl}${RELEASE_STATUS_PATH}`,
      method: "GET",
      headers: { accept: "application/json" },
      ...(ca === undefined ? {} : { ca }),
      timeoutMs: 15_000,
      maxResponseBytes: 4 * 1024 * 1024,
    });
    if (response.status !== 200) {
      doctor.add("stack_release_status", "fail", `${stack.tokenUrl}: the release status answered ${response.status}`);
      return;
    }
    const verified = await verifyReleaseStatusText(new TextDecoder().decode(response.body), {
      publicKey: bytesToHex(key.publicKey),
      relayId: config.daemon.relayId,
      nowMs,
      maxAgeMs: 60_000,
      maxFutureMs: 60_000,
    });
    if (!verified.ok) {
      doctor.add("stack_release_status", "fail", `${stack.tokenUrl}: the release status does not verify (${verified.code})`);
      return;
    }
    const count = (member: string) => (Array.isArray(verified.status[member]) ? (verified.status[member] as unknown[]).length : 0);
    doctor.add("stack_release_status", "ok", `${stack.tokenUrl}: the release status is signed by the relay key (${count("releases")} release(s), ${count("os_images")} OS image(s))`);
  } catch (error) {
    doctor.add("stack_release_status", "fail", `${stack.tokenUrl}: unreachable (${error instanceof RelayKitError ? error.code : "io"})`);
  }
}

/** The machine-readable view, printed as the last line by the CLI. */
export function doctorReportValue(report: DoctorReport): Record<string, unknown> {
  return {
    command: "doctor",
    ok: report.ok,
    checks: report.lines.map((line) => ({ id: line.id, status: line.status, message: line.message })),
  };
}

/** Exported for the guidance test: the stable ids the operator guide names. */
export const DOCTOR_LINE_IDS = [
  "config",
  "key_permissions",
  "accounts_permissions",
  "token_permissions",
  "policy_bundle",
  "state_permissions",
  "release_key",
  "source_detected",
  "source_credential",
  "source_contract",
  "release_list",
  "release_pairing",
  "scheduler_tls",
  "scheduler_echo",
  "stack_files",
  "stack_registry",
  "stack_instance",
  "stack_challenge",
  "stack_release_status",
  "stack_accounts",
  "agent_status",
  "tunnel",
  "tunnel_certificate",
  "tunnel_public",
  "tunnel_ct",
  "messages",
] as const;
