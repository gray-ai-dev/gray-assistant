/**
 * The daemon's public shapes: what a host injects, what it may read, and the closed reasons a
 * health check can name. Pure code; the Node state file and the HTTPS fetch are
 * `src/node/daemon/`, and the supervisor itself is `src/daemon/daemon.ts`.
 *
 * No type here carries a credential. `SourceAdapter` is the only source of secrets, and the daemon
 * releases one only into a sealed envelope it uploads in the same step (never into status, health,
 * the state file or a log event). The tests hold that invariant with a marker credential.
 */
import type { StackInstanceAnswer } from "@gray/control/stack-provision";
import type { JsonObject } from "@gray/json";
import type { LaneBinding } from "../lane-binding.ts";
import type { OsImageEntry, ReleaseEntry, ReleaseFreshnessState, ReleaseList, ReleaseListCurrentBy, ReleaseListStaleness, StackBootFacts } from "@gray/lane-verify";
import type { Credential, Vendor } from "@gray/relay-connector";
import type { CheckedVerifiedReport } from "../verified-report.ts";
import type { AccountAliasStore } from "./account-aliases.ts";
import type { SchedulerHandler } from "../scheduler/handler.ts";
import type { SourceAdapter } from "../source/types.ts";

/** The two clocks the supervisor reads: the wall clock writes document times, the monotonic clock schedules work. */
export interface DaemonClock {
  /** Unix milliseconds, the only clock a sealed document's `issued_at`/`expires_at` comes from. */
  wallMs(): number;
  /** A monotonic millisecond count for renewal and backoff; it may start anywhere and never goes back. */
  monoMs(): number;
}

/** One HTTP answer as the daemon needs it, with no `Response` dependency (pure, workerd and Node). */
export interface DaemonHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: Uint8Array;
  /** The TLS SPKI the client saw, when the host reports it (the Node adapter does). */
  readonly spkiSha256?: string | null;
}

/** One request the daemon makes; the host pins the peer to `expectedSpkiSha256` inside TLS validation. */
export interface DaemonHttpInit {
  readonly method: "GET" | "POST";
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: Uint8Array;
  readonly expectedSpkiSha256?: string;
  readonly timeoutMs?: number;
  /**
   * Through a tunnel origin, the keyset digest (64 lower-case hex) of the boot to reach (the entry's `?keyset=`): while
   * an image rollout runs two instances of the relay's app, each relay-stack replica reaches its own boot
   * (docs/design/relay-zero-downtime.md). Ignored for a direct origin.
   */
  readonly tunnelKeyset?: string;
}

/**
 * The one HTTP function a host injects. The Node adapter (`src/node/daemon/fetch.ts`) is the
 * SPKI-pinned `httpsRequestOnce`; a test supplies an in-process function. Every lane request passes
 * the verified report's `tls_spki_sha256`, so a WebPKI-valid substitute endpoint never sees a body.
 */
export type DaemonFetch = (url: string, init: DaemonHttpInit) => Promise<DaemonHttpResponse>;

/** What an attestation attempt is given: the origin, the release list to pin, and the verifier's clock. */
export interface DaemonAttestInput {
  readonly origin: string;
  readonly release: ReleaseList | null;
  readonly nowSecs: bigint;
  /**
   * The instance the origin must be (S12): the adopted stack instance with `stack.instance: "gray"` (P12), which the
   * config does not list. Absent: the config's `lane.instances` entry for the origin.
   */
  readonly instance?: LaneBinding;
  /** Through a tunnel origin, the boot to attest (its keyset digest, 64 hex); absent: the entry's newest boot. */
  readonly keyset?: string;
  /** P4b: a phase-2 boot in the empty slot passes (the relay's own `deliver` only; the daemon never sets it). */
  readonly allowEmptySlot?: boolean;
}

/** A verified replica, as the daemon needs it to seal and to identify the boot. */
export interface DaemonAttestation {
  readonly checked: CheckedVerifiedReport;
  readonly keysetDigest: string;
  readonly tlsSpkiSha256: string;
  readonly composeHash: string | null;
  readonly osImageHash: string | null;
  /**
   * S52/S54: what the boot measured after `system-ready` (`AttestationVerification.stackBoot`'s facts, the
   * relay's signature on its image already checked); null for none. Absent counts as null: the relay-stack
   * origin seals only to a boot whose facts name this relay and an image it issued.
   */
  readonly stackBoot?: StackBootFacts | null;
}

/** S54: one issue of the relay's own pull-token record, as credential intake looks it up by the boot's nonce. */
export interface StackIssueRecord {
  readonly composeHash: string;
  readonly relayImage: string;
}

/** Why an attestation did not produce a verified replica; never a secret. */
export type DaemonAttestResult =
  | ({ readonly ok: true } & DaemonAttestation)
  | { readonly ok: false; readonly stage: "report" | "verification" | "pinning" | "transport" | "clock"; readonly code: string };

/** The injected attestation: `attestLane` wrapped by the host, which owns the nonce and the quote verifier. */
export type DaemonAttest = (input: DaemonAttestInput) => Promise<DaemonAttestResult>;

/** A structured, content-free log event. A host maps it to its own logger. */
export interface DaemonLogEvent {
  readonly level: "info" | "warn" | "error";
  readonly event: string;
  readonly [detail: string]: string | number | boolean | null | undefined;
}

export type DaemonLog = (event: DaemonLogEvent) => void;

/**
 * The daemon's own durable state, exactly the two fields it owns: the version ledger and when the
 * relay first saw each release. No credentials, no account id, no source id.
 */
export interface DaemonState {
  readonly lastVersion: bigint;
  /** compose hash → the relay's own wall-clock milliseconds when it first saw the entry. */
  readonly releaseFirstSeen: Readonly<Record<string, number>>;
  /**
   * S11b: OS image hash → when the relay first saw it in a verified list. Absent only in a state file
   * written before S11b, which makes the daemon adopt the OS images of its first verified list.
   */
  readonly osImageFirstSeen?: Readonly<Record<string, number>>;
  /**
   * The lane origins the last started process was configured with, sorted. On start, an origin that
   * is here but no longer in the config gets a signed whole-relay revoke before it is dropped (R28).
   * Optional in the library type only so older callers can still write a state; the parser and the
   * writer always emit it.
   */
  readonly configuredOrigins?: readonly string[];
}

/** A state read: `intact` is false when the file was missing, unreadable or not this shape. */
export interface DaemonStateLoad {
  readonly state: DaemonState;
  readonly intact: boolean;
  /**
   * A `paused`/`accepted_releases` pair an older state file still carried (the one state file held
   * all four members before K5-3). The daemon adopts it once, at start, only when there is no
   * control file yet; a current state file has `null` here.
   */
  readonly legacyControl: DaemonControl | null;
}

/** The one durable piece the daemon writes: persisted before a message is sent, atomically. */
export interface DaemonStateStore {
  read(): Promise<DaemonStateLoad>;
  write(state: DaemonState): Promise<void>;
}

/**
 * The operator's control document (`control.json`): the pause flag and the manual acceptances.
 * Only the CLI writes it; the daemon reads it every tick.
 */
export interface DaemonControl {
  readonly paused: boolean;
  /** compose hashes an operator accepted explicitly (`releases accept`, any mode). */
  readonly acceptedReleases: readonly string[];
  /**
   * compose hash → the wall-clock millisecond of the acceptance. Optional: a control file written
   * before R27 carries acceptances with no stamp, and such an acceptance never shortens a new first
   * sight (it counts only while no sight exists to compare it with).
   */
  readonly acceptedAtMs?: Readonly<Record<string, number>>;
  /**
   * S11b: the operator's veto (`releases reject`), compose hashes and OS image hashes alike. A
   * rejected hash is never acceptable until `releases accept` or `releases unreject`. Optional: a
   * control file without a veto omits it.
   */
  readonly rejectedReleases?: readonly string[];
  /**
   * The hashes the agent accepted because `init --pair` recorded them (the config's `releases.accepted_at_pairing`),
   * each once: a pairing acceptance is never made a second time, so a release Gray withdraws and lists again waits
   * its delay like any other. Optional: absent until the first one.
   */
  readonly acceptedAtPairing?: readonly string[];
  /**
   * S53: the relay image the token service names from now on (`gray-assistant stack rollout|rollback`), overriding
   * the config's `stack.current_image`; optional, absent until the first rollout.
   */
  readonly stackCurrentImage?: string;
  /** S53: the image before the last rollout, which `stack rollback` rolls out again. */
  readonly stackPreviousImage?: string;
  /**
   * P12: the stack instance adopted from Gray's answer (`stack.instance: "gray"`) once a boot's quote proved it; the
   * agent writes it under the control lock (`persistStackInstance`), absent until the first adoption.
   */
  readonly stackInstance?: DaemonStackInstance;
}

/** P12: a lane instance Gray named: the stack app's id, its lane origin and its KMS CA key. */
export interface StackInstanceValues extends LaneBinding {
  readonly laneOrigin: string;
}

/** P12: the adopted stack instance as control.json keeps it (`stack_instance`). */
export interface DaemonStackInstance extends StackInstanceValues {
  readonly adoptedMs: number;
}

/** P12: what a token request's quote is checked against: a held binding, or Gray's candidate the quote would prove. */
export interface StackBindingChoice {
  readonly binding: LaneBinding;
  readonly candidate: boolean;
}

/**
 * P12: the relay-stack instance as `doctor`, the agent status and the token service see it: where it comes from, the
 * one held now (the config's, or the adopted one; null before the first adoption) and Gray's current candidate.
 */
export interface DaemonStackInstanceView {
  readonly source: "gray" | "config";
  readonly held: (StackInstanceValues & { readonly adoptedMs: number | null }) | null;
  readonly candidate: StackInstanceValues | null;
}

/** A control read: `intact` is false when the file is missing, unreadable or not this shape. */
export interface DaemonControlLoad {
  readonly control: DaemonControl;
  readonly intact: boolean;
}

/**
 * The daemon's read-only view of `control.json`. Deliberately no `write`: the agent can never
 * overwrite a control edit, and a concurrent daemon state write and CLI control write touch two
 * different files.
 */
export interface DaemonControlStore {
  read(): Promise<DaemonControlLoad>;
}

/**
 * The real-timer seam. The library never starts a timer; a host that wants the supervisor to run
 * passes a scheduler that calls `tick` every `intervalMs` and returns a cancel function. Tests omit
 * it and drive `tick()` by hand.
 */
export type DaemonSchedule = (tick: () => void, intervalMs: number) => () => void;

/** A transport-level refusal the host may throw; `code` is the relay-kit refusal where one exists. */
export class DaemonTransportError extends Error {
  override readonly name = "DaemonTransportError";
  readonly code: string;

  constructor(code: string) {
    super(`daemon transport: ${code}`);
    this.code = code;
  }
}

/** Everything `createRelayDaemon` needs. All I/O, time and randomness are injected. */
export interface RelayDaemonOptions {
  /** The raw config document (snake_case, as the operator wrote it); parsed by `parseRelayDaemonConfig`. */
  readonly config: unknown;
  readonly source: SourceAdapter;
  /** The 32-byte Ed25519 seed of the relay's registered key. */
  readonly signingKey: Uint8Array;
  /**
   * The signed policy bundle (the exact document `gray-assistant policy bundle` wrote). Null only for a
   * relay whose one lane origin is its relay-stack app, which runs no policy module (S23).
   */
  readonly policyBundle: JsonObject | null;
  readonly fetch: DaemonFetch;
  readonly attest: DaemonAttest;
  readonly clock: DaemonClock;
  readonly stateStore: DaemonStateStore;
  /** The CLI-owned `control.json`; read at start and at the beginning of every tick. */
  readonly controlStore: DaemonControlStore;
  readonly log: DaemonLog;
  /** Optional: a host that wants start() to run ticks on a real timer. */
  readonly schedule?: DaemonSchedule;
  /**
   * The operator's bearer token for `POST /v1/admin/reset`. When absent the route is not served at
   * all (404). The daemon never logs or returns it, and refuses a value outside the reference
   * scheduler's printable 16–512-byte shape.
   */
  readonly adminToken?: string;
  /**
   * S54: the relay's pull-token record, by a boot's challenge nonce (the Node agent reads its issue log). Without
   * it the relay-stack origin seals to no boot: intake requires the boot's image to be one this relay issued.
   */
  readonly stackIssue?: (nonce: string) => Promise<StackIssueRecord | null>;
  /**
   * P12: write control.json's `stack_instance` (null removes it), a locked read-merge-write that keeps every CLI edit
   * (the Node agent's `setStackInstanceState`). Without it an adoption lives in memory until control.json changes.
   */
  readonly persistStackInstance?: (instance: DaemonStackInstance | null) => Promise<void>;
  /**
   * Accept the config's pairing hashes in control.json, stamped `acceptedAtMs` and marked `accepted_at_pairing`: the
   * locked read-merge-write of `releases accept` (the Node agent's `acceptPairingReleasesState`), which skips a hash
   * the file already rejects or already took at pairing. Without it the acceptances live in memory until control.json
   * changes.
   */
  readonly persistPairingAcceptances?: (hashes: readonly string[], acceptedAtMs: number) => Promise<void>;
  /**
   * P12 rule 4: send the agent status now and resolve once Gray's answer was handed to `onStackInstance` (the Node
   * agent's reporter `send`). The daemon calls it at most once per `STACK_INSTANCE_ASK_MIN_MS`.
   */
  readonly requestStackInstance?: () => Promise<void>;
  /**
   * S59: where the panel ids given to source accounts whose own id is not one are kept (the Node agent's
   * `account-aliases.json`). Without it they are kept in memory only, for this process.
   */
  readonly aliasStore?: AccountAliasStore;
}

/** Why the daemon is not ready to serve, or a condition worth surfacing while it is. */
export type DaemonHealthReason =
  | "starting"
  | "paused"
  | "no_replica_serving"
  | "lease_low"
  | "lease_expired"
  | "relay_unknown"
  | "release_pending"
  | "release_unpinned"
  | "release_list_unavailable"
  | "source_unhealthy"
  | "credential_expired_unchanged"
  | "second_writer"
  | "version_probe_exhausted"
  | "origin_serves_two_boots"
  | "policy_missing"
  | "attestation_failed"
  | "clock_skew"
  | "stopped";

/** `health()`: ready only when a replica is serving an unexpired lease, plus every reason otherwise. */
export interface DaemonHealth {
  readonly ready: boolean;
  readonly reasons: readonly DaemonHealthReason[];
  /** The wall clock the answer was computed at. */
  readonly atMs: number;
}

/** One alert the daemon raised; detail is a fixed sentence or a public id, never a secret. */
export interface DaemonAlert {
  readonly atMs: number;
  readonly event: string;
  readonly detail: string;
}

/** One replica as `status()` reports it. Public identity only: origin, digests, versions, counts. */
export interface DaemonReplicaStatus {
  readonly origin: string;
  readonly phase: string;
  readonly keysetDigest: string | null;
  readonly policyVersion: string | null;
  readonly credentialVersion: string | null;
  readonly leaseExpiresAtMs: number | null;
  readonly leaseRemainingMs: number | null;
  readonly accounts: number;
  readonly reasons: readonly DaemonHealthReason[];
  readonly lastError: string | null;
  /**
   * When the supervisor next tries this replica's step after a failure (wall-clock milliseconds);
   * null when nothing is waiting. A standing `unknown_relay` is retried every `RELAY_UNKNOWN_RETRY_MS`.
   */
  readonly nextAttemptAtMs: number | null;
  /**
   * The relay-stack origin only (null elsewhere): the ids its lane holds credentials under, which are
   * the source's account_ids and must be the panel's account ids, so they can be compared with the
   * panel. Other origins hold derived ids (account-id.ts).
   */
  readonly sealedAccountIds: readonly string[] | null;
  /**
   * The relay-stack origin only: the lane ids of accounts not sealed to it because their source
   * account_id is not a panel account id (`STACK_ACCOUNT_ID_RULE`); null elsewhere.
   */
  readonly refusedAccountIds: readonly string[] | null;
  readonly digestChanges: number;
  /** D35: true while the current list announces a `retire_after` for this replica's OS image. */
  readonly retiring: boolean;
  /** D35: that date as wall-clock milliseconds; null when no retirement is announced. */
  readonly retireAfterMs: number | null;
  /**
   * The scheduler API version this replica's TEE sent on its last verified call (D116(b)); null
   * until one arrives after the replica's boot.
   */
  readonly schedulerApiVersion: number | null;
  /** When this process last installed a credential bundle on the replica (wall-clock ms); null before one. */
  readonly lastPushAtMs: number | null;
  /** S52/S54, the relay-stack origin only: the image its attested boot runs; null elsewhere and before. */
  readonly relayImage: string | null;
  /**
   * Every account the replica holds, by the source's own id, with the version of the message that sealed its current
   * credential (a full bundle or a one-account update) and when the lane accepted it (wall-clock ms). The local page
   * (`gray-assistant ui`) shows it beside each account; no credential, mark or lane id.
   */
  readonly sealedAccounts: readonly DaemonSealedAccount[];
}

/** One account a replica holds: the source's id, the version that sealed its credential, and when. */
export interface DaemonSealedAccount {
  readonly sourceId: string;
  readonly version: string;
  readonly atMs: number;
}

/** A parked account and the closed reason it is not in a bundle. Never a secret, never a value. */
export interface DaemonParkedAccount {
  readonly accountId: string;
  readonly vendor: Vendor;
  readonly reason: string;
  /** The source's own id of the account (on the relay-stack origin, the panel's account id); the daemon always sets it. */
  readonly sourceId?: string;
}

/** One account the source lists, as the source states it: never its credential, a hash of it, a path or a URL. */
export interface DaemonSourceAccount {
  /** The source's own id (on the relay-stack origin, the panel's account id). */
  readonly sourceId: string;
  readonly vendor: Vendor;
  readonly credentialType: Credential["type"];
  /**
   * The proxy the source declares for the account, without its user name and password (the console's panel proxy is
   * its type, host and port, all the lane compares with the sealed egress): null for none; absent when the source's
   * proxy is not one the connector would seal (the account is parked `invalid_egress_format`), so Gray changes nothing.
   */
  readonly proxy?: DaemonSourceProxy | null;
}

/** A source account's proxy as the agent status names it: never its user name or password. */
export interface DaemonSourceProxy {
  readonly type: "http" | "https" | "socks5" | "socks5h";
  readonly host: string;
  readonly port: number;
}

/** One release the list carries, as acceptance sees it. */
export interface DaemonReleaseStatus {
  readonly composeHash: string;
  readonly gitCommit: string | null;
  readonly firstSeenMs: number | null;
  readonly acceptableAtMs: number | null;
  readonly acceptable: boolean;
  readonly accepted: boolean;
  /** When the operator's counting acceptance was made, or null. */
  readonly acceptedAtMs: number | null;
  /** The counting acceptance is the one `init --pair` recorded (control.json's `accepted_at_pairing`). */
  readonly acceptedAtPairing: boolean;
  /** S11b: the operator rejected it (`releases reject`); it is not acceptable until accepted or unrejected. */
  readonly rejected: boolean;
}

/** S11b: one OS image the list carries, as acceptance sees it. */
export interface DaemonOsImageStatus {
  readonly osImageHash: string;
  readonly firstSeenMs: number | null;
  readonly acceptableAtMs: number | null;
  readonly acceptable: boolean;
  /** Why it is not acceptable now (`os_image_rejected`, `os_image_dev`, `os_image_unverified`, `os_image_not_accepted`), or null. */
  readonly refusal: string | null;
  readonly accepted: boolean;
  readonly acceptedAtMs: number | null;
  /** The counting acceptance is the one `init --pair` recorded. */
  readonly acceptedAtPairing: boolean;
  readonly rejected: boolean;
  /** `ok` when the entry's texts bind its hash, else `osImageProvenance`'s code. */
  readonly provenance: string;
  readonly isDev: boolean | null;
  readonly version: string | null;
}

/** `status()`: an operator view with no credential, no token and no source secret. */
export interface DaemonStatus {
  readonly relayId: string;
  readonly started: boolean;
  readonly paused: boolean;
  readonly lastVersion: string;
  readonly source: { readonly healthy: boolean; readonly lastPollAtMs: number | null; readonly accounts: number };
  /**
   * The last measured wall-clock skew against the TEE (relay clock minus the TEE's signed timestamp),
   * from a verified scheduler request; null until one arrives (K4-7).
   */
  readonly clockSkewMs: number | null;
  readonly clockSkewAtMs: number | null;
  readonly replicas: readonly DaemonReplicaStatus[];
  readonly parked: readonly DaemonParkedAccount[];
  /**
   * The accounts the source listed at its last poll, metadata only, sorted by source id (the agent status's
   * `sources`, S45); null while the source cannot be read (the last poll failed or was refused, or none yet), so
   * "unknown" is not "none".
   */
  readonly sources: readonly DaemonSourceAccount[] | null;
  readonly releases: readonly DaemonReleaseStatus[];
  /** S11b: the list's OS images and their acceptance. */
  readonly osImages: readonly DaemonOsImageStatus[];
  /** D137: the release list's currency and the last poll's refusal. */
  readonly releaseList: DaemonReleaseListStatus;
  readonly alerts: readonly DaemonAlert[];
  /** S53: the relay image the token service names now and the one before it; null without a `stack` section. */
  readonly stack: { readonly current: string; readonly previous: string | null } | null;
  /**
   * An image rollout's second relay-stack replica (docs/design/relay-zero-downtime.md): the new instance's boot before
   * it is adopted (`candidate`), or the replaced instance's boot while its VM drains (`draining`); null or absent
   * otherwise. Both are boots of the relay's one app.
   */
  readonly stackSecondary?: DaemonStackSecondaryStatus | null;
}

export interface DaemonStackSecondaryStatus {
  readonly role: "candidate" | "draining";
  readonly origin: string;
  readonly appId: string | null;
  readonly phase: string;
  readonly keysetDigest: string | null;
  readonly relayImage: string | null;
  readonly leaseExpiresAtMs: number | null;
  readonly lastError: string | null;
}

/**
 * D137: what keeps the release list an authority, and until when. The times are the last verified list's
 * (null before one); `currentUntilMs` is the first instant it no longer is. `lastError` and `staleness`
 * are the last poll's refusal (null after a good poll); a failed poll keeps the previous window.
 */
export interface DaemonReleaseListStatus {
  readonly url: string;
  readonly freshnessUrl: string | null;
  readonly issuedAtMs: number | null;
  readonly expiresAtMs: number | null;
  readonly currentUntilMs: number | null;
  readonly currentBy: ReleaseListCurrentBy | null;
  readonly freshness: ReleaseFreshnessState | null;
  readonly freshnessIssuedAtMs: number | null;
  readonly freshnessExpiresAtMs: number | null;
  readonly lastError: string | null;
  readonly staleness: ReleaseListStaleness | null;
}

/** The object `createRelayDaemon` returns. */
export interface RelayDaemon {
  readonly handler: SchedulerHandler;
  start(): Promise<void>;
  stop(): Promise<void>;
  tick(): Promise<void>;
  health(): DaemonHealth;
  status(): DaemonStatus;
  /**
   * In-process `pause`/`resume`: changes this process's view only. The durable edit is
   * `gray-assistant pause|resume`, which writes `control.json`; the next tick adopts it.
   */
  setPaused(paused: boolean): Promise<void>;
  /**
   * In-process `releases accept <id>`: records this process's acceptance only. The durable edit is
   * `gray-assistant releases accept`, which writes `control.json`.
   */
  acceptRelease(releaseId: string): Promise<boolean>;
  /** A host that reloads config calls this for an origin it removed: signed whole-relay revoke, keys out. */
  retireReplica(origin: string, reason?: string): Promise<void>;
  /**
   * S11: the release decision for one boot's measured compose hash and OS image: a fresh signed
   * list, the compose hash accepted under `releases.accept` and not rejected, the OS image listed
   * and accepted under S11b (production by its own texts, first-sight delay or an explicit accept,
   * not rejected), and D35's retirement lead. The pull-token service asks it; it changes nothing.
   */
  releaseForBoot(composeHash: string, osImageHash: string | null): StackReleaseDecision;
  /**
   * Relay standard v1.7 item 9: the stack releases of Gray's list the relay lets boot now, sorted; null before the
   * first list. The agent status reports them as `accepted_compose`; it changes nothing.
   */
  acceptedComposeHashes(): string[] | null;
  /**
   * Resolves once the first tick has read Gray's release list (taking `init --pair`'s acceptances) and the account
   * source, whatever either read found; never rejects. The agent status's first send waits for it (run.ts), so Gray's
   * first view of a relay that just started already names what it accepts and lists.
   */
  firstReads(): Promise<void>;
  /** S53: the image the token service names from now on and the one before it; null without a `stack` section. */
  stackImages(): { readonly current: string; readonly previous: string | null } | null;
  /** Re-reads control.json now, as every tick does first (the token service's `refreshImages`). */
  reloadControl(): Promise<void>;
  /** P12: the relay-stack instance (source, held, candidate); null without a `stack` section. */
  stackInstance(): DaemonStackInstanceView | null;
  /**
   * P12 rules 3 and 5: Gray's answer to the agent status names the relay's lane instance. With `stack.instance:
   * "gray"` a live deployment's three values become the candidate (another app than the adopted one is warned as
   * `lane_instance_changed`), and `deleted`, `none` or a null app id drop the adopted instance (`lane_instance_removed`).
   */
  onStackInstance(answer: StackInstanceAnswer): Promise<void>;
  /**
   * P12 rules 3 and 4: the binding a token request's quote (its app-id event and key-provider CA) is checked against:
   * Gray's candidate when the quote is its VM, else the held one, after asking Gray once (rate-bound) when it holds
   * and names no instance of that app id. Null: nothing to check against.
   */
  stackBindingFor(appId: string | null, kmsCaPubkey?: string | null): Promise<StackBindingChoice | null>;
  /** P12 rule 3: a token request's quote proved the candidate with this binding; adopt it (`lane_instance_adopted`). */
  adoptStackCandidate(binding: LaneBinding): Promise<void>;
  /**
   * S59: the id the panel knows a source account by: its alias, else its own id when that is a panel id no alias
   * holds, else null. Everything the agent sends Gray names accounts by it.
   */
  panelAccountId(vendor: Vendor, sourceId: string): string | null;
}

/** Why `releaseForBoot` refuses a boot, in the order it checks. */
export type StackReleaseRefusal =
  | "release_list_unavailable"
  | "compose_not_listed"
  | "release_not_stack"
  | "release_rejected"
  | "release_not_accepted"
  | "os_image_missing"
  | "os_image_not_listed"
  | "os_image_rejected"
  | "os_image_dev"
  | "os_image_unverified"
  | "os_image_not_accepted"
  | "os_image_retiring";

/** Credential intake's refusals: the boot's, and a stack release on an origin that is not the relay's stack app. */
export type ReleaseRefusal = StackReleaseRefusal | "release_stack_unexpected";

/** The release entry and OS image entry a boot was accepted under, or the first refusal. */
export type StackReleaseDecision =
  | { readonly ok: true; readonly entry: ReleaseEntry; readonly osImage: OsImageEntry }
  | { readonly ok: false; readonly code: StackReleaseRefusal };

/** One account as the sealed bundle and the scheduler's pool see it. */
export interface DaemonAccount {
  readonly accountId: string;
  readonly sourceId: string;
  readonly vendor: Vendor;
  readonly credentialType: Credential["type"];
  readonly models: readonly string[];
  readonly weight: bigint;
  readonly maxConcurrency: bigint;
}
