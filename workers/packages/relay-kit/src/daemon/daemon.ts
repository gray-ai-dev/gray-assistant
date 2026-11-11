/**
 * The relay daemon: one supervisor per configured lane origin, one version ledger, one release
 * registry, one scheduler handler and one status surface (design v2 §A.5–§A.7, §E K2).
 *
 * Lifecycle in one sentence: `start()` reads the state file and verifies the pre-signed policy
 * bundle, `tick()` does one deterministic round of work for every replica, and `stop()` only stops
 * the timer seam (it never revokes anything; `retireReplica` is the explicit revoke).
 *
 * A tick, in order:
 *
 * 1. fetch the release list when due (never a time from the document);
 * 2. poll the source when due (metadata only, never a secret);
 * 3. refresh the scheduler pool from the snapshot and the installed maps;
 * 4. run each replica's single-flight queue: attest → policy → full credential bundle → serving,
 *    or (while serving) healthz/keyset check, token pushes/revokes, then lease renewal.
 *
 * Every state-changing step that allocates a version persists it before the message is sent. The
 * queue serializes bundle/update/revoke for one replica, so a renewal can never interleave with a
 * token push or a revoke. The scheduler's key resolver is rebuilt from the replicas with a verified
 * report, so a reboot drops the old boot's keys before a new attestation exists.
 */
import { bytesToLowerHex, ed25519PublicKey } from "@gray/attest";
import { STACK_ID_PATTERN } from "@gray/control";
import type { StackInstanceAnswer } from "@gray/control/stack-provision";
import type { OsImageEntry, ReleaseEntry, StackBootFacts } from "@gray/lane-verify";
import { isObject, parseStrict, toJsonString, type Json, type JsonObject } from "@gray/json";
import {
  RelayConnectorError,
  SCHEDULER_MAX_SKEW_MS,
  egressSchema,
  hexBytes,
  type Credential,
  type CredentialBundle,
  type CredentialRevoke,
  type CredentialUpdate,
  type EgressSpec,
  type Vendor,
} from "@gray/relay-connector";
import { parsePolicyBundleValue, verifyPolicyBundleDocument } from "../policy-bundle.ts";
import { LANE_ENDPOINTS } from "../endpoints.ts";
import { RelayKitError } from "../errors.ts";
import { isLaneBinding, type LaneBinding } from "../lane-binding.ts";
import { createSchedulerHandler, type SchedulerCandidateKey, type SchedulerHandler } from "../scheduler/handler.ts";
import { sealCredentialBundleForReplicas, sealCredentialRevokeForReplicas, sealCredentialUpdateForReplicas } from "../seal.ts";
import { accountAliasKey, newAccountAliases, panelIdOf, type AccountAlias } from "./account-aliases.ts";
import { parseRelayDaemonConfig, policyOrigins, type RelayDaemonConfig } from "./config.ts";
import { daemonControlText, EMPTY_DAEMON_CONTROL, withPairingAcceptances, withStackInstance } from "./control.ts";
import { credentialParkReason, metadataParkReason, ParkRegistry, planAccount, type ParkReason, type PlannedAccount } from "./eligibility.ts";
import { ReplicaQueue } from "./queue.ts";
import { decideRefusal } from "./refusals.ts";
import { ReleaseListError, ReleaseRegistry, fetchReleaseList, releaseListHasOsMeasurements, type VerifiedReleaseList } from "./releases.ts";
import { DaemonSchedulerPool, type PoolAccount } from "./scheduler-pool.ts";
import { EMPTY_DAEMON_STATE } from "./state.ts";
import { DaemonTransportError, type DaemonStackInstance, type DaemonStackInstanceView, type StackBindingChoice, type StackInstanceValues, type DaemonAlert, type DaemonAttestResult, type DaemonControl, type DaemonControlLoad, type DaemonHealth, type DaemonHealthReason, type DaemonLogEvent, type DaemonReleaseListStatus, type DaemonReplicaStatus, type DaemonStackSecondaryStatus, type DaemonState, type DaemonStateLoad, type DaemonStatus, type RelayDaemon, type RelayDaemonOptions, type ReleaseRefusal, type StackReleaseDecision } from "./types.ts";
import { normalizeHttpsOrigin, type CheckedVerifiedReport } from "../verified-report.ts";
import { tunnelOriginOf } from "../lane-origin.ts";
import { attestationMismatch, stackBootDecision } from "./stack-boot.ts";
import { DaemonVersionError, VersionLedger } from "./versions.ts";
import type { SourceAccount, SourceCredential, SourceSnapshot } from "../source/types.ts";

/** The policy registry GET (the lane's M22 document); the one route that proves a policy is installed. */
export const POLICY_REGISTRY_PREFIX = "/v1/aci/relay-policy/";

/** How many phases one replica may advance in one tick (attest → release → policy → credentials). */
const MAX_PHASES_PER_TICK = 5;

/** Re-attest before the report's own age limit rather than exactly at it (review M4). */
const REPORT_REFRESH_FRACTION = 0.75;

/** The most alerts `status()` keeps; the log is the unbounded record. */
const MAX_ALERTS = 100;

/** The unknown-key signal is rate-limited: a hostile caller must not drive attestation. */
const UNKNOWN_KEY_COOLDOWN_MS = 5_000;

/** S11b's refusals, which the withdrawal log names instead of `release_withdrawn`. */
const S11B_REFUSALS: ReadonlySet<string> = new Set([
  "release_rejected",
  "os_image_rejected",
  "os_image_dev",
  "os_image_unverified",
  "os_image_not_accepted",
  // The separation of stack and default releases (a stack release on the wrong origin, or another relay's).
  "release_not_stack",
  "release_stack_unexpected",
]);

/**
 * How long a persisting `unknown_relay` waits between attempts: the lifetime of the signed snapshot the
 * lane's relay registry follows (`workers/console/src/provider/snapshots.ts` SNAPSHOT_TTL_SECONDS, 300 s).
 * A registration cannot reach the lane sooner, so a faster retry only repeats the refusal.
 */
export const RELAY_UNKNOWN_RETRY_MS = 300_000;

/**
 * P12 rule 4 (docs/relay-stack-provisioner.md §9): a token request whose quote names an app id the relay neither
 * holds nor has as Gray's candidate sends the agent status at once, at most this often.
 */
export const STACK_INSTANCE_ASK_MIN_MS = 10_000;

/**
 * How long a replaced relay-stack boot is kept after an image rollout's new instance took over
 * (docs/design/relay-zero-downtime.md): its lease is renewed and nothing is revoked while its VM finishes the requests it
 * holds and Gray removes it. Once its VM is gone the replica goes with nothing to revoke; still there after this long, it
 * gets the whole-relay revoke. Gray's drain ends within the longest request (well under it).
 */
export const STACK_DRAIN_MAX_MS = 30 * 60_000;
/**
 * How often the agent reads the entry's boots route of its relay while it serves one boot, for a second instance of its
 * app (an image rollout's new VM) to seal beside it (docs/design/relay-zero-downtime.md).
 */
export const STACK_BOOTS_POLL_MS = 10_000;
/** How long a boot a candidate was dropped for is not tried again (its VM may still be starting, or be gone). */
export const STACK_BOOT_SKIP_MS = 2 * 60_000;
/** The entry's public boots route of a relay (workers/gateway/src/lane/peer-link.ts). */
export const STACK_BOOTS_PATH = "/v1/peer/relays/";
/**
 * The longest wait between two attempts of a relay-stack replica the entry could not reach a VM for (`tunnel_refused`):
 * a VM that just started attaches within seconds (an image rollout's new one, a restarted one), and a minute's backoff
 * would hold its sealing that much longer.
 */
export const STACK_CANDIDATE_RETRY_MAX_MS = 5_000;

/** P12 rule 3: the deployments whose named instance is a candidate (a VM that boots, runs or restarts). */
const LIVE_DEPLOYMENTS: ReadonlySet<string> = new Set(["deploying", "running", "restarting"]);

/** Why an account is not sealed to the relay-stack origin; the log and doctor name this rule. */
export const STACK_ACCOUNT_ID_RULE = `on the relay-stack origin an account is sealed under its panel id: its source account_id when that matches ${STACK_ID_PATTERN.source} and no alias holds it, else the plain alias gray-assistant gives it (gray-assistant accounts lists both)`;

/** The verified bundle the policy step uploads and compares the lane's registry against. */
interface LoadedPolicy {
  readonly document: JsonObject;
  readonly version: bigint;
  readonly moduleSha256: string;
}

/** Two consecutive `unknown_relay` refusals make the condition actionable; one is transient. */
const RELAY_UNKNOWN_THRESHOLD = 2;

/** A replica's step in the supervisor; the agent status names it (S45, @gray/control/stack-agent's closed list). */
export const REPLICA_PHASES = ["unknown", "attesting", "release_pending", "policy", "credentials", "serving", "failed", "withdrawn"] as const;
type Phase = (typeof REPLICA_PHASES)[number];

interface InstalledAccount {
  /**
   * The id the lane holds it under (`#laneAccountId`): the derived id, or on the relay-stack origin the
   * source's account_id. Kept here because a revoke may follow the account's removal from the source.
   */
  readonly laneId: string;
  readonly vendor: Vendor;
  readonly changeMark: string;
  readonly expiresAtMs: number | null;
  /** Whether the accepted message carried an egress member (so a later absence sends `null`). */
  readonly hasEgress: boolean;
  /** The source's own id, the version of the message that sealed this credential, and when the lane took it. */
  readonly sourceId: string;
  readonly version: bigint;
  readonly sealedAtMs: number;
}

interface ReplicaRuntime {
  readonly origin: string;
  /** The instance the origin must be (S12): its `lane.instances` entry, or the adopted stack instance (P12). */
  readonly binding: LaneBinding | null;
  readonly queue: ReplicaQueue;
  phase: Phase;
  checked: CheckedVerifiedReport | null;
  keysetDigest: string | null;
  tlsSpkiSha256: string | null;
  composeHash: string | null;
  osImageHash: string | null;
  /** S52/S54: the image the relay-stack origin's attested boot runs (null elsewhere, and until attested). */
  relayImage: string | null;
  policyInstalled: boolean;
  policyVersion: bigint | null;
  credentialVersion: bigint | null;
  readonly installed: Map<string, InstalledAccount>;
  leaseExpiresAtSecs: bigint | null;
  leaseExpiresAtMs: number | null;
  lastUploadMono: number | null;
  /** When a bundle was last installed (wall clock); kept across re-attestations, as it says when the lane last got one. */
  lastPushAtMs: number | null;
  lastHealthzMono: number;
  observedDigests: string[];
  digestChanges: number;
  alternating: boolean;
  reattestRequested: boolean;
  reattestReason: string | null;
  /** The lane said it holds none of the last bundle (`#pollHealthz`): send a full one at the next step. */
  resealRequested: boolean;
  nextAttemptMono: number;
  failureStreak: number;
  unknownRelayStreak: number;
  lastError: string | null;
  terminal: boolean;
  retired: boolean;
  /** The scheduler API version this replica's TEE sent on its last verified call (D116(b)); null before one. */
  schedulerApiVersion: number | null;
  /**
   * The boot a relay-stack replica reaches through Gray's entry (its keyset digest, 64 hex; `?keyset=`): the one it
   * attested, or the one a rollout's candidate is made for; null: the entry's newest boot (docs/design/relay-zero-
   * downtime.md). Always null for a direct origin.
   */
  addressKeyset: string | null;
}

interface BundleAccount {
  readonly planned: PlannedAccount;
  readonly credential: Credential;
  readonly egress?: EgressSpec;
}

/** A bundle account as one replica's lane holds it. */
interface LaneBundleAccount extends BundleAccount {
  readonly laneId: string;
}

/**
 * The sealed egress member for one source account, or `"invalid"` when the source's fields fail the
 * connector's own E2 rules. The password is the one secret half of the proxy (K4-1); a username with
 * no declared password is sealed with an empty password, which is the one wire form E2 has for it.
 * Nothing here logs or returns a value in an error.
 */
export function egressOf(planned: PlannedAccount, read: SourceCredential): EgressSpec | undefined | "invalid" {
  const declared = planned.account.egress;
  if (declared === undefined) {
    // A password without a declared proxy has no wire form.
    return read.egressPassword === undefined ? undefined : "invalid";
  }
  if (declared.username === undefined && read.egressPassword !== undefined) return "invalid";
  const candidate = {
    type: declared.type,
    host: declared.host,
    port: declared.port,
    ...(declared.username === undefined ? {} : { username: declared.username, password: read.egressPassword ?? "" }),
  };
  const parsed = egressSchema.safeParse(candidate);
  return parsed.success ? parsed.data : "invalid";
}

/** The daemon implementation; `createRelayDaemon` is the one constructor. */
class RelayDaemonImpl implements RelayDaemon {
  readonly handler: SchedulerHandler;
  readonly #options: RelayDaemonOptions;
  readonly #config: RelayDaemonConfig;
  readonly #replicas = new Map<string, ReplicaRuntime>();
  readonly #parked = new ParkRegistry();
  readonly #pool: DaemonSchedulerPool;
  #ledger: VersionLedger;
  #releases: ReleaseRegistry;
  /** The signed policy bundle; null for a relay whose only origin is its relay-stack app (S23). */
  #policy: LoadedPolicy | null;
  #state: DaemonState;
  /** The CLI-owned control view; only `#reloadControl` replaces it from disk. */
  #control: DaemonControl;
  /** The canonical text last read from `control.json`, so an unchanged file is not re-applied. */
  #lastControlText: string | null;
  #planned = new Map<string, PlannedAccount>();
  /** Accounts refused on the relay-stack origin (`#laneAccountId`), by lane id, with the change mark last logged. */
  readonly #stackRefused = new Map<string, string>();
  #sourceHealthy = false;
  #sourceLastPollMono = Number.NEGATIVE_INFINITY;
  #sourceLastPollAtMs: number | null = null;
  #releaseLastPollMono = Number.NEGATIVE_INFINITY;
  /** Set when a new acceptance names a hash with no first sight: the next tick reads the list at once (`#reloadControl`). */
  #releasePollDue = false;
  #releaseListHealthy = false;
  /** The `issued_at` of the last verified list: D78 refuses an older one. */
  #releaseIssuedAtSecs: bigint | null = null;
  /**
   * R02, D137: the first second the last verified list is no longer an authority: its own window, or its
   * freshness document's, capped by its `expires_at`. Kept across a failed poll; for the same list bytes the
   * latest end any verified document gave is kept, so an older cached document never shortens it.
   */
  #releaseCurrentUntilSecs: bigint | null = null;
  /** The last verified list's view and the last poll's refusal, for `status` (D137). */
  #releaseView: VerifiedReleaseList | null = null;
  #releaseLastError: ReleaseListError | null = null;
  /** The origins this boot's config names, sorted; what `configured_origins` will persist. */
  #configuredOrigins: string[] = [];
  /** Origins an earlier start had configured that this config no longer names (R28). */
  #retirements = new Map<string, { firstMono: number; nextMono: number; attempts: number }>();
  /** Whether the loaded state file was intact, which decides whether adopting a list may write it. */
  #stateIntact = false;
  #started = false;
  #startPromise: Promise<void> | null = null;
  #stopped = false;
  #tickPromise: Promise<void> | null = null;
  // `firstReads`: settled once the first tick has polled the release list and the source.
  #firstReadsDone: () => void = () => undefined;
  readonly #firstReads: Promise<void> = new Promise((resolve) => {
    this.#firstReadsDone = resolve;
  });
  #cancelSchedule: (() => void) | null = null;
  #stateWriteTail: Promise<void> = Promise.resolve();
  #secondWriter = false;
  #versionProbeExhausted = false;
  #lastUnknownKeyMono = Number.NEGATIVE_INFINITY;
  readonly #alerts: DaemonAlert[] = [];
  readonly #alerted = new Set<string>();
  readonly #credentialExpiryAlerted = new Set<string>();
  #credentialExpiredUnchanged = false;
  #keysByKeyId = new Map<string, SchedulerCandidateKey[]>();
  /** The last signed-clock sample (K4-7), and when the last warning was logged. */
  #clockSkewMs: number | null = null;
  #clockSkewAtMs: number | null = null;
  #lastSkewLogMono = Number.NEGATIVE_INFINITY;
  /** The relay key's public half, lower hex (S54: what a stack boot's identity must name); set at start. */
  #relayPublicKeyHex: string | null = null;
  /**
   * The relay-stack origin's replica: the config's `stack.lane_origin`, or with `stack.instance: "gray"` the adopted
   * instance's (P12), null before the first adoption. Only it seals under the panel's ids and runs no policy.
   */
  #stackReplica: ReplicaRuntime | null = null;
  /**
   * The second relay-stack replica while an image rollout runs two instances of the relay's app
   * (docs/design/relay-zero-downtime.md), at the same tunnel origin and reaching its own boot (`?keyset=`):
   * `candidate`, the newer instance's boot the entry lists, attested and sealed before it takes over; `draining`, the
   * boot it replaced, kept (its lease renewed, nothing revoked) until its VM is gone or STACK_DRAIN_MAX_MS passed. Never
   * in `#replicas`, so the pool, the scheduler's keys and the agent status see only the stack replica.
   */
  #stackSecondary: { readonly replica: ReplicaRuntime; readonly role: "candidate" | "draining"; readonly sinceMono: number } | null = null;
  /** When the entry's boots route was last read (`#discoverStackBoot`). */
  #bootsReadMono = Number.NEGATIVE_INFINITY;
  /** Boots a candidate was dropped for (gone, never answered), not tried again before the time kept here. */
  readonly #bootsSkipped = new Map<string, number>();
  /** P12: Gray's last named live instance (rule 3's candidate); memory only, the next answer replaces it. */
  #stackCandidate: StackInstanceValues | null = null;
  /** The named instance last warned about, so a heartbeat answer does not repeat the warning. */
  #stackWarned: string | null = null;
  /** P12 rule 4: the last immediate status post, and the one in flight. */
  #stackAskMono = Number.NEGATIVE_INFINITY;
  #stackAsk: Promise<void> | null = null;
  /** Answers and adoptions change the adopted instance one at a time. */
  #stackInstanceTail: Promise<void> = Promise.resolve();
  /** S59: the panel ids given to source accounts whose own id is not one, by `accountAliasKey`, and the ids they hold. */
  readonly #aliases = new Map<string, AccountAlias>();
  readonly #aliasIds = new Set<string>();
  /** False when the aliases file is there but does not read: no alias is given then, so none is given twice. */
  #aliasesReadable = true;

  constructor(options: RelayDaemonOptions) {
    this.#options = options;
    this.#config = parseRelayDaemonConfig(options.config);
    if (!(options.signingKey instanceof Uint8Array) || options.signingKey.length !== 32) {
      throw new RelayKitError("invalid_key_file", "the signing key is not a 32-byte seed");
    }
    // R21: the reference scheduler's admin token shape (printable, 16–512 bytes) is refused here
    // too, so `run`'s one-line file read cannot turn a truncated file into a one-character bearer.
    if (options.adminToken !== undefined && !/^[\x21-\x7e]{16,512}$/.test(options.adminToken)) {
      throw new RelayKitError("usage", "invalid daemon config: scheduler.admin_token_file");
    }
    if (options.policyBundle === undefined || options.policyBundle === null) {
      // S23: a relay-stack lane runs no policy module, so a relay with no other origin needs no bundle.
      if (policyOrigins(this.#config).length > 0) throw new RelayKitError("invalid_policy_bundle", "a policy bundle is required for every lane origin but the relay-stack one");
      this.#policy = null;
    } else {
      const parsedPolicy = parsePolicyBundleValue(options.policyBundle);
      if (parsedPolicy.relayId !== this.#config.relayId) throw new RelayKitError("invalid_policy_bundle", "relay_id");
      this.#policy = { document: options.policyBundle, version: parsedPolicy.version, moduleSha256: requiredString(options.policyBundle, "module_sha256") };
    }
    this.#state = EMPTY_DAEMON_STATE;
    this.#control = EMPTY_DAEMON_CONTROL;
    this.#lastControlText = null;
    this.#ledger = new VersionLedger({
      initial: 0n,
      intact: false,
      now: () => options.clock.wallMs(),
      persist: async (last) => {
        this.#state = { ...this.#state, lastVersion: last };
        await this.#writeState();
      },
    });
    this.#releases = new ReleaseRegistry({
      mode: this.#config.releases.accept,
      delayDays: this.#config.releases.delayDays,
      wallMs: () => options.clock.wallMs(),
      firstSeen: {},
      osImageFirstSeen: {},
      accepted: [],
      persist: async (slice) => {
        // Only the daemon-owned first-seen maps reach the state file. The accepted and rejected
        // sets are the CLI's control document (`control.json`); accept() keeps them in memory until
        // the CLI writes it. D49: a failed write must leave the previous persisted state in place, so
        // the registry can restore its first-seen maps and count the poll as failed without this view
        // diverging.
        const previous = this.#state;
        this.#state = { ...this.#state, releaseFirstSeen: slice.firstSeen, osImageFirstSeen: slice.osImageFirstSeen };
        try {
          await this.#writeState();
        } catch (error) {
          this.#state = previous;
          throw error;
        }
        this.#control = { ...this.#control, acceptedReleases: slice.accepted, acceptedAtMs: slice.acceptedAtMs, rejectedReleases: slice.rejected };
      },
      log: options.log,
    });
    this.#pool = new DaemonSchedulerPool({
      now: () => options.clock.wallMs(),
      parked: this.#parked,
      inflightTtlMs: this.#config.inflightTtlMs,
      affinityTtlMs: this.#config.affinityTtlMs,
      ...(this.#config.affinityCap === null ? {} : { affinityCap: this.#config.affinityCap }),
      rateLimitedMs: this.#config.cooldowns.rateLimitedMs,
      overloadedMs: this.#config.cooldowns.overloadedMs,
    });
    this.handler = createSchedulerHandler({
      relayId: this.#config.relayId,
      keyFor: (keyId) => this.#keysByKeyId.get(keyId) ?? [],
      signingKey: options.signingKey,
      pool: this.#pool,
      now: () => options.clock.wallMs(),
      replayCap: this.#config.replayCap,
      paused: () => this.#control.paused,
      ...(options.adminToken === undefined ? {} : { adminToken: options.adminToken }),
      onUnknownKey: (event) => this.#onUnknownKey(event),
      onVerifiedRequest: (event) => this.#onVerifiedRequest(event),
      // D111(c): the scheduler's one line per pick and per report batch, through the daemon's own
      // logger. Both events are scheduling metadata: no body, model or credential.
      onPick: (event) =>
        this.#log({
          level: "info",
          event: "scheduler_pick",
          replica: event.replicaId,
          decision: event.decision,
          ...(event.accountId === undefined ? {} : { account_id: event.accountId }),
          duration_ms: event.durationMs,
          request_ref_digest: event.requestRefDigest,
        }),
      onReport: (event) =>
        this.#log({ level: "info", event: "scheduler_report", replica: event.replicaId, count: event.count, outcomes: event.outcomes }),
      // D116(b): a batch a verified TEE sent and this relay could not apply, with its status and kind;
      // the TEE logs the same refusal on its side.
      onReportRefused: (event) =>
        this.#log({ level: "warn", event: "scheduler_report_refused", replica: event.replicaId, status: event.status, kind: event.kind, code: event.code }),
    });
  }

  async start(): Promise<void> {
    if (this.#started) return;
    if (this.#startPromise !== null) return this.#startPromise;
    const run = this.#doStart();
    this.#startPromise = run;
    try {
      await run;
    } finally {
      this.#startPromise = null;
    }
  }

  async #doStart(): Promise<void> {
    const loaded: DaemonStateLoad = await this.#options.stateStore.read();
    this.#state = loaded.state;
    if (this.#options.aliasStore !== undefined) {
      const kept = await this.#options.aliasStore.read().catch(() => null);
      if (kept === null) {
        this.#aliasesReadable = false;
        this.#log({ level: "error", event: "account_aliases_unreadable", detail: "the account aliases file does not read; accounts without a panel id of their own are not sealed to the relay-stack origin until it is fixed" });
      } else {
        for (const alias of kept) this.#adoptAlias(alias);
      }
    }
    this.#stateIntact = loaded.intact;
    this.#configuredOrigins = [...this.#config.lane.origins].sort();
    // R28: an origin the previous start had configured and this config removed gets a signed
    // whole-relay revoke before it leaves the state. It is not put into the normal supervision
    // path: it must never receive policy or credentials again.
    const current = new Set(this.#configuredOrigins);
    const firstMono = this.#options.clock.monoMs();
    for (const origin of loaded.state.configuredOrigins ?? []) {
      if (current.has(origin)) continue;
      this.#retirements.set(origin, { firstMono, nextMono: firstMono, attempts: 0 });
    }
    // K5-3: `control.json` is the CLI's file. At start the daemon adopts it; only when there is no
    // control document does it fall back, once, to the legacy `paused`/accepted fields an older
    // state file still carries. Every later tick reads only control.json.
    this.#control = await this.#initialControl(loaded);
    // The ledger was constructed before the file was read (the constructor is synchronous), so its
    // first version starts from 0. The daemon's own state carries the real last_version; a fresh
    // ledger with the loaded values is the one that allocates.
    const ledger = new VersionLedger({
      initial: loaded.state.lastVersion,
      intact: loaded.intact,
      now: () => this.#options.clock.wallMs(),
      persist: async (last) => {
        this.#state = { ...this.#state, lastVersion: last };
        await this.#writeState();
      },
    });
    this.#ledger = ledger;
    this.#releases = new ReleaseRegistry({
        mode: this.#config.releases.accept,
        delayDays: this.#config.releases.delayDays,
        wallMs: () => this.#options.clock.wallMs(),
        firstSeen: loaded.state.releaseFirstSeen,
        // S11b: an intact state without the member was written before OS images had a first sight;
        // the registry adopts the first list's images instead of withdrawing a running lane. A
        // missing or lost state adopts nothing.
        osImageFirstSeen: loaded.intact ? loaded.state.osImageFirstSeen : {},
        accepted: this.#control.acceptedReleases,
        ...(this.#control.acceptedAtMs === undefined ? {} : { acceptedAtMs: this.#control.acceptedAtMs }),
        rejected: this.#control.rejectedReleases ?? [],
        acceptedAtPairing: this.#control.acceptedAtPairing ?? [],
        persist: async (slice) => {
          // Only the daemon-owned first-seen maps reach the state file. The accepted and rejected
          // sets stay in the CLI's control document; the in-process `acceptRelease` sees them until
          // restart. D49: restore this view when the state write fails; the registry restores its own
          // maps and the poll fails, so the next successful list is judged against the old sight.
          const previous = this.#state;
          this.#state = { ...this.#state, releaseFirstSeen: slice.firstSeen, osImageFirstSeen: slice.osImageFirstSeen };
          try {
            await this.#writeState();
          } catch (error) {
            this.#state = previous;
            throw error;
          }
          this.#control = { ...this.#control, acceptedReleases: slice.accepted, acceptedAtMs: slice.acceptedAtMs, rejectedReleases: slice.rejected };
        },
        log: this.#options.log,
      });
    if (!loaded.intact) this.#log({ level: "warn", event: "state_lost", detail: "the state file is missing or unreadable; version probing is armed" });
    // Verify the pre-signed policy bundle against the registered relay key before any upload. The
    // TEE will do the same; a local refusal is a configuration error, not a boot that keeps retrying.
    this.#relayPublicKeyHex = bytesToLowerHex(await ed25519PublicKey(this.#options.signingKey));
    if (this.#policy !== null) {
      const publicKey = await ed25519PublicKey(this.#options.signingKey);
      const document = parsePolicyBundleValue(this.#policy.document);
      const verified = await verifyPolicyBundleDocument(document, publicKey);
      if (!verified.ok) throw new RelayKitError("invalid_policy_bundle", verified.code);
    }
    for (const origin of this.#config.lane.origins) this.#replicas.set(origin, this.#newReplica(origin));
    const stackOrigin = this.#config.stack?.laneOrigin ?? null;
    if (stackOrigin !== null) this.#stackReplica = this.#replicas.get(stackOrigin) ?? null;
    // P12: the instance an earlier start adopted (control.json) is the stack replica from the first tick.
    await this.#syncStackReplica();
    this.#refreshPool();
    this.#refreshKeys();
    this.#started = true;
    // One retirement round at start (the finding's "at start"); a failed origin is retried from
    // ticks with backoff and dropped once `lease_lifetime` has passed.
    await this.#processRetirements();
    if (this.#options.schedule !== undefined) {
      this.#cancelSchedule = this.#options.schedule(() => {
        void this.tick().catch(() => undefined);
      }, this.#config.tickMs);
    }
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    this.#cancelSchedule?.();
    this.#cancelSchedule = null;
    if (this.#tickPromise !== null) await this.#tickPromise.catch(() => undefined);
    await Promise.all([...this.#replicas.values(), ...(this.#stackSecondary === null ? [] : [this.#stackSecondary.replica])].map((replica) => replica.queue.idle()));
  }

  async tick(): Promise<void> {
    if (!this.#started) await this.start();
    if (this.#stopped) return;
    if (this.#tickPromise !== null) return this.#tickPromise;
    const run = this.#runTick();
    this.#tickPromise = run;
    try {
      await run;
    } finally {
      this.#tickPromise = null;
    }
  }

  async setPaused(paused: boolean): Promise<void> {
    if (!this.#started) await this.start();
    // In-process only: the daemon never writes control.json (K5-3). The CLI's `pause`/`resume`
    // writes it and the next tick adopts the file; this call is for an embedding host and tests.
    this.#control = { ...this.#control, paused };
    this.#log({ level: "info", event: paused ? "paused" : "resumed", source: "process" });
  }

  async acceptRelease(releaseId: string): Promise<boolean> {
    if (!this.#started) await this.start();
    if (!this.#releaseListHealthy && this.#releases.list === null) await this.#pollReleases(true);
    const accepted = await this.#releases.accept(releaseId);
    if (accepted !== null) {
      // The registry's persist callback updated #control; keep it in step with the registry's
      // rolled-back view too (a failed state write leaves the acceptance unapplied).
      this.#control = { ...this.#control, acceptedReleases: this.#releases.slice().accepted };
      this.#alert("release_accepted", accepted);
    }
    return accepted !== null;
  }

  async retireReplica(origin: string, reason = "config_removed"): Promise<void> {
    if (!this.#started) await this.start();
    await this.#retire(origin, reason);
  }

  async #retire(origin: string, reason: string): Promise<void> {
    const replica = this.#replicas.get(origin);
    if (replica === undefined || replica.retired) return;
    await replica.queue.run(async () => {
      await this.#withdraw(replica, reason);
      replica.retired = true;
    });
    this.#replicas.delete(origin);
    this.#pool.removeReplica(origin);
    this.#refreshKeys();
  }

  health(): DaemonHealth {
    const atMs = this.#options.clock.wallMs();
    // R23: a stopped process is never ready, whatever its replicas last reported.
    if (this.#stopped) return { ready: false, reasons: ["stopped"], atMs };
    if (!this.#started) return { ready: false, reasons: ["starting"], atMs };
    const reasons = new Set<DaemonHealthReason>();
    if (this.#control.paused) reasons.add("paused");
    if (!this.#sourceHealthy) reasons.add("source_unhealthy");
    if (!this.#releaseListHealthy) reasons.add("release_list_unavailable");
    if (this.#secondWriter) reasons.add("second_writer");
    if (this.#versionProbeExhausted) reasons.add("version_probe_exhausted");
    if (this.#clockSkewMs !== null && Math.abs(this.#clockSkewMs) > SCHEDULER_MAX_SKEW_MS) reasons.add("clock_skew");
    if (this.#credentialExpiredUnchanged) reasons.add("credential_expired_unchanged");
    let serving = 0;
    for (const replica of this.#replicas.values()) {
      for (const reason of this.#replicaReasons(replica)) reasons.add(reason);
      if (!this.#isUsableServing(replica, atMs)) continue;
      serving += 1;
      const remaining = (replica.leaseExpiresAtMs ?? 0) - atMs;
      if (remaining < this.#config.leaseLifetimeSeconds * 1000 * 0.1) reasons.add("lease_low");
    }
    if (serving === 0) reasons.add("no_replica_serving");
    const ready = !this.#control.paused && serving > 0 && !this.#secondWriter && !this.#versionProbeExhausted;
    return { ready, reasons: [...reasons].sort() as DaemonHealthReason[], atMs };
  }

  status(): DaemonStatus {
    const atMs = this.#options.clock.wallMs();
    const mono = this.#options.clock.monoMs();
    const replicas: DaemonReplicaStatus[] = [];
    for (const replica of this.#replicas.values()) {
      const retireAfterMs = this.#retireAfterMs(replica);
      replicas.push({
        origin: replica.origin,
        phase: replica.phase,
        keysetDigest: replica.keysetDigest,
        policyVersion: replica.policyVersion === null ? null : replica.policyVersion.toString(),
        credentialVersion: replica.credentialVersion === null ? null : replica.credentialVersion.toString(),
        leaseExpiresAtMs: replica.leaseExpiresAtMs,
        leaseRemainingMs: replica.leaseExpiresAtMs === null ? null : replica.leaseExpiresAtMs - atMs,
        accounts: replica.installed.size,
        reasons: this.#replicaReasons(replica),
        lastError: replica.lastError,
        nextAttemptAtMs: replica.nextAttemptMono > mono ? atMs + (replica.nextAttemptMono - mono) : null,
        sealedAccountIds: this.#isStackOrigin(replica) ? [...replica.installed.values()].map((installed) => installed.laneId).sort() : null,
        refusedAccountIds: this.#isStackOrigin(replica)
          ? this.#plannedSorted()
              .filter((planned) => !this.#parked.has(planned.accountId) && this.#laneAccountId(replica, planned) === null)
              .map((planned) => planned.accountId)
          : null,
        digestChanges: replica.digestChanges,
        retiring: retireAfterMs !== null,
        retireAfterMs,
        schedulerApiVersion: replica.schedulerApiVersion,
        lastPushAtMs: replica.lastPushAtMs,
        relayImage: this.#isStackOrigin(replica) ? replica.relayImage : null,
        sealedAccounts: [...replica.installed.values()]
          .map((installed) => ({ sourceId: installed.sourceId, version: installed.version.toString(), atMs: installed.sealedAtMs }))
          .sort((a, b) => (a.sourceId < b.sourceId ? -1 : a.sourceId > b.sourceId ? 1 : 0)),
      });
    }
    return {
      relayId: this.#config.relayId,
      started: this.#started,
      paused: this.#control.paused,
      lastVersion: this.#ledger.lastIssued.toString(),
      source: { healthy: this.#sourceHealthy, lastPollAtMs: this.#sourceLastPollAtMs, accounts: this.#planned.size },
      clockSkewMs: this.#clockSkewMs,
      clockSkewAtMs: this.#clockSkewAtMs,
      replicas: replicas.sort((left, right) => left.origin.localeCompare(right.origin)),
      parked: this.#parked.list(),
      sources: this.#sourceHealthy
        ? [...this.#planned.values()]
            .map((planned) => ({ sourceId: planned.account.sourceId, vendor: planned.vendor, credentialType: planned.credentialType }))
            .sort((left, right) => (left.sourceId < right.sourceId ? -1 : left.sourceId > right.sourceId ? 1 : 0))
        : null,
      releases: this.#releases.status(atMs),
      osImages: this.#releases.osImageStatus(atMs),
      releaseList: this.#releaseListStatus(),
      alerts: [...this.#alerts],
      stack: this.stackImages(),
      stackSecondary: this.#stackSecondaryStatus(),
    };
  }

  #stackSecondaryStatus(): DaemonStackSecondaryStatus | null {
    const second = this.#stackSecondary;
    if (second === null) return null;
    const replica = second.replica;
    return {
      role: second.role,
      origin: replica.origin,
      appId: replica.binding?.appId ?? null,
      phase: replica.phase,
      keysetDigest: replica.keysetDigest,
      relayImage: replica.relayImage,
      leaseExpiresAtMs: replica.leaseExpiresAtMs,
      lastError: replica.lastError,
    };
  }

  /** D137: the list's currency as `status` shows it. */
  #releaseListStatus(): DaemonReleaseListStatus {
    const view = this.#releaseView;
    const ms = (secs: bigint | null): number | null => (secs === null ? null : Number(secs) * 1000);
    return {
      url: this.#config.lane.releaseList,
      freshnessUrl: this.#config.lane.releaseFreshness?.url ?? null,
      issuedAtMs: view === null ? null : ms(view.issuedAt),
      expiresAtMs: view === null ? null : ms(view.expiresAt),
      currentUntilMs: ms(this.#releaseCurrentUntilSecs),
      currentBy: view?.currentBy ?? null,
      freshness: view?.freshness.state ?? null,
      freshnessIssuedAtMs: view === null ? null : ms(view.freshness.issuedAt),
      freshnessExpiresAtMs: view === null ? null : ms(view.freshness.expiresAt),
      lastError: this.#releaseLastError?.code ?? null,
      staleness: this.#releaseLastError?.staleness ?? null,
    };
  }

  // --- tick ----------------------------------------------------------------

  async #runTick(): Promise<void> {
    await this.#reloadControl();
    await this.#syncStackReplica();
    await this.#syncStackSecondary();
    await this.#pollReleases(false);
    await this.#processRetirements();
    await this.#pollSource(false);
    this.#firstReadsDone();
    this.#refreshPool();
    // R16: one unreachable origin must not delay a healthy one's renewal. Each replica still runs
    // inside its own single-flight queue, so bundle/update/revoke for one origin stay serialized.
    const second = this.#stackSecondary;
    await Promise.all(
      [...this.#replicas.values(), ...(second === null ? [] : [second.replica])]
        .filter((replica) => !replica.retired)
        .map((replica) => replica.queue.run(async () => {
          await this.#supervise(replica);
          // A relay-stack VM that just started (an image rollout's new one, a restarted one) reaches the entry within
          // seconds: its replica is not left in a minute's backoff behind the entry's `peer_session_missing`
          // (docs/design/relay-zero-downtime.md).
          if (this.#isStackOrigin(replica) && replica.lastError !== null && replica.lastError.endsWith("tunnel_refused")) {
            const mono = this.#options.clock.monoMs();
            if (replica.nextAttemptMono - mono > STACK_CANDIDATE_RETRY_MAX_MS) replica.nextAttemptMono = mono + STACK_CANDIDATE_RETRY_MAX_MS;
            // The stack replica's boot is gone (a restart, or an instance Gray removed): its next attestation reaches
            // the entry's newest boot, as before keysets were named. A secondary's boot gone ends it (`#syncStackSecondary`).
            if (replica === this.#stackReplica && replica.addressKeyset !== null && this.#stackSecondary?.role !== "draining") {
              replica.addressKeyset = null;
              this.#triggerReattest(replica, "boot_gone", true);
            }
          }
        })),
    );
    this.#refreshKeys();
  }

  async #supervise(replica: ReplicaRuntime): Promise<void> {
    let phaseSteps = 0;
    for (let guard = 0; guard < MAX_PHASES_PER_TICK + 1; guard += 1) {
      if (replica.retired || replica.alternating || replica.terminal || this.#stopped) return;
      const mono = this.#options.clock.monoMs();
      const wall = this.#options.clock.wallMs();
      if (this.#secondWriter) return;
      // D77: D37's withdrawal is not a `serving`-only rule. A replica keeps its installed map,
      // lease and checked report across a re-attestation (`attesting`, and a pending boot in
      // `release_pending`), so a verified list that stops accepting its compose hash must withdraw
      // it there too: the TEE otherwise keeps the relay's vendor credentials until the lease lapses.
      // This runs before the retry backoff so a withdrawal is not delayed by a failed attestation;
      // `#refreshPool` already stopped advertising the replica earlier in this tick.
      if (replica.checked !== null && (replica.installed.size > 0 || replica.leaseExpiresAtMs !== null)) {
        const retiring = this.#retirementDue(replica);
        if (retiring || !this.#releaseAcceptable(replica)) {
          await this.#withdraw(replica, retiring ? "os_image_retiring" : this.#withdrawReason(replica));
          return;
        }
      }
      if (replica.nextAttemptMono > mono) return;
      switch (replica.phase) {
        case "unknown":
        case "attesting": {
          phaseSteps += 1;
          if (phaseSteps > MAX_PHASES_PER_TICK) return;
          if (!(await this.#doAttest(replica))) return;
          continue;
        }
        case "release_pending": {
          // R07: a pending replica still watches the boot, so a replacement boot on the same origin
          // is discovered without a restart. It stays out of policy until the release is accepted.
          await this.#pollHealthz(replica, mono);
          if (replica.phase !== "release_pending") return;
          // D35: a boot whose OS image is retiring is never sealed to. With a checked report the
          // withdrawal also sends the whole-relay revoke; without one there is nothing to revoke.
          if (this.#retirementDue(replica)) {
            if (replica.checked !== null) await this.#withdraw(replica, "os_image_retiring");
            return;
          }
          if (!this.#releaseAcceptable(replica)) return;
          replica.phase = "policy";
          continue;
        }
        case "policy": {
          phaseSteps += 1;
          if (phaseSteps > MAX_PHASES_PER_TICK) return;
          // D35: a retiring OS image is withdrawn before its `retire_after`, and never advances to
          // a credential upload. D37: losing the release is immediate from `policy` too. A retryable
          // refusal (for example `unknown_relay`) leaves an accepted bundle installed; it must not
          // keep being advertised while Gray has withdrawn the boot's compose hash.
          if (this.#retirementDue(replica)) {
            await this.#withdraw(replica, "os_image_retiring");
            return;
          }
          if (!this.#releaseAcceptable(replica)) {
            await this.#withdraw(replica, this.#withdrawReason(replica));
            return;
          }
          if (!(await this.#doPolicy(replica))) return;
          continue;
        }
        case "credentials": {
          phaseSteps += 1;
          if (phaseSteps > MAX_PHASES_PER_TICK) return;
          if (this.#retirementDue(replica)) {
            await this.#withdraw(replica, "os_image_retiring");
            return;
          }
          if (!this.#releaseAcceptable(replica)) {
            await this.#withdraw(replica, this.#withdrawReason(replica));
            return;
          }
          if (!(await this.#doCredentials(replica))) return;
          continue;
        }
        case "serving": {
          await this.#superviseServing(replica, wall, mono);
          return;
        }
        case "withdrawn": {
          // R07: a withdrawal is not permanent. If this same boot becomes acceptable again, re-run
          // policy and credentials; otherwise keep watching for a replacement boot on the origin.
          // D35: a still-announced retirement keeps it withdrawn; a list that drops `retire_after`
          // before the date cancels the retirement and allows the normal recovery path.
          if (!this.#retirementDue(replica) && this.#releaseAcceptable(replica)) {
            replica.phase = "attesting";
            continue;
          }
          await this.#pollHealthz(replica, mono);
          return;
        }
        case "failed":
          return;
      }
    }
  }

  async #superviseServing(replica: ReplicaRuntime, _wall: number, mono: number): Promise<void> {
    // D35: stop before the OS image's `retire_after`, and before any renewal that could seal a
    // bundle which would still be live at that date.
    if (this.#retirementDue(replica)) {
      await this.#withdraw(replica, "os_image_retiring");
      return;
    }
    if (!this.#releaseAcceptable(replica)) {
      await this.#withdraw(replica, this.#withdrawReason(replica));
      return;
    }
    await this.#pollHealthz(replica, mono);
    if (replica.phase !== "serving" || replica.checked === null) return;
    if (replica.reattestRequested) {
      replica.phase = "attesting";
      return;
    }
    if (this.#reportTooOld(replica)) {
      replica.reattestRequested = true;
      replica.reattestReason = "report_age";
      replica.phase = "attesting";
      return;
    }
    if (replica.nextAttemptMono > mono) return;
    if (replica.resealRequested) {
      // The lane lost the bundle (it clears a relay on a definite end, or after a long absence from
      // Gray's snapshot): a full one now, as a renewal sends it, rather than at the lease's half-life.
      // The registry is asked first, as R08 asks before a renewal: a cleared relay lost its policy too.
      replica.resealRequested = false;
      if (!(await this.#policyStillInstalled(replica))) return;
      await this.#doCredentials(replica);
      return;
    }
    if (!(await this.#pushAccountChanges(replica))) return;
    if (replica.phase !== "serving") return;
    if (this.#renewalDue(replica, mono)) {
      // R08: the gateway can drop and re-add a relay, clearing both stores. Ask the registry once
      // per renewal so the credential renewal never succeeds while the mandatory policy is absent.
      if (!(await this.#policyStillInstalled(replica))) return;
      await this.#doCredentials(replica);
    }
  }

  // --- attestation ---------------------------------------------------------

  async #doAttest(replica: ReplicaRuntime): Promise<boolean> {
    // R01: a library user can inject any `attest`. Without a signed list there is nothing to pin,
    // so the daemon refuses to attest (and later seal) rather than trusting an unpinned report.
    if (this.#releases.list === null) {
      this.#fail(replica, "release_pending");
      replica.lastError = "release_pending";
      return false;
    }
    const nowMs = this.#options.clock.wallMs();
    const nowSecs = BigInt(Math.floor(nowMs / 1000));
    let result: DaemonAttestResult;
    try {
      result = await this.#options.attest({
        origin: replica.origin,
        release: this.#releases.list,
        nowSecs,
        ...(replica.binding === null ? {} : { instance: replica.binding }),
        ...(replica.addressKeyset === null || tunnelOriginOf(replica.origin) === null ? {} : { keyset: replica.addressKeyset }),
      });
    } catch (error) {
      this.#fail(replica, `attest_transport_${this.#errorCode(error)}`);
      return false;
    }
    if (!result.ok) {
      this.#fail(replica, `attest_${result.stage}_${result.code}`);
      if (result.stage === "pinning") replica.lastError = "release_pending";
      return false;
    }
    // The report is the origin's, with the keyset and TLS key it signed. Through Gray's entry
    // (docs/design/relay-outbound-only.md §5) the origin names the entry, not the VM, and the VM's identity names no TLS
    // domain to compare it with: the rule is that the identity's relay is this relay (`./stack-boot.ts`).
    const mismatch = attestationMismatch(result, replica.origin, this.#config.relayId);
    if (mismatch !== null) {
      this.#fail(replica, mismatch);
      if (mismatch === "attest_relay_mismatch") this.#log({ level: "warn", event: "tunnel_relay_refused", origin: replica.origin, attested_relay: result.stackBoot?.identity.relayId ?? null });
      return false;
    }
    // S54: the relay-stack origin seals only to a boot pre-launch sealed with this relay's identity and an
    // image this relay listed and issued to that boot.
    let relayImage: string | null = null;
    if (this.#isStackOrigin(replica)) {
      const stackBoot = await this.#stackBootDecision(result.stackBoot ?? null, result.composeHash);
      if (!stackBoot.ok) {
        this.#fail(replica, `attest_${stackBoot.code}`);
        this.#log({ level: "warn", event: "stack_boot_refused", origin: replica.origin, code: stackBoot.code, compose_hash: result.composeHash });
        return false;
      }
      relayImage = stackBoot.image;
    }
    // R13: a re-attestation to a new boot must not keep the old boot's installed map, lease or pool
    // entry. Until the first new bundle they would name accounts this boot does not hold.
    if (replica.keysetDigest !== null && replica.keysetDigest !== result.keysetDigest) {
      replica.installed.clear();
      replica.credentialVersion = null;
      replica.leaseExpiresAtSecs = null;
      replica.leaseExpiresAtMs = null;
      replica.lastUploadMono = null;
      this.#pool.clearReplica(replica.origin);
    }
    replica.checked = result.checked;
    replica.keysetDigest = result.keysetDigest;
    replica.tlsSpkiSha256 = result.tlsSpkiSha256;
    replica.composeHash = result.composeHash;
    replica.osImageHash = result.osImageHash;
    replica.relayImage = relayImage;
    // docs/design/relay-zero-downtime.md: from now on this replica's calls reach this boot only.
    if (this.#isStackOrigin(replica) && tunnelOriginOf(replica.origin) !== null) replica.addressKeyset = bareKeyset(result.keysetDigest);
    replica.policyInstalled = false;
    replica.policyVersion = null;
    replica.reattestRequested = false;
    replica.reattestReason = null;
    if (!replica.observedDigests.includes(result.keysetDigest)) replica.observedDigests.push(result.keysetDigest);
    this.#clearFailure(replica);
    this.#refreshKeys();
    this.#log({ level: "info", event: "replica_attested", origin: replica.origin, keyset_digest: result.keysetDigest, compose_hash: result.composeHash });
    if (this.#releaseAcceptable(replica)) {
      replica.phase = "policy";
    } else {
      replica.phase = "release_pending";
      // S11b: an OS image refused by its own texts or by the operator is named, a dev image as such.
      const reason = this.#withdrawReason(replica);
      if (S11B_REFUSALS.has(reason)) this.#log({ level: "warn", event: "replica_release_refused", origin: replica.origin, code: reason, os_image_hash: replica.osImageHash });
    }
    return true;
  }

  /**
   * S54's credential intake on the relay-stack origin: the boot's facts are pre-launch's sealed ones, its identity
   * names this relay, its token service and its key, its image is one of `stack.relay_images`, and this relay's
   * own pull-token record issued that image to that boot (its nonce) for the same compose.
   */
  async #stackBootDecision(
    facts: StackBootFacts | null,
    composeHash: string | null,
  ): Promise<{ readonly ok: true; readonly image: string } | { readonly ok: false; readonly code: string }> {
    return stackBootDecision({
      facts,
      composeHash,
      relayId: this.#config.relayId,
      relayPublicKeyHex: this.#relayPublicKeyHex,
      stack: this.#config.stack,
      stackIssue: this.#options.stackIssue,
    });
  }

  /**
   * S53: the image the token service names from now on (control.json's, else the config's), and the one before
   * it; null without a `stack` section.
   */
  stackImages(): { readonly current: string; readonly previous: string | null } | null {
    const stack = this.#config.stack;
    if (stack === null) return null;
    return { current: this.#control.stackCurrentImage ?? stack.currentImage, previous: this.#control.stackPreviousImage ?? null };
  }

  async reloadControl(): Promise<void> {
    await this.#reloadControl();
  }

  // --- the relay-stack instance (P12) --------------------------------------

  stackInstance(): DaemonStackInstanceView | null {
    const stack = this.#config.stack;
    if (stack === null) return null;
    if (stack.instanceSource === "config") {
      const held = stack.laneOrigin === null || stack.instance === null ? null : { ...stack.instance, laneOrigin: stack.laneOrigin, adoptedMs: null };
      return { source: "config", held, candidate: null };
    }
    const adopted = this.#control.stackInstance ?? null;
    return { source: "gray", held: adopted === null ? null : { ...adopted }, candidate: this.#stackCandidate === null ? null : { ...this.#stackCandidate } };
  }

  async onStackInstance(answer: StackInstanceAnswer): Promise<void> {
    if (this.#config.stack?.instanceSource !== "gray") return;
    await this.#stackInstanceStep(async () => {
      const held = this.#control.stackInstance ?? null;
      // Rule 5: Gray has no VM for this relay (any more); stop sealing to the adopted one.
      if (answer.app_id === null || answer.deployment === "deleted" || answer.deployment === "none") {
        this.#stackCandidate = null;
        if (held !== null) await this.#writeStackInstance(null, answer.deployment);
        return;
      }
      const candidate = this.#candidateOf(answer);
      this.#stackCandidate = candidate;
      if (candidate !== null && held !== null && sameStackInstance(candidate, held)) this.#stackWarned = null;
      if (candidate === null || held === null || sameStackInstance(candidate, held)) return;
      // Rule 5: another app while the adopted one stands; it is adopted only once a boot of it proves it (rule 3).
      const key = `changed ${candidate.appId} ${candidate.laneOrigin} ${candidate.kmsCaPubkey}`;
      if (this.#stackWarned === key) return;
      this.#stackWarned = key;
      this.#log({ level: "warn", event: "lane_instance_changed", app_id: held.appId, lane_origin: held.laneOrigin, named_app_id: candidate.appId, named_lane_origin: candidate.laneOrigin, deployment: answer.deployment });
    });
  }

  async stackBindingFor(appId: string | null, kmsCaPubkey: string | null = null): Promise<StackBindingChoice | null> {
    const stack = this.#config.stack;
    if (stack === null) return null;
    if (stack.instanceSource === "config") return stack.instance === null ? null : { binding: stack.instance, candidate: false };
    const known = this.#stackChoice(appId, kmsCaPubkey);
    if (known !== null || appId === null) return known;
    // Rule 4: a fresh Deploy's first boot can come before the agent's next status; ask Gray now and decide on its answer.
    this.#log({ level: "info", event: "lane_instance_unknown", app_id: appId });
    await this.#askStackInstance();
    return this.#stackChoice(appId, kmsCaPubkey);
  }

  async adoptStackCandidate(binding: LaneBinding): Promise<void> {
    if (this.#config.stack?.instanceSource !== "gray") return;
    await this.#stackInstanceStep(async () => {
      const candidate = this.#stackCandidate;
      // Only the candidate the quote was checked against: a newer answer may have replaced it meanwhile.
      if (candidate === null || candidate.appId !== binding.appId || candidate.kmsCaPubkey !== binding.kmsCaPubkey) return;
      const held = this.#control.stackInstance ?? null;
      if (held !== null && sameStackInstance(candidate, held)) return;
      await this.#writeStackInstance({ ...candidate, adoptedMs: this.#options.clock.wallMs() }, null);
    });
  }

  /**
   * The binding a quote with this app id and KMS CA key is checked against: Gray's candidate when the quote is its VM
   * (and it is not the adopted one already), else the adopted instance for its own app id, else the candidate of that
   * app id (so a KMS mismatch is named), else null.
   */
  #stackChoice(appId: string | null, kmsCaPubkey: string | null): StackBindingChoice | null {
    if (appId === null) return null;
    const held = this.#control.stackInstance ?? null;
    const candidate = this.#stackCandidate;
    const fresh = candidate !== null && candidate.appId === appId && (held === null || !sameStackInstance(candidate, held)) ? candidate : null;
    if (fresh !== null && fresh.kmsCaPubkey === kmsCaPubkey) return { binding: bindingOf(fresh), candidate: true };
    if (held !== null && held.appId === appId) return { binding: bindingOf(held), candidate: false };
    return fresh === null ? null : { binding: bindingOf(fresh), candidate: true };
  }

  /** Rule 4's immediate status post: at most once per STACK_INSTANCE_ASK_MIN_MS; a request meanwhile waits for the one in flight. */
  async #askStackInstance(): Promise<void> {
    const ask = this.#options.requestStackInstance;
    if (ask === undefined) return;
    if (this.#stackAsk !== null) return this.#stackAsk;
    const mono = this.#options.clock.monoMs();
    if (mono - this.#stackAskMono < STACK_INSTANCE_ASK_MIN_MS) return;
    this.#stackAskMono = mono;
    const run = ask()
      .catch(() => undefined)
      .finally(() => {
        this.#stackAsk = null;
      });
    this.#stackAsk = run;
    return run;
  }

  /** Rule 3's candidate in an answer: three values in their forms and a live deployment, on no configured origin. */
  #candidateOf(answer: StackInstanceAnswer): StackInstanceValues | null {
    if (answer.app_id === null || answer.lane_origin === null || answer.kms_ca_pubkey === null || !LIVE_DEPLOYMENTS.has(answer.deployment)) return null;
    if (!isLaneBinding({ appId: answer.app_id, kmsCaPubkey: answer.kms_ca_pubkey })) return null;
    let laneOrigin: string;
    try {
      laneOrigin = normalizeHttpsOrigin(answer.lane_origin);
    } catch {
      return null;
    }
    // A relay-stack VM takes no inbound connection (docs/design/relay-outbound-only.md section 5): its lane origin is
    // the entry's tunnel route, and a plain https origin reaches no VM.
    const tunnel = tunnelOriginOf(laneOrigin);
    if (tunnel === null) {
      const key = `plain ${laneOrigin}`;
      if (this.#stackWarned !== key) this.#log({ level: "warn", event: "lane_instance_not_tunnel", lane_origin: laneOrigin, app_id: answer.app_id });
      this.#stackWarned = key;
      return null;
    }
    // A tunnel reaches the VM of the relay it names; Gray's answer for this relay never names another one's.
    if (tunnel.relayId !== this.#config.relayId) {
      const key = `tunnel ${laneOrigin}`;
      if (this.#stackWarned !== key) this.#log({ level: "warn", event: "lane_instance_tunnel_other_relay", lane_origin: laneOrigin, app_id: answer.app_id });
      this.#stackWarned = key;
      return null;
    }
    // A configured lane runs the relay's policy under its own binding; the stack app is never one of them.
    if (this.#config.lane.origins.includes(laneOrigin)) {
      const key = `configured ${laneOrigin}`;
      if (this.#stackWarned !== key) this.#log({ level: "warn", event: "lane_instance_origin_configured", lane_origin: laneOrigin, app_id: answer.app_id });
      this.#stackWarned = key;
      return null;
    }
    return { appId: answer.app_id, laneOrigin, kmsCaPubkey: answer.kms_ca_pubkey };
  }

  async #stackInstanceStep(step: () => Promise<void>): Promise<void> {
    const run = this.#stackInstanceTail.then(step);
    this.#stackInstanceTail = run.then(
      () => undefined,
      () => undefined,
    );
    await run;
  }

  /**
   * Adopt `next` (rule 3) or drop the adopted instance (null, rule 5): control.json first, then this view; the next
   * tick moves the stack replica (`#syncStackReplica`). An adoption that could not be written is not made (the next
   * proving boot tries again); a removal stops sealing even then.
   */
  async #writeStackInstance(next: DaemonStackInstance | null, deployment: string | null): Promise<void> {
    const previous = this.#control.stackInstance ?? null;
    try {
      await this.#options.persistStackInstance?.(next);
    } catch (error) {
      this.#log({ level: "warn", event: next === null ? "lane_instance_remove_unsaved" : "lane_instance_adopt_failed", code: this.#errorCode(error) });
      if (next !== null) return;
    }
    this.#control = withStackInstance(this.#control, next);
    this.#stackWarned = null;
    if (next !== null) {
      this.#log({ level: "info", event: "lane_instance_adopted", app_id: next.appId, lane_origin: next.laneOrigin, ...(previous === null ? {} : { replaced_app_id: previous.appId }) });
    } else if (previous !== null) {
      this.#log({ level: "warn", event: "lane_instance_removed", app_id: previous.appId, lane_origin: previous.laneOrigin, deployment });
    }
  }

  /**
   * P12: the stack replica follows the adopted instance (control.json's `stack_instance`): none before the first
   * adoption; a replaced or removed one gets the whole-relay revoke (its VM may be gone already) and leaves the pool.
   */
  async #syncStackReplica(): Promise<void> {
    if (this.#config.stack?.instanceSource !== "gray") return;
    // An instance adopted at a plain https origin before kit 1.1.0 reaches no VM any more: it is not followed, and
    // Gray's tunnel answer is adopted once its VM's quote proves it.
    const kept = this.#control.stackInstance ?? null;
    const wanted = kept !== null && tunnelOriginOf(kept.laneOrigin) === null ? null : kept;
    const current = this.#stackReplica;
    if (current !== null && wanted !== null && current.origin === wanted.laneOrigin && current.binding !== null && sameBinding(current.binding, wanted)) return;
    if (current === null && wanted === null) return;
    if (current !== null) {
      this.#stackReplica = null;
      await this.#retire(current.origin, wanted === null ? "lane_instance_removed" : "lane_instance_replaced");
    }
    // A configured lane is never the stack app (`#candidateOf`); a hand-edited control.json is not followed onto one.
    if (wanted === null || this.#replicas.has(wanted.laneOrigin)) return;
    const replica = this.#newReplica(wanted.laneOrigin, bindingOf(wanted));
    this.#replicas.set(wanted.laneOrigin, replica);
    this.#stackReplica = replica;
    this.#log({ level: "info", event: "stack_replica_added", origin: wanted.laneOrigin, app_id: wanted.appId });
  }

  /**
   * An image rollout's second replica (docs/design/relay-zero-downtime.md). Gray adds a second instance of the relay's
   * app; the entry's boots route lists its boot newer than the one the stack replica serves. A `candidate` replica for
   * that boot (same app, same binding, `?keyset=`) attests it as any boot and seals it; once it serves it becomes the
   * stack replica, and the one it replaced turns `draining`: renewed, never revoked, until its boot is gone (dropped,
   * nothing to revoke) or STACK_DRAIN_MAX_MS passed (the whole-relay revoke). If the new boot goes while the old one
   * still drains (a rollout Gray undid), the old one is the stack replica again at once. Nothing here changes
   * control.json: both boots are the adopted app's. With `stack.instance: "config"` the app is the config's (its
   * `stack.lane_origin` and that origin's `lane.instances` binding), and a rollout's second boot is found, attested
   * against that binding and sealed the same way (review 11-09: the console's rollout gate checks only the kit).
   */
  async #syncStackSecondary(): Promise<void> {
    const stack = this.#config.stack;
    if (stack === null) return;
    const held: StackInstanceValues | null =
      stack.instanceSource === "gray"
        ? (this.#control.stackInstance ?? null)
        : stack.laneOrigin === null || stack.instance === null
          ? null
          : { ...bindingOf(stack.instance), laneOrigin: stack.laneOrigin };
    const primary = this.#stackReplica;
    const mono = this.#options.clock.monoMs();
    let second = this.#stackSecondary;
    if (held === null || primary === null || primary.binding === null || !sameBinding(primary.binding, held) || tunnelOriginOf(primary.origin) === null) {
      // No adopted instance, or the stack replica is moving to another app: no second boot to keep.
      if (second !== null) await this.#dropStackSecondary("lane_instance_removed", true);
      return;
    }
    const gone = (replica: ReplicaRuntime): boolean => (replica.lastError !== null && replica.lastError.endsWith("tunnel_refused")) || replica.failureStreak >= 3;
    if (second !== null && second.replica.binding !== null && !sameBinding(second.replica.binding, held)) {
      await this.#dropStackSecondary("lane_instance_replaced", true);
      second = null;
    }
    if (second !== null && second.role === "draining") {
      // The new boot is gone while the old one drains (a rollout undone after the handover): the old one serves again.
      if (gone(primary) && this.#isUsableServing(second.replica, this.#options.clock.wallMs())) {
        this.#swapStackReplicas(second.replica, primary, "stack_replica_restored");
        await this.#dropStackSecondary("lane_instance_gone", false);
        return;
      }
      if (gone(second.replica)) await this.#dropStackSecondary("lane_instance_gone", false);
      else if (mono - second.sinceMono >= STACK_DRAIN_MAX_MS) await this.#dropStackSecondary("lane_instance_drained", true);
      return;
    }
    if (second !== null && second.role === "candidate") {
      if (second.replica.addressKeyset !== null && second.replica.addressKeyset === primary.addressKeyset) {
        // The stack replica attested that very boot meanwhile (its own boot went): it holds it.
        await this.#dropStackSecondary("lane_candidate_merged", false);
        return;
      }
      if (gone(second.replica) && second.replica.failureStreak >= 3) {
        if (second.replica.addressKeyset !== null) this.#bootsSkipped.set(second.replica.addressKeyset, mono + STACK_BOOT_SKIP_MS);
        await this.#dropStackSecondary("lane_candidate_gone", second.replica.checked !== null);
        return;
      }
      if (this.#isUsableServing(second.replica, this.#options.clock.wallMs())) this.#swapStackReplicas(second.replica, primary, "stack_replica_handover");
      return;
    }
    if (second === null && this.#isUsableServing(primary, this.#options.clock.wallMs()) && primary.addressKeyset !== null) await this.#discoverStackBoot(primary, held);
  }

  /**
   * At most every STACK_BOOTS_POLL_MS, the entry's boots route of the relay: a boot listed newer than the one the stack
   * replica serves (another instance of the app: Gray's rollout) gets a candidate replica. The route is public and its
   * answer is only a hint: the candidate's own attestation decides whether its boot is the relay's.
   */
  async #discoverStackBoot(primary: ReplicaRuntime, held: StackInstanceValues): Promise<void> {
    const mono = this.#options.clock.monoMs();
    if (mono - this.#bootsReadMono < STACK_BOOTS_POLL_MS) return;
    this.#bootsReadMono = mono;
    const tunnel = tunnelOriginOf(primary.origin);
    if (tunnel === null) return;
    let rows: { readonly keyset: string; readonly appId: string | null }[];
    try {
      const response = await this.#request(`${tunnel.entry}${STACK_BOOTS_PATH}${encodeURIComponent(tunnel.relayId)}/boots`, {
        method: "GET",
        headers: { accept: "application/json", "user-agent": "gray-relay-daemon/0" },
        timeoutMs: 10_000,
      });
      if (response.status !== 200) return;
      rows = bootRowsOf(parseStrict(new TextDecoder().decode(response.body)), tunnel.relayId);
    } catch {
      return;
    }
    // Newest first: every boot listed before the one the stack replica serves is newer than it.
    const at = rows.findIndex((row) => row.keyset === primary.addressKeyset);
    if (at <= 0) return;
    for (const [keyset, until] of this.#bootsSkipped) if (until <= mono) this.#bootsSkipped.delete(keyset);
    const newer = rows.slice(0, at).find((row) => (row.appId === null || row.appId === held.appId) && !this.#bootsSkipped.has(row.keyset));
    if (newer === undefined) return;
    const replica = this.#newReplica(primary.origin, bindingOf(held));
    replica.addressKeyset = newer.keyset;
    this.#stackSecondary = { replica, role: "candidate", sinceMono: mono };
    this.#log({ level: "info", event: "stack_candidate_added", origin: primary.origin, app_id: held.appId, keyset_digest: `sha256:${newer.keyset}`, serving_keyset_digest: `sha256:${primary.addressKeyset}` });
  }

  /** The secondary takes the stack origin; `previous` turns draining. */
  #swapStackReplicas(next: ReplicaRuntime, previous: ReplicaRuntime, event: string): void {
    this.#replicas.set(next.origin, next);
    this.#stackReplica = next;
    this.#stackSecondary = { replica: previous, role: "draining", sinceMono: this.#options.clock.monoMs() };
    this.#pool.clearReplica(next.origin);
    this.#refreshKeys();
    this.#log({ level: "info", event, origin: next.origin, keyset_digest: next.keysetDigest, draining_keyset_digest: previous.keysetDigest });
  }

  /** The secondary goes: with the whole-relay revoke to its own VM (`revoke`), or without (its VM is gone). */
  async #dropStackSecondary(reason: string, revoke: boolean): Promise<void> {
    const second = this.#stackSecondary;
    if (second === null) return;
    this.#stackSecondary = null;
    const replica = second.replica;
    await replica.queue.run(async () => {
      if (revoke && replica.checked !== null) await this.#withdraw(replica, reason);
      else {
        replica.phase = "withdrawn";
        replica.installed.clear();
        replica.leaseExpiresAtSecs = null;
        replica.leaseExpiresAtMs = null;
      }
      replica.retired = true;
    });
    this.#refreshKeys();
    this.#log({ level: "info", event: "stack_replica_dropped", origin: replica.origin, keyset_digest: replica.keysetDigest, role: second.role, reason, revoked: revoke && replica.checked !== null });
  }

  // --- policy --------------------------------------------------------------

  /**
   * Whether this origin installs the relay's policy before credentials. The relay-stack origin does
   * not (S23): the lane runs no policy module for a stack relay and answers its policy upload
   * `unknown_relay` for good, so its readiness is attestation and credentials alone.
   */
  #runsPolicy(replica: ReplicaRuntime): boolean {
    return !this.#isStackOrigin(replica);
  }

  #isStackOrigin(replica: ReplicaRuntime): boolean {
    return replica === this.#stackReplica || replica === this.#stackSecondary?.replica;
  }

  /**
   * The id `planned` is sealed under on `replica`'s lane. Every origin but the relay-stack one gets the
   * derived id (account-id.ts), so that lane never learns the source's handle. The stack origin gets the
   * source's account_id unchanged: the entry joins the panel's accounts to sealed credentials by id
   * (gateway stack-document.ts), and the operator gives Gray that same id in the panel, so a hash would
   * hide nothing. Null when the id is not one the panel takes (`STACK_ID_PATTERN`): that account is not
   * sealed to the stack origin, and is named in its status and in doctor.
   */
  #laneAccountId(replica: ReplicaRuntime, planned: PlannedAccount): string | null {
    if (!this.#isStackOrigin(replica)) return planned.accountId;
    return this.panelAccountId(planned.vendor, planned.account.sourceId);
  }

  panelAccountId(vendor: Vendor, sourceId: string): string | null {
    return panelIdOf(this.#aliases, this.#aliasIds, vendor, sourceId);
  }

  #adoptAlias(alias: AccountAlias): void {
    this.#aliases.set(accountAliasKey(alias.vendor, alias.sourceId), alias);
    this.#aliasIds.add(alias.panelId);
  }

  /**
   * S59: give each source account whose own id is not a panel id its alias, at first sight. The new ones are kept
   * (the store's atomic write) before any is used, so an id that reached Gray is never given again; a failed write
   * uses none and tries again at the next poll. Only a relay with a `stack` section names accounts to the panel.
   */
  async #assignAliases(): Promise<void> {
    if (this.#config.stack === null || !this.#aliasesReadable) return;
    const planned = [...this.#planned.values()];
    const added = newAccountAliases([...this.#aliases.values()], planned.map((p) => ({ vendor: p.vendor, sourceId: p.account.sourceId })), this.#options.clock.wallMs());
    if (added.length === 0) return;
    try {
      await this.#options.aliasStore?.write([...this.#aliases.values(), ...added]);
    } catch (error) {
      this.#log({ level: "warn", event: "account_aliases_write_failed", code: this.#errorCode(error), accounts: added.length });
      return;
    }
    for (const alias of added) {
      this.#adoptAlias(alias);
      // The lane id, never the source's handle (an e-mail address).
      const accountId = planned.find((p) => p.vendor === alias.vendor && p.account.sourceId === alias.sourceId)?.accountId;
      this.#log({ level: "info", event: "account_alias_assigned", account_id: accountId, vendor: alias.vendor, panel_id: alias.panelId });
    }
  }

  /** The accounts `replica`'s lane takes, each with its lane id; a refused stack account is logged once per change. */
  #laneAccounts(replica: ReplicaRuntime, accounts: readonly BundleAccount[]): LaneBundleAccount[] {
    const out: LaneBundleAccount[] = [];
    for (const entry of accounts) {
      const laneId = this.#laneAccountId(replica, entry.planned);
      if (laneId === null) {
        this.#noteStackRefusal(entry.planned);
        continue;
      }
      out.push({ ...entry, laneId });
    }
    return out;
  }

  #noteStackRefusal(planned: PlannedAccount): void {
    if (this.#stackRefused.get(planned.accountId) === planned.account.changeMark) return;
    this.#stackRefused.set(planned.accountId, planned.account.changeMark);
    this.#log({ level: "warn", event: "stack_account_refused", account_id: planned.accountId, vendor: planned.vendor, detail: STACK_ACCOUNT_ID_RULE });
  }

  /** The bundle a policy-running origin uploads; the constructor refuses a config without one. */
  #policyBundle(): LoadedPolicy {
    if (this.#policy === null) throw new RelayKitError("invalid_policy_bundle", "no policy bundle for a lane origin that runs one");
    return this.#policy;
  }

  async #doPolicy(replica: ReplicaRuntime): Promise<boolean> {
    if (replica.checked === null) {
      replica.phase = "attesting";
      return true;
    }
    if (!this.#runsPolicy(replica)) {
      replica.phase = "credentials";
      return true;
    }
    const policy = this.#policyBundle();
    const registry = await this.#readPolicyRegistry(replica);
    if (registry === "error") return false;
    if (registry !== null && this.#policyMatches(registry)) {
      replica.policyInstalled = true;
      replica.policyVersion = policy.version;
      replica.unknownRelayStreak = 0;
      replica.phase = "credentials";
      return true;
    }
    let response;
    try {
      response = await this.#post(replica, LANE_ENDPOINTS.policyBundle, toJsonString(policy.document));
    } catch (error) {
      if (this.#isPinFailure(error)) {
        this.#triggerReattest(replica, "policy_pin_failure", true);
      } else {
        this.#fail(replica, `policy_transport_${this.#errorCode(error)}`);
      }
      return false;
    }
    const code = refusalCode(response);
    if (code !== null) {
      const outcome = await this.#applyRefusal(replica, "policy", "policy", code, 1, response.status);
      if (outcome === "installed") {
        const after = await this.#readPolicyRegistry(replica);
        if (after !== "error" && after !== null && this.#policyMatches(after)) {
          replica.policyInstalled = true;
          replica.policyVersion = policy.version;
          replica.unknownRelayStreak = 0;
          replica.phase = "credentials";
          return true;
        }
        this.#fail(replica, "policy_replay_not_installed");
      }
      return false;
    }
    const after = await this.#readPolicyRegistry(replica);
    if (after === "error") return false;
    if (after !== null && this.#policyMatches(after)) {
      replica.policyInstalled = true;
      replica.policyVersion = policy.version;
      replica.unknownRelayStreak = 0;
      this.#clearFailure(replica);
      replica.phase = "credentials";
      this.#log({ level: "info", event: "policy_installed", origin: replica.origin, version: policy.version.toString() });
      return true;
    }
    this.#fail(replica, "policy_registry_mismatch");
    return false;
  }

  async #readPolicyRegistry(replica: ReplicaRuntime): Promise<JsonObject | null | "error"> {
    const path = `${POLICY_REGISTRY_PREFIX}${this.#config.relayId}`;
    let response;
    try {
      response = await this.#get(replica, path);
    } catch (error) {
      if (this.#isPinFailure(error)) {
        this.#triggerReattest(replica, "registry_pin_failure", true);
      } else {
        this.#fail(replica, `registry_transport_${this.#errorCode(error)}`);
      }
      return "error";
    }
    if (response.status === 404) return null;
    if (response.status < 200 || response.status >= 300) {
      this.#fail(replica, `registry_http_${response.status}`);
      return "error";
    }
    const value = decodeJson(response.body);
    if (!isObject(value)) {
      this.#fail(replica, "registry_invalid");
      return "error";
    }
    return value;
  }

  /** R08: one registry read before a renewal; a missing or changed policy restarts the policy step. */
  async #policyStillInstalled(replica: ReplicaRuntime): Promise<boolean> {
    if (!this.#runsPolicy(replica)) return true;
    const registry = await this.#readPolicyRegistry(replica);
    if (registry !== "error" && registry !== null && this.#policyMatches(registry)) {
      replica.policyInstalled = true;
      replica.policyVersion = this.#policyBundle().version;
      return true;
    }
    if (registry === "error") return false;
    if (replica.policyInstalled) {
      this.#log({ level: "warn", event: "policy_missing", origin: replica.origin });
    }
    replica.policyInstalled = false;
    replica.policyVersion = null;
    replica.phase = "policy";
    return false;
  }

  #policyMatches(document: JsonObject): boolean {
    const version = document["version"];
    const digest = document["module_sha256"];
    const policy = this.#policyBundle();
    if (typeof digest !== "string" || digest !== policy.moduleSha256) return false;
    if (typeof version === "bigint") return version === policy.version;
    if (typeof version === "number") return BigInt(version) === policy.version;
    if (typeof version === "string") {
      try {
        return BigInt(version) === policy.version;
      } catch {
        return false;
      }
    }
    return false;
  }

  // --- credentials ---------------------------------------------------------

  async #doCredentials(replica: ReplicaRuntime): Promise<boolean> {
    // D35: no credential may be sealed to a boot whose image is retiring; the revocation is sent
    // first (the same clear-then-revoke order as D37) and the caller returns.
    if (this.#retirementDue(replica)) {
      await this.#withdraw(replica, "os_image_retiring");
      return false;
    }
    // R03 + D37: this is the secret-delivery boundary. A replica held in `policy`/`credentials` by a
    // retryable refusal re-checks the release here, so a release Gray withdrew during a long wait
    // (for example `unknown_relay` while registration is pending) is never sealed to. Losing the
    // release clears the accepted bundle and lease before the revoke, so no pick finds an account.
    if (!this.#releaseAcceptable(replica)) {
      await this.#withdraw(replica, this.#withdrawReason(replica));
      return false;
    }
    if (replica.checked === null) {
      replica.phase = "attesting";
      return true;
    }
    // R09: while the source list is refused, the last snapshot must not keep renewing. The current
    // lease ends on its own; a healthy snapshot resumes renewals.
    if (!this.#sourceHealthy) {
      this.#fail(replica, "source_unhealthy");
      return false;
    }
    let prepared: { readonly accounts: readonly LaneBundleAccount[] };
    try {
      prepared = { accounts: this.#laneAccounts(replica, (await this.#readBundleAccounts()).accounts) };
    } catch (error) {
      this.#fail(replica, `source_credential_${this.#errorCode(error)}`);
      return false;
    }
    let version: bigint;
    try {
      version = await this.#ledger.allocate();
    } catch (error) {
      this.#versionFailure(error);
      replica.terminal = true;
      replica.phase = "failed";
      replica.lastError = error instanceof DaemonVersionError ? error.code : "version_stopped";
      return false;
    }
    const nowMs = this.#options.clock.wallMs();
    // R17: the lease is issued now, before the (possibly slow) upload. Renewal counts from this
    // moment, not from the acknowledgement.
    const issuedMono = this.#options.clock.monoMs();
    const nowSecs = BigInt(Math.floor(nowMs / 1000));
    const expiresAt = nowSecs + BigInt(this.#config.leaseLifetimeSeconds);
    const bundle: CredentialBundle = {
      relay_id: this.#config.relayId,
      version,
      issued_at: nowSecs,
      expires_at: expiresAt,
      accounts: prepared.accounts.map((entry) => ({
        account_id: entry.laneId,
        vendor: entry.planned.vendor,
        credential: entry.credential,
        ...(entry.egress === undefined ? {} : { egress: entry.egress }),
      })),
    };
    let body: string;
    try {
      const sealed = await sealCredentialBundleForReplicas({ reports: [replica.checked], signingKey: this.#options.signingKey, nowSecs, bundle });
      const envelope = sealed[0];
      if (envelope === undefined) throw new RelayKitError("invalid_envelope");
      body = toJsonString(envelope.envelope);
    } catch (error) {
      this.#fail(replica, `seal_bundle_${this.#errorCode(error)}`);
      return false;
    }
    let response;
    try {
      response = await this.#post(replica, LANE_ENDPOINTS.credentials, body);
    } catch (error) {
      if (this.#isPinFailure(error)) {
        this.#triggerReattest(replica, "credentials_pin_failure", true);
      } else {
        this.#fail(replica, `credentials_transport_${this.#errorCode(error)}`);
      }
      return false;
    }
    const code = refusalCode(response);
    if (code !== null) {
      const outcome = await this.#applyRefusal(replica, "credentials", "bundle", code, 1, response.status);
      if (outcome === "installed") {
        this.#markInstalled(replica, prepared.accounts, version, expiresAt, issuedMono);
        this.#clearFailure(replica);
        replica.unknownRelayStreak = 0;
        replica.phase = "serving";
        return true;
      }
      return false;
    }
    const answer = decodeJson(response.body);
    if (!isObject(answer) || (answer["relay_id"] !== undefined && answer["relay_id"] !== this.#config.relayId) || (answer["kind"] !== undefined && answer["kind"] !== "bundle")) {
      this.#fail(replica, "credentials_bad_answer");
      return false;
    }
    const echoed = answer["version"];
    if (echoed !== undefined && !sameVersion(echoed, version)) {
      this.#fail(replica, "credentials_version_mismatch");
      return false;
    }
    this.#markInstalled(replica, prepared.accounts, version, expiresAt, issuedMono);
    this.#clearFailure(replica);
    replica.unknownRelayStreak = 0;
    replica.phase = "serving";
    this.#log({ level: "info", event: "credentials_installed", origin: replica.origin, version: version.toString(), accounts: prepared.accounts.length });
    return true;
  }

  #markInstalled(replica: ReplicaRuntime, accounts: readonly LaneBundleAccount[], version: bigint, expiresAt: bigint, issuedMono: number): void {
    const atMs = this.#options.clock.wallMs();
    replica.installed.clear();
    for (const entry of accounts) {
      replica.installed.set(entry.planned.accountId, {
        laneId: entry.laneId,
        vendor: entry.planned.vendor,
        changeMark: entry.planned.account.changeMark,
        expiresAtMs: entry.planned.account.credentialExpiresAtMs ?? null,
        hasEgress: entry.egress !== undefined,
        sourceId: entry.planned.account.sourceId,
        version,
        sealedAtMs: atMs,
      });
    }
    replica.credentialVersion = version;
    replica.resealRequested = false;
    replica.leaseExpiresAtSecs = expiresAt;
    replica.leaseExpiresAtMs = Number(expiresAt) * 1000;
    replica.lastUploadMono = issuedMono;
    replica.lastPushAtMs = atMs;
    this.#pool.setInstalled(replica.origin, [...replica.installed.keys()]);
    this.#refreshPool();
  }

  async #readBundleAccounts(): Promise<{ readonly accounts: readonly BundleAccount[] }> {
    const signal = this.#sourceSignal();
    const accounts: BundleAccount[] = [];
    for (const planned of this.#plannedSorted()) {
      if (this.#parked.has(planned.accountId)) continue;
      const metadataReason = metadataParkReason(planned.account);
      if (metadataReason !== null) {
        this.#park(planned, metadataReason);
        continue;
      }
      let read: SourceCredential;
      try {
        read = await this.#options.source.credential(planned.account.sourceId, signal);
      } catch (error) {
        // R04: a per-account source error (a 404, a malformed CLIProxyAPI/http record) must park
        // that account, not abort every other account's bundle. Source-wide failures still throw.
        if (error instanceof RelayConnectorError || isPerAccountSourceError(error)) {
          this.#park(planned, "credential_unreadable");
          continue;
        }
        throw error;
      }
      const reason = credentialParkReason(planned.vendor, read.credential);
      if (reason !== null) {
        this.#park(planned, reason);
        continue;
      }
      // The proxy's password is the one secret half of the egress member; it is combined with the
      // metadata only here, and the combined value is validated by the connector's own schema.
      const egress = egressOf(planned, read);
      if (egress === "invalid") {
        this.#park(planned, "invalid_egress_format");
        continue;
      }
      accounts.push({ planned, credential: read.credential, ...(egress === undefined ? {} : { egress }) });
    }
    // Re-apply every park and every pool constraint (vendor, lease) — not just `pool.refresh()`:
    // this runs in the middle of a tick, after accounts were parked while reading their secrets.
    this.#refreshPool();
    return { accounts };
  }

  // --- account changes -----------------------------------------------------

  async #pushAccountChanges(replica: ReplicaRuntime): Promise<boolean> {
    if (replica.checked === null) return false;
    const desired = new Map(
      this.#plannedSorted()
        .filter((planned) => !this.#parked.has(planned.accountId) && this.#laneAccountId(replica, planned) !== null)
        .map((planned) => [planned.accountId, planned]),
    );
    let needFull = false;
    for (const accountId of desired.keys()) {
      if (!replica.installed.has(accountId)) {
        needFull = true;
        break;
      }
    }
    if (!needFull) {
      for (const [accountId, installed] of replica.installed) {
        const planned = desired.get(accountId);
        if (planned === undefined) continue;
        if (planned.vendor !== installed.vendor) {
          needFull = true;
          break;
        }
      }
    }
    if (needFull) return this.#doCredentials(replica);
    // Removals first: a revoke frees a slot and never invalidates another account.
    for (const [accountId, installed] of [...replica.installed]) {
      if (desired.has(accountId)) continue;
      if (!(await this.#revokeAccount(replica, accountId, installed))) return false;
    }
    for (const [accountId, planned] of desired) {
      const installed = replica.installed.get(accountId);
      if (installed === undefined) {
        return this.#doCredentials(replica);
      }
      if (installed.changeMark === planned.account.changeMark) continue;
      const outcome = await this.#updateAccount(replica, planned, installed);
      if (outcome === "full_bundle") return this.#doCredentials(replica);
      if (outcome !== "ok") return false;
    }
    return true;
  }

  async #updateAccount(replica: ReplicaRuntime, planned: PlannedAccount, installed: InstalledAccount): Promise<"ok" | "retry" | "full_bundle" | "terminal"> {
    // D35: a partial update is a credential delivery too; never send it to a retiring image.
    if (this.#retirementDue(replica)) {
      await this.#withdraw(replica, "os_image_retiring");
      return "retry";
    }
    // R03 + D37: a partial update also carries a credential, so it needs the same release check and
    // the same immediate withdrawal (clear the pool and lease first, then revoke).
    if (!this.#releaseAcceptable(replica)) {
      await this.#withdraw(replica, this.#withdrawReason(replica));
      return "retry";
    }
    let read: SourceCredential;
    try {
      read = await this.#options.source.credential(planned.account.sourceId, this.#sourceSignal());
    } catch (error) {
      // R04: the same per-account parking rule as the full-bundle path; otherwise one unreadable
      // account skips the renewal and every healthy account's lease expires.
      if (error instanceof RelayConnectorError || isPerAccountSourceError(error)) {
        this.#park(planned, "credential_unreadable");
        return "full_bundle";
      }
      this.#fail(replica, `source_credential_${this.#errorCode(error)}`);
      return "retry";
    }
    const credential = read.credential;
    const reason = credentialParkReason(planned.vendor, credential);
    if (reason !== null) {
      this.#park(planned, reason);
      return "full_bundle";
    }
    const egress = egressOf(planned, read);
    if (egress === "invalid") {
      this.#park(planned, "invalid_egress_format");
      return "full_bundle";
    }
    let version: bigint;
    try {
      version = await this.#ledger.allocate();
    } catch (error) {
      this.#versionFailure(error);
      replica.terminal = true;
      replica.phase = "failed";
      replica.lastError = error instanceof DaemonVersionError ? error.code : "version_stopped";
      return "terminal";
    }
    const update: CredentialUpdate = {
      relay_id: this.#config.relayId,
      version,
      account_id: installed.laneId,
      credential,
      // Always name the proxy when the source declares one; clear it when the accepted message had
      // one and the source no longer does (a proxy rotation needs no re-sealed pool, E2).
      ...(egress === undefined ? (installed.hasEgress ? { egress: null } : {}) : { egress }),
    };
    let body: string;
    try {
      const sealed = await sealCredentialUpdateForReplicas({ reports: [replica.checked as NonNullable<ReplicaRuntime["checked"]>], signingKey: this.#options.signingKey, nowSecs: BigInt(Math.floor(this.#options.clock.wallMs() / 1000)), update });
      body = toJsonString((sealed[0] as { envelope: JsonObject }).envelope);
    } catch (error) {
      this.#fail(replica, `seal_update_${this.#errorCode(error)}`);
      return "retry";
    }
    let response;
    try {
      response = await this.#post(replica, LANE_ENDPOINTS.credentials, body);
    } catch (error) {
      if (this.#isPinFailure(error)) {
        this.#triggerReattest(replica, "update_pin_failure", true);
      } else {
        this.#fail(replica, `update_transport_${this.#errorCode(error)}`);
      }
      return "retry";
    }
    const code = refusalCode(response);
    if (code !== null) {
      const outcome = await this.#applyRefusal(replica, "credentials", "update", code, 1, response.status);
      if (outcome === "full_bundle") return "full_bundle";
      if (outcome === "installed") {
        replica.installed.set(planned.accountId, { laneId: installed.laneId, vendor: planned.vendor, changeMark: planned.account.changeMark, expiresAtMs: planned.account.credentialExpiresAtMs ?? null, hasEgress: egress !== undefined, sourceId: planned.account.sourceId, version, sealedAtMs: this.#options.clock.wallMs() });
        replica.unknownRelayStreak = 0;
        this.#clearFailure(replica);
        return "ok";
      }
      return outcome === "terminal" ? "terminal" : "retry";
    }
    replica.installed.set(planned.accountId, {
      laneId: installed.laneId,
      vendor: planned.vendor,
      changeMark: planned.account.changeMark,
      expiresAtMs: planned.account.credentialExpiresAtMs ?? null,
      hasEgress: egress !== undefined,
      sourceId: planned.account.sourceId,
      version,
      sealedAtMs: this.#options.clock.wallMs(),
    });
    this.#clearFailure(replica);
    replica.unknownRelayStreak = 0;
    this.#pool.setInstalled(replica.origin, [...replica.installed.keys()]);
    this.#log({ level: "info", event: "token_pushed", origin: replica.origin, account_id: installed.laneId, version: version.toString() });
    return "ok";
  }

  async #revokeAccount(replica: ReplicaRuntime, accountId: string, installed: InstalledAccount): Promise<boolean> {
    let version: bigint;
    try {
      version = await this.#ledger.allocate();
    } catch (error) {
      this.#versionFailure(error);
      replica.terminal = true;
      replica.phase = "failed";
      replica.lastError = error instanceof DaemonVersionError ? error.code : "version_stopped";
      return false;
    }
    const revoke: CredentialRevoke = { relay_id: this.#config.relayId, version, revoke: "account", account_id: installed.laneId };
    let body: string;
    try {
      const sealed = await sealCredentialRevokeForReplicas({ reports: [replica.checked as NonNullable<ReplicaRuntime["checked"]>], signingKey: this.#options.signingKey, nowSecs: BigInt(Math.floor(this.#options.clock.wallMs() / 1000)), revoke });
      body = toJsonString((sealed[0] as { envelope: JsonObject }).envelope);
    } catch (error) {
      this.#fail(replica, `seal_revoke_${this.#errorCode(error)}`);
      return false;
    }
    let response;
    try {
      response = await this.#post(replica, LANE_ENDPOINTS.credentials, body);
    } catch (error) {
      if (this.#isPinFailure(error)) {
        this.#triggerReattest(replica, "revoke_pin_failure", true);
      } else {
        this.#fail(replica, `revoke_transport_${this.#errorCode(error)}`);
      }
      return false;
    }
    const code = refusalCode(response);
    if (code !== null) {
      const outcome = await this.#applyRefusal(replica, "credentials", "revoke", code, 1, response.status);
      if (outcome === "installed") {
        this.#removeInstalled(replica, accountId);
        replica.unknownRelayStreak = 0;
        this.#clearFailure(replica);
        return true;
      }
      return false;
    }
    this.#removeInstalled(replica, accountId);
    this.#clearFailure(replica);
    replica.unknownRelayStreak = 0;
    this.#log({ level: "info", event: "account_revoked", origin: replica.origin, account_id: installed.laneId, version: version.toString() });
    return true;
  }

  #removeInstalled(replica: ReplicaRuntime, accountId: string): void {
    replica.installed.delete(accountId);
    this.#pool.uninstall(replica.origin, accountId);
  }

  // --- withdrawal ----------------------------------------------------------

  /**
   * D37: a withdrawal is immediate. Clear the installed map, the lease and the pool entry *before*
   * the version allocation and the revoke POST, so a scheduler pick that arrives while the revoke
   * is in flight finds no account (and the TEE no longer holds a bundle the relay advertises). This
   * runs from `policy` and `credentials` as well as `serving`; R07's recovery still re-attests a
   * withdrawn boot when a later signed list accepts it.
   */
  async #withdraw(replica: ReplicaRuntime, reason: string): Promise<void> {
    if (replica.phase === "withdrawn") return;
    const checked = replica.checked;
    replica.phase = "withdrawn";
    replica.installed.clear();
    replica.leaseExpiresAtSecs = null;
    replica.leaseExpiresAtMs = null;
    replica.lastUploadMono = null;
    this.#pool.clearReplica(replica.origin);
    if (checked !== null) {
      try {
        const version = await this.#ledger.allocate();
        const revoke: CredentialRevoke = { relay_id: this.#config.relayId, version, revoke: "relay" };
        const sealed = await sealCredentialRevokeForReplicas({ reports: [checked], signingKey: this.#options.signingKey, nowSecs: BigInt(Math.floor(this.#options.clock.wallMs() / 1000)), revoke });
        const response = await this.#post(replica, LANE_ENDPOINTS.credentials, toJsonString((sealed[0] as { envelope: JsonObject }).envelope));
        const code = refusalCode(response);
        if (code === null) {
          this.#log({ level: "info", event: "relay_revoked", origin: replica.origin, reason, version: version.toString() });
        } else {
          this.#log({ level: "warn", event: "relay_revoke_refused", origin: replica.origin, reason, code });
        }
      } catch (error) {
        this.#log({ level: "warn", event: "relay_revoke_failed", origin: replica.origin, reason, code: this.#errorCode(error) });
      }
    }
    // The TEE is revoked (or unreachable and its lease will lapse) only now: during the revoke the
    // key stays resolvable so a pick still verifies and is answered `unavailable` from the cleared
    // pool, rather than becoming an authentication error mid-withdrawal.
    this.#refreshKeys();
    this.#alert("replica_withdrawn", `${replica.origin}: ${reason}`);
  }

  // --- healthz -------------------------------------------------------------

  async #pollHealthz(replica: ReplicaRuntime, mono: number): Promise<void> {
    if (mono - replica.lastHealthzMono < this.#config.healthzPollMs) return;
    replica.lastHealthzMono = mono;
    if (replica.checked === null) return;
    let response;
    try {
      response = await this.#get(replica, `/healthz?relay=${encodeURIComponent(this.#config.relayId)}`);
    } catch (error) {
      if (this.#isPinFailure(error)) {
        this.#triggerReattest(replica, "healthz_pin_failure", true);
      } else {
        this.#fail(replica, `healthz_transport_${this.#errorCode(error)}`);
      }
      return;
    }
    if (response.status !== 200) {
      this.#fail(replica, `healthz_http_${response.status}`);
      return;
    }
    const digest = headerValue(response, "x-aci-keyset-digest") ?? headerValue(response, "x-workload-keyset-digest");
    if (digest === null) {
      this.#fail(replica, "healthz_no_digest");
      return;
    }
    if (digest === replica.keysetDigest) {
      this.#clearFailure(replica);
      this.#checkSealed(replica, response.body);
      return;
    }
    // A different keyset digest is a new boot. If it is a digest this origin had before, the origin
    // is alternating between two boots: alert once and stop switching, rather than flapping forever.
    if (replica.observedDigests.includes(digest)) {
      replica.alternating = true;
      replica.phase = "failed";
      replica.terminal = true;
      replica.lastError = "origin_serves_two_boots";
      this.#clearForNewBoot(replica);
      this.#alert("origin_serves_two_boots", replica.origin);
      return;
    }
    replica.digestChanges += 1;
    this.#triggerReattest(replica, "keyset_digest_changed", true);
  }

  /**
   * Whether the lane still holds what this daemon sealed to it: its `/healthz?relay=` answer names the
   * last version it accepted from this relay, or null for none. Null, or a version below the last
   * bundle's, on a serving replica means the lane cleared the relay (same boot, same keyset, and no
   * refusal to say so): a re-seal is asked for. A lane that answers no `relay` member (one older than
   * the field), a malformed one or another relay's says nothing, and nothing changes.
   */
  #checkSealed(replica: ReplicaRuntime, body: Uint8Array): void {
    if (replica.phase !== "serving" || replica.credentialVersion === null || replica.resealRequested) return;
    const answer = decodeJson(body);
    const relay = isObject(answer) ? answer["relay"] : undefined;
    if (!isObject(relay) || relay["relay_id"] !== this.#config.relayId) return;
    const sealed = relay["sealed_version"];
    let held: bigint | null;
    if (sealed === null) held = null;
    else if (typeof sealed === "string" && /^(0|[1-9][0-9]{0,19})$/.test(sealed)) held = BigInt(sealed);
    else return;
    if (held !== null && held >= replica.credentialVersion) return;
    this.#log({ level: "warn", event: "lane_credentials_missing", origin: replica.origin, lane_version: held === null ? null : held.toString(), installed_version: replica.credentialVersion.toString() });
    replica.resealRequested = true;
  }

  // --- refusals ------------------------------------------------------------

  async #applyRefusal(replica: ReplicaRuntime, route: "credentials" | "policy", kind: "bundle" | "update" | "revoke" | "policy", code: string, attempt: number, httpStatus?: number): Promise<"installed" | "reattest" | "retry" | "full_bundle" | "terminal"> {
    const decision = decideRefusal({ route, kind, code, attempt, ledgerIntact: this.#ledger.intact, ...(httpStatus === undefined ? {} : { httpStatus }) });
    this.#log({ level: decision.transient ? "warn" : "error", event: "upload_refused", origin: replica.origin, route, kind, code, action: decision.action });
    switch (decision.action) {
      case "installed":
        return "installed";
      case "reattest":
        this.#triggerReattest(replica, code, true);
        return "reattest";
      case "reseal":
      case "retry":
      case "refilter":
        this.#fail(replica, code);
        return "retry";
      case "full_bundle":
        this.#fail(replica, code);
        return "full_bundle";
      case "version_probe": {
        const probe = this.#ledger.onRollback(attempt);
        if (probe.action === "probe") {
          this.#log({ level: "warn", event: "version_probe", origin: replica.origin, attempt: probe.attempt, jump_ms: Number(probe.jumpMs) });
          this.#fail(replica, "version_probe");
          return "retry";
        }
        if (probe.action === "exhausted") this.#versionProbeExhausted = true;
        this.#raiseSecondWriter();
        replica.terminal = true;
        replica.phase = "failed";
        replica.lastError = code;
        return "terminal";
      }
      case "second_writer":
        this.#raiseSecondWriter();
        replica.terminal = true;
        replica.phase = "failed";
        replica.lastError = code;
        return "terminal";
      case "relay_unknown":
        // R08: a removal clears the lane's policy and credential records. Do not let the next
        // credential renewal succeed; run policy again first.
        replica.policyInstalled = false;
        replica.phase = "policy";
        this.#noteRelayUnknown(replica);
        // Once it persists, the lane's registry is waiting for Gray's next snapshot at the soonest:
        // retry at that pace, and keep saying so (health `relay_unknown`, status, doctor).
        this.#fail(replica, "unknown_relay", replica.unknownRelayStreak >= RELAY_UNKNOWN_THRESHOLD ? RELAY_UNKNOWN_RETRY_MS : 0);
        return "retry";
      case "terminal":
        this.#terminal(replica, decision.message, code);
        return "terminal";
    }
  }

  #noteRelayUnknown(replica: ReplicaRuntime): void {
    replica.unknownRelayStreak += 1;
    if (replica.unknownRelayStreak === RELAY_UNKNOWN_THRESHOLD) {
      this.#alert("relay_unknown", replica.origin);
      this.#log({ level: "error", event: "relay_unknown_persists", origin: replica.origin, attempts: replica.unknownRelayStreak, retry_in_ms: RELAY_UNKNOWN_RETRY_MS });
    }
  }

  #terminal(replica: ReplicaRuntime, message: string, code: string): void {
    replica.terminal = true;
    replica.phase = "failed";
    replica.lastError = code;
    this.#refreshKeys();
    this.#alert("replica_failed", `${replica.origin}: ${message}`);
  }

  #raiseSecondWriter(): void {
    if (this.#secondWriter) return;
    this.#secondWriter = true;
    this.#ledger.stop("second_writer");
    this.#alert("second_writer", "an unexpected rollback or replay with an intact state file");
    this.#log({ level: "error", event: "second_writer" });
  }

  // --- source and releases -------------------------------------------------

  async #pollSource(force: boolean): Promise<void> {
    const mono = this.#options.clock.monoMs();
    if (!force && mono - this.#sourceLastPollMono < this.#config.sourcePollMs) return;
    this.#sourceLastPollMono = mono;
    let snapshot: SourceSnapshot;
    try {
      snapshot = await this.#options.source.list(this.#sourceSignal());
    } catch (error) {
      this.#sourceHealthy = false;
      this.#log({ level: "warn", event: "source_poll_failed", code: this.#errorCode(error) });
      return;
    }
    try {
      this.#applySnapshot(snapshot);
      this.#sourceHealthy = true;
      this.#sourceLastPollAtMs = this.#options.clock.wallMs();
    } catch (error) {
      this.#sourceHealthy = false;
      this.#log({ level: "warn", event: "source_snapshot_refused", code: this.#errorCode(error) });
      return;
    }
    await this.#assignAliases();
  }

  #applySnapshot(snapshot: SourceSnapshot): void {
    if (!Array.isArray(snapshot.accounts)) throw new Error("source accounts is not an array");
    const seen = new Set<string>();
    const planned = new Map<string, PlannedAccount>();
    const sourceIds = new Map<string, string>();
    for (const account of snapshot.accounts) {
      if (typeof account.sourceId !== "string" || account.sourceId.length === 0) throw new Error("source account id");
      if (seen.has(account.sourceId)) throw new Error("duplicate source account id");
      seen.add(account.sourceId);
      const plannedAccount = planAccount(this.#config.relayId, this.#options.source.kind, account);
      if (planned.has(plannedAccount.accountId)) throw new Error("duplicate lane account id");
      planned.set(plannedAccount.accountId, plannedAccount);
      sourceIds.set(account.sourceId, plannedAccount.accountId);
      const reason = metadataParkReason(account);
      if (reason !== null) this.#park(plannedAccount, reason);
    }
    this.#planned = planned;
    this.#parked.prune(snapshot.accounts, sourceIds);
    for (const accountId of [...this.#stackRefused.keys()]) if (!planned.has(accountId)) this.#stackRefused.delete(accountId);
    // The pool is rebuilt by the caller's `#refreshPool` after the poll, so the snapshot and the
    // installed maps are applied once per tick, not twice.
    this.#checkCredentialExpiry();
  }

  /**
   * The initial control view at start: the CLI's `control.json` when it is readable, otherwise the
   * legacy state-file pair once (K5-3 migration), otherwise the empty control. `#lastControlText`
   * records the file's canonical bytes so the first tick does not apply them a second time.
   */
  async #initialControl(loaded: DaemonStateLoad): Promise<DaemonControl> {
    let stored: DaemonControlLoad | null = null;
    try {
      stored = await this.#options.controlStore.read();
    } catch {
      stored = null;
    }
    if (stored !== null && stored.intact) {
      this.#lastControlText = daemonControlText(stored.control);
      return stored.control;
    }
    this.#lastControlText = null;
    if (loaded.legacyControl === null) return EMPTY_DAEMON_CONTROL;
    this.#log({
      level: "info",
      event: "control_migrated",
      source: "state_file",
      paused: loaded.legacyControl.paused,
      accepted: loaded.legacyControl.acceptedReleases.length,
    });
    return loaded.legacyControl;
  }

  /**
   * Adopt `control.json` at the start of every tick. The CLI writes it (atomic rename + fsync) and
   * is its only writer; the daemon has no write member for it. Identical bytes are a no-op, so an
   * in-process `setPaused`/`acceptRelease` survives until the CLI actually changes the file.
   */
  async #reloadControl(): Promise<void> {
    let loaded: DaemonControlLoad;
    try {
      loaded = await this.#options.controlStore.read();
    } catch {
      return;
    }
    if (!loaded.intact) return;
    const text = daemonControlText(loaded.control);
    if (text === this.#lastControlText) return;
    this.#lastControlText = text;
    const previous = this.#control;
    this.#control = loaded.control;
    if (loaded.control.paused !== previous.paused) {
      this.#log({ level: "info", event: loaded.control.paused ? "paused" : "resumed", source: "control_file" });
    }
    const previousAccepted = previous.acceptedReleases;
    const nextAccepted = loaded.control.acceptedReleases;
    const previousStamps = JSON.stringify(previous.acceptedAtMs ?? {});
    const nextStamps = JSON.stringify(loaded.control.acceptedAtMs ?? {});
    const pairingChanged = (previous.acceptedAtPairing ?? []).join(",") !== (loaded.control.acceptedAtPairing ?? []).join(",");
    if (previousAccepted.length !== nextAccepted.length || previousAccepted.some((hash, index) => hash !== nextAccepted[index]) || previousStamps !== nextStamps || pairingChanged) {
      this.#releases.setAccepted(nextAccepted, loaded.control.acceptedAtMs ?? {}, loaded.control.acceptedAtPairing ?? []);
      this.#log({ level: "info", event: "releases_accepted_reloaded", count: nextAccepted.length, source: "control_file" });
      // R27: an acceptance counts only from this agent's first sight, and `releases accept` waits for that sight
      // before it stamps the acceptance that counts. A new or re-stamped acceptance of a hash this agent has not seen
      // means Gray listed it after the last read: read the list at this tick rather than at the next `release_poll`.
      // It decides nothing: the sight is recorded as any other, and the early stamp stays before it.
      const stamped = new Set(nextAccepted.filter((hash) => !previousAccepted.includes(hash) || previous.acceptedAtMs?.[hash] !== loaded.control.acceptedAtMs?.[hash]));
      const unseen = [...stamped].filter((hash) => !this.#releases.hasFirstSight(hash));
      if (unseen.length > 0) {
        this.#releasePollDue = true;
        this.#log({ level: "info", event: "release_list_read_for_acceptance", count: unseen.length });
      }
    }
    const previousRejected = previous.rejectedReleases ?? [];
    const nextRejected = loaded.control.rejectedReleases ?? [];
    if (previousRejected.length !== nextRejected.length || previousRejected.some((hash, index) => hash !== nextRejected[index])) {
      this.#releases.setRejected(nextRejected);
      this.#log({ level: "info", event: "releases_rejected_reloaded", count: nextRejected.length, source: "control_file" });
    }
    if (loaded.control.stackCurrentImage !== previous.stackCurrentImage) {
      // S53: a rollout or rollback; the token service names it from the next challenge on.
      this.#log({ level: "info", event: "stack_image_rolled", image: loaded.control.stackCurrentImage ?? null, source: "control_file" });
    }
  }

  async #pollReleases(force: boolean): Promise<void> {
    const mono = this.#options.clock.monoMs();
    if (!force && !this.#releasePollDue && mono - this.#releaseLastPollMono < this.#config.releasePollMs && this.#releases.list !== null) return;
    this.#releaseLastPollMono = mono;
    this.#releasePollDue = false;
    try {
      const nowMs = this.#options.clock.wallMs();
      const verified = await fetchReleaseList(this.#options.fetch, this.#config.lane.releaseList, {
        publicKey: this.#config.lane.releasePublicKey,
        maxAgeSeconds: this.#config.lane.releaseListMaxAgeSeconds,
        nowMs,
        freshness: this.#config.lane.releaseFreshness,
      });
      // D78: `issued_at` is monotonic for this daemon. A CDN edge, a mirror or a replay can hand
      // back a still-fresh, correctly signed list issued before the one in hand (it can even lack a
      // `retire_after` already acted on); adopting it would resurrect a withdrawn release or cancel
      // a retirement. Treat it as a failed poll and keep the newer list authoritative.
      if (this.#releaseIssuedAtSecs !== null && verified.issuedAt < this.#releaseIssuedAtSecs) {
        throw new ReleaseListError("issued_at_regressed");
      }
      await this.#releases.observe(verified.list);
      // The first sights are persisted now, so a pairing acceptance stamped from here on counts (R27).
      await this.#acceptPairingReleases();
      const previous = this.#releaseView;
      const sameList = previous !== null && previous.listSha256 === verified.listSha256;
      const kept = sameList && this.#releaseCurrentUntilSecs !== null && this.#releaseCurrentUntilSecs > verified.currentUntil;
      this.#releaseCurrentUntilSecs = kept ? this.#releaseCurrentUntilSecs : verified.currentUntil;
      this.#releaseView = kept && previous !== null ? previous : verified;
      this.#releaseIssuedAtSecs = verified.issuedAt;
      this.#releaseListHealthy = true;
      this.#releaseLastError = null;
      this.#warnFreshness(verified, nowMs);
    } catch (error) {
      this.#releaseListHealthy = false;
      const failure = error instanceof ReleaseListError ? error : new ReleaseListError("fetch_failed");
      this.#releaseLastError = failure;
      this.#log({ level: "warn", event: "release_list_failed", code: failure.code, ...(failure.staleness === null ? {} : { staleness: failure.staleness }) });
    }
  }

  /**
   * `init --pair`'s acceptances (the config's `releases.accepted_at_pairing`): the compose and OS image hashes Gray's
   * signed list named when the relay paired. Joining was the relay's choice to trust them, so each one the current list
   * names is accepted once, as `releases accept` would (R05), right after `observe` persisted its first sight, so the
   * stamp is at or after it (R27). A hash the operator rejects is left alone while the veto stands (`releases unreject`
   * puts it back under this rule), and one taken at pairing before is never taken again (a release Gray withdrew and
   * lists again waits its delay). control.json is written first; an acceptance that
   * could not be written is not made, and the next poll tries again.
   */
  async #acceptPairingReleases(): Promise<void> {
    const list = this.#releases.list;
    const wanted = this.#config.releases.acceptedAtPairing;
    if (list === null || wanted.length === 0) return;
    const images = new Set(list.osImages.map((entry) => entry.os_image_hash));
    const listed = new Set([...list.releases.map((entry) => entry.compose_hash), ...images]);
    const taken = new Set(this.#control.acceptedAtPairing ?? []);
    const rejected = new Set(this.#control.rejectedReleases ?? []);
    const due = wanted.filter((hash) => listed.has(hash) && !taken.has(hash) && !rejected.has(hash));
    if (due.length === 0) return;
    const nowMs = this.#options.clock.wallMs();
    try {
      await this.#options.persistPairingAcceptances?.(due, nowMs);
    } catch (error) {
      this.#log({ level: "warn", event: "release_pairing_accept_unsaved", code: this.#errorCode(error) });
      return;
    }
    this.#control = withPairingAcceptances(this.#control, due, nowMs);
    this.#releases.setAccepted(this.#control.acceptedReleases, this.#control.acceptedAtMs ?? {}, this.#control.acceptedAtPairing ?? []);
    for (const hash of due) {
      this.#log({ level: "info", event: "release_accepted_at_pairing", ...(images.has(hash) ? { os_image_hash: hash } : { compose_hash: hash }) });
    }
  }

  /**
   * D137: a list current by its own `issued_at` while its freshness document is unusable is fine for a
   * while (a new list's document comes with the signer's next run), but once its own window ends within
   * 12 h, the document is what will keep the relay serving: say so on every poll until it is usable.
   */
  #warnFreshness(verified: VerifiedReleaseList, nowMs: number): void {
    if (this.#config.lane.releaseFreshness === null || verified.freshness.state === "ok") return;
    const ownEndMs = (Number(verified.issuedAt) + this.#config.lane.releaseListMaxAgeSeconds + 1) * 1000;
    if (ownEndMs - nowMs > 12 * 3_600_000) return;
    this.#log({ level: "warn", event: "release_freshness_unusable", state: verified.freshness.state, current_until_ms: Number(verified.currentUntil) * 1000 });
  }

  #releaseAcceptable(replica: ReplicaRuntime): boolean {
    if (replica.composeHash === null || replica.osImageHash === null) return false;
    // S11b: credential intake applies the OS image rule too (production by its own texts, delay or
    // explicit accept, no veto), the same decision the pull-token service asks for.
    return this.#releaseDecision(replica.composeHash, replica.osImageHash, true, replica.origin).ok;
  }

  /**
   * Why a replica loses (or never gets) its release, for the withdrawal log: S11b's own refusals by
   * name, every other loss as before (`release_withdrawn`, or `release_unpinned` without a compose hash).
   */
  #withdrawReason(replica: ReplicaRuntime): string {
    if (replica.composeHash === null) return "release_unpinned";
    const decision = this.#releaseDecision(replica.composeHash, replica.osImageHash, true, replica.origin);
    return !decision.ok && S11B_REFUSALS.has(decision.code) ? decision.code : "release_withdrawn";
  }

  /**
   * The acceptance rule of `#releaseAcceptable` for one compose hash and OS image, with its first
   * refusal; `osImageAcceptance` adds S11b's rule for the OS image. With `origin` (credential intake)
   * the entry must also be the kind that origin is: the relay's stack origin takes only its own stack
   * release, every other origin only a release without `stack`. The pull-token service checks the
   * stack member at its own place in S11 and passes none.
   */
  #releaseDecision(
    composeHash: string,
    osImageHash: string | null,
    osImageAcceptance: boolean,
    origin: string | null = null,
  ): { readonly ok: true; readonly entry: ReleaseEntry; readonly osImage: OsImageEntry } | { readonly ok: false; readonly code: ReleaseRefusal } {
    // R02: the registry is only an authority while the list it came from is current (its own window or,
    // D137, its freshness document's, never past its expires_at). A failed or withheld refresh must not
    // extend the previous list's acceptance forever.
    const currentUntil = this.#releaseCurrentUntilSecs;
    if (currentUntil === null) return { ok: false, code: "release_list_unavailable" };
    const nowSecs = BigInt(Math.floor(this.#options.clock.wallMs() / 1000));
    if (nowSecs >= currentUntil) return { ok: false, code: "release_list_unavailable" };
    const list = this.#releases.list;
    if (list === null) return { ok: false, code: "release_list_unavailable" };
    // D36 (defence in depth beside the strict reader): a list that names an OS image without all
    // four measurements is not an authority at all, so no replica may be published from it.
    if (!releaseListHasOsMeasurements(list)) return { ok: false, code: "release_list_unavailable" };
    const entry = list.releases.find((release) => release.compose_hash === composeHash);
    if (entry === undefined) return { ok: false, code: "compose_not_listed" };
    if (origin !== null) {
      const stackOrigin = this.#stackReplica?.origin ?? null;
      if (origin === stackOrigin) {
        // S55: one stack release serves every relay; the boot's identity names the relay (`#stackBootDecision`).
        if (entry.stack === null) return { ok: false, code: "release_not_stack" };
      } else if (entry.stack !== null) {
        // A relay-stack release seals to nothing but its own relay's stack app.
        return { ok: false, code: "release_stack_unexpected" };
      }
    }
    if (this.#releases.isRejected(composeHash)) return { ok: false, code: "release_rejected" };
    if (!this.#releases.acceptable(composeHash, this.#options.clock.wallMs())) return { ok: false, code: "release_not_accepted" };
    // R01: the compose hash alone is not the boot. The OS image must be in the same signed list.
    if (osImageHash === null) return { ok: false, code: "os_image_missing" };
    const osImage = list.osImages.find((image) => image.os_image_hash === osImageHash);
    if (osImage === undefined) return { ok: false, code: "os_image_not_listed" };
    if (osImageAcceptance) {
      const accepted = this.#releases.osImageDecision(osImageHash, this.#options.clock.wallMs());
      if (accepted === null) return { ok: false, code: "os_image_not_listed" };
      if (!accepted.ok) return { ok: false, code: accepted.code };
    }
    return { ok: true, entry, osImage };
  }

  /**
   * Relay standard v1.7 item 9: the stack releases of Gray's list this relay lets boot now (`acceptable`: listed with a
   * commit, not rejected, accepted explicitly or after `delay_days`), sorted; null before the first list is read. The
   * agent status reports them as `accepted_compose`, and Gray boots no relay VM for a release outside them. The token
   * service's own check (`releaseForBoot`) is unchanged and still decides every boot.
   */
  firstReads(): Promise<void> {
    return this.#firstReads;
  }

  acceptedComposeHashes(): string[] | null {
    const list = this.#releases.list;
    if (list === null) return null;
    const nowMs = this.#options.clock.wallMs();
    return list.releases
      .filter((entry) => entry.stack !== null && this.#releases.acceptable(entry.compose_hash, nowMs))
      .map((entry) => entry.compose_hash)
      .sort();
  }

  releaseForBoot(composeHash: string, osImageHash: string | null): StackReleaseDecision {
    // No origin: the stack-member separation is the token service's own S11a check.
    const decision = this.#releaseDecision(composeHash, osImageHash, true) as StackReleaseDecision;
    if (!decision.ok) return decision;
    // D35: a boot on a retiring OS image would never receive credentials; it gets nothing else either.
    if (this.#retirementDueFor(osImageHash)) return { ok: false, code: "os_image_retiring" };
    return decision;
  }

  /**
   * D35: the current list's announced retirement of this replica's OS image, as wall-clock ms, or
   * null when the list carries no `retire_after` for it. `status()` reports it and the supervisor
   * uses it to withdraw before the date.
   */
  #retireAfterMs(replica: ReplicaRuntime): number | null {
    return this.#retireAfterMsFor(replica.osImageHash);
  }

  #retireAfterMsFor(osImageHash: string | null): number | null {
    const list = this.#releases.list;
    if (list === null || osImageHash === null) return null;
    const image = list.osImages.find((entry) => entry.os_image_hash === osImageHash);
    if (image === undefined || image.retire_after === null) return null;
    return Number(image.retire_after) * 1000;
  }

  /**
   * D35: stop one full credential lease before `retire_after`. `lease_lifetime` is the longest
   * lease this daemon can seal (the config bound is `MAX_CREDENTIAL_LEASE_SECONDS`), so a bundle
   * issued before this threshold expires by the date and nothing is renewed inside it. The wall
   * clock is injected in tests; `nowMs` defaults to it.
   */
  #retirementDue(replica: ReplicaRuntime, nowMs = this.#options.clock.wallMs()): boolean {
    return this.#retirementDueFor(replica.osImageHash, nowMs);
  }

  #retirementDueFor(osImageHash: string | null, nowMs = this.#options.clock.wallMs()): boolean {
    const retireAfterMs = this.#retireAfterMsFor(osImageHash);
    if (retireAfterMs === null) return false;
    return nowMs >= retireAfterMs - this.#config.leaseLifetimeSeconds * 1000;
  }

  // --- scheduler pool and keys --------------------------------------------

  #refreshPool(): void {
    const eligible: PoolAccount[] = this.#plannedSorted().map((planned) => ({ planned, pickEligible: this.#pickEligible(planned.account) }));
    this.#pool.setSource(eligible, [...this.#replicas.keys()]);
    const plannedById = new Map(this.#plannedSorted().map((planned) => [planned.accountId, planned]));
    const now = this.#options.clock.wallMs();
    for (const replica of this.#replicas.values()) {
      // D37: a replica that has just lost its release must not be advertised even in the window
      // before its supervisor runs `#withdraw` (the pool is rebuilt before the per-replica steps).
      // D35: a retiring image stops advertising as soon as the retirement lead is reached too.
      const released = this.#releaseAcceptable(replica) && !this.#retirementDue(replica);
      // R15: an expired lease means the TEE will refuse the pick as `bundle_expired`; publish no
      // installed account until a renewal succeeds.
      const leaseValid = released && replica.leaseExpiresAtMs !== null && replica.leaseExpiresAtMs > now;
      // R14: after a vendor change on the same source id, an account may only be offered for the
      // vendor the TEE actually installed. A pending full bundle keeps it out of picks.
      const installed = leaseValid
        ? [...replica.installed]
            .filter(([accountId, entry]) => {
              const planned = plannedById.get(accountId);
              return planned !== undefined && planned.vendor === entry.vendor;
            })
            .map(([accountId]) => accountId)
        : [];
      this.#pool.setInstalled(replica.origin, installed);
    }
  }

  #refreshKeys(): void {
    const next = new Map<string, SchedulerCandidateKey[]>();
    for (const replica of this.#replicas.values()) {
      if (replica.checked === null || replica.retired || replica.phase === "withdrawn" || replica.phase === "failed") continue;
      const keyset = replica.checked.binding.keyset;
      for (const key of keyset.receipt_signing_keys) {
        if (key.algo !== "ed25519") continue;
        const bytes = hexBytes(key.public_key, 32);
        if (bytes === null) continue;
        const candidates = next.get(key.key_id) ?? [];
        candidates.push({ replicaId: replica.origin, publicKey: bytes, notAfter: keyset.not_after });
        next.set(key.key_id, candidates);
      }
    }
    this.#keysByKeyId = next;
    this.handler.setKeyFor((keyId) => this.#keysByKeyId.get(keyId) ?? []);
  }

  #onVerifiedRequest(event: { readonly replicaId: string; readonly path: string; readonly method: string; readonly timestampMs: number; readonly nowMs: number; readonly apiVersion: number }): void {
    // D116(b): the scheduler API version each replica's TEE speaks, for `gray-assistant status` and doctor;
    // one line when it is first seen or changes, so a TEE upgrade shows in the log.
    const replica = this.#replicas.get(event.replicaId);
    if (replica !== undefined && replica.schedulerApiVersion !== event.apiVersion) {
      replica.schedulerApiVersion = event.apiVersion;
      this.#log({ level: "info", event: "scheduler_api_version", replica: event.replicaId, api_version: event.apiVersion });
    }
    const skew = event.nowMs - event.timestampMs;
    const first = this.#clockSkewMs === null;
    this.#clockSkewMs = skew;
    this.#clockSkewAtMs = event.nowMs;
    const mono = this.#options.clock.monoMs();
    if (first) {
      this.#log({ level: "info", event: "clock_skew", skew_ms: skew, replica: event.replicaId });
      return;
    }
    if (Math.abs(skew) >= 10_000 && mono - this.#lastSkewLogMono >= 60_000) {
      this.#lastSkewLogMono = mono;
      this.#log({ level: "warn", event: "clock_skew", skew_ms: skew, replica: event.replicaId });
    }
  }

  #onUnknownKey(event: { readonly keyId: string; readonly path: string; readonly method: string; readonly reason: string }): void {
    const mono = this.#options.clock.monoMs();
    if (mono - this.#lastUnknownKeyMono < UNKNOWN_KEY_COOLDOWN_MS) return;
    this.#lastUnknownKeyMono = mono;
    this.#log({ level: "warn", event: "scheduler_unknown_key", key_id: event.keyId, path: event.path, reason: event.reason });
    for (const replica of this.#replicas.values()) {
      // R07: a withdrawn replica still watches for its replacement boot; a terminal one does not.
      if (replica.retired || replica.phase === "failed") continue;
      this.#triggerReattest(replica, "scheduler_unknown_key", false);
    }
  }

  // --- install helpers -----------------------------------------------------

  #triggerReattest(replica: ReplicaRuntime, reason: string, clear: boolean): void {
    replica.reattestRequested = true;
    replica.reattestReason = reason;
    if (clear) this.#clearForNewBoot(replica);
    replica.phase = "attesting";
    this.#refreshKeys();
  }

  #clearForNewBoot(replica: ReplicaRuntime): void {
    replica.checked = null;
    // A new boot may run another release: its version is learned from its own first call.
    replica.schedulerApiVersion = null;
    replica.keysetDigest = null;
    replica.tlsSpkiSha256 = null;
    replica.composeHash = null;
    replica.osImageHash = null;
    replica.relayImage = null;
    replica.policyInstalled = false;
    replica.policyVersion = null;
    replica.credentialVersion = null;
    replica.resealRequested = false;
    replica.installed.clear();
    replica.leaseExpiresAtSecs = null;
    replica.leaseExpiresAtMs = null;
    replica.lastUploadMono = null;
    this.#pool.clearReplica(replica.origin);
    this.#refreshKeys();
  }

  // --- configured origins (R28) -------------------------------------------

  /**
   * R28: retire every origin a previous start had configured and this config no longer names. One
   * attempt per backoff; after `lease_lifetime` without a successful revoke the origin is dropped
   * anyway (its old credentials then end with their lease). The new origin list is persisted once
   * every retirement is resolved.
   */
  async #processRetirements(): Promise<void> {
    if (this.#retirements.size === 0) {
      // No removal: adopt the list in memory only. The next ledger write persists it, so a start
      // never blocks on an extra state write (and a lost file is not recreated just for this).
      this.#adoptConfiguredOrigins(false);
      return;
    }
    const mono = this.#options.clock.monoMs();
    const leaseMs = this.#config.leaseLifetimeSeconds * 1000;
    for (const [origin, entry] of [...this.#retirements]) {
      if (mono < entry.nextMono) continue;
      // Attestation needs the signed list to pin; the first tick fetches it. Do not spend an
      // attempt (or start the lease-lifetime clock) before there is anything to attest against.
      if (this.#releases.list === null) break;
      if (mono - entry.firstMono > leaseMs) {
        this.#retirements.delete(origin);
        this.#log({ level: "warn", event: "replica_retire_abandoned", origin, attempts: entry.attempts });
        continue;
      }
      if (await this.#retireRemovedOrigin(origin)) {
        this.#retirements.delete(origin);
        this.#log({ level: "info", event: "replica_retired_removed_origin", origin });
        continue;
      }
      entry.attempts += 1;
      const delay = Math.min(60_000, 1_000 * 2 ** Math.min(entry.attempts - 1, 6));
      entry.nextMono = mono + delay;
      this.#log({ level: "warn", event: "replica_retire_failed", origin, attempts: entry.attempts, retry_in_ms: delay });
    }
    await this.#adoptConfiguredOrigins(true);
  }

  /**
   * R28: verify a removed origin and send it the signed whole-relay revoke. The temporary replica is
   * never supervised: it receives no policy and no credential bundle, only the revocation.
   */
  async #retireRemovedOrigin(origin: string): Promise<boolean> {
    const release = this.#releases.list;
    if (release === null) return false;
    const nowSecs = BigInt(Math.floor(this.#options.clock.wallMs() / 1000));
    let result: DaemonAttestResult;
    try {
      result = await this.#options.attest({ origin, release, nowSecs });
    } catch {
      return false;
    }
    if (!result.ok || result.checked.file.origin !== origin) return false;
    const replica = this.#newReplica(origin);
    replica.checked = result.checked;
    replica.keysetDigest = result.keysetDigest;
    replica.tlsSpkiSha256 = result.tlsSpkiSha256;
    replica.composeHash = result.composeHash;
    replica.osImageHash = result.osImageHash;
    await this.#withdraw(replica, "config_removed");
    return true;
  }

  /**
   * Record the current config's origin list once no retirement is outstanding (R28). `persist` is
   * false at start when nothing was removed: adopting in memory is enough, and the next ledger
   * write carries the member without an extra blocking write.
   */
  async #adoptConfiguredOrigins(persist: boolean): Promise<void> {
    if (this.#retirements.size > 0) return;
    const previous = this.#state.configuredOrigins ?? [];
    if (previous.length === this.#configuredOrigins.length && previous.every((origin, index) => origin === this.#configuredOrigins[index])) return;
    const next: DaemonState = { ...this.#state, configuredOrigins: [...this.#configuredOrigins] };
    if (!persist || !this.#stateIntact) {
      // A lost state file is not created just to record origins; the ledger's next write carries it.
      this.#state = next;
      return;
    }
    const previousState = this.#state;
    this.#state = next;
    try {
      await this.#writeState();
    } catch {
      this.#state = previousState;
    }
  }

  #pickEligible(account: SourceAccount): boolean {
    const now = this.#options.clock.wallMs();
    if (account.status === "active") return true;
    if (account.status !== "limited") return false;
    return account.limitedUntilMs !== undefined && now >= account.limitedUntilMs;
  }

  #renewalDue(replica: ReplicaRuntime, mono: number): boolean {
    if (replica.lastUploadMono === null || replica.leaseExpiresAtMs === null) return true;
    const leaseMs = this.#config.leaseLifetimeSeconds * 1000;
    return mono - replica.lastUploadMono >= leaseMs * this.#config.renewFraction;
  }

  #reportTooOld(replica: ReplicaRuntime): boolean {
    if (replica.checked === null) return false;
    const nowSecs = BigInt(Math.floor(this.#options.clock.wallMs() / 1000));
    const age = nowSecs - replica.checked.file.verifiedAt;
    if (age < 0n) return false;
    const limit = BigInt(Math.floor(this.#config.reportMaxAgeSeconds * REPORT_REFRESH_FRACTION));
    return age >= limit;
  }

  #isUsableServing(replica: ReplicaRuntime, wallMs: number): boolean {
    return replica.phase === "serving" && !replica.retired && replica.leaseExpiresAtMs !== null && replica.leaseExpiresAtMs > wallMs;
  }

  #replicaReasons(replica: ReplicaRuntime): readonly DaemonHealthReason[] {
    const reasons = new Set<DaemonHealthReason>();
    if (replica.phase === "release_pending") reasons.add(replica.composeHash === null ? "release_unpinned" : "release_pending");
    if (replica.alternating) reasons.add("origin_serves_two_boots");
    if (replica.unknownRelayStreak >= RELAY_UNKNOWN_THRESHOLD) reasons.add("relay_unknown");
    if ((replica.phase === "policy" || replica.phase === "credentials") && !replica.policyInstalled && this.#runsPolicy(replica)) reasons.add("policy_missing");
    if (replica.phase === "attesting" && replica.lastError !== null) reasons.add("attestation_failed");
    if (replica.leaseExpiresAtMs !== null && replica.leaseExpiresAtMs <= this.#options.clock.wallMs()) reasons.add("lease_expired");
    return [...reasons].sort() as DaemonHealthReason[];
  }

  #checkCredentialExpiry(): void {
    let expired = false;
    for (const replica of this.#replicas.values()) {
      for (const [accountId, installed] of replica.installed) {
        if (installed.expiresAtMs === null || installed.expiresAtMs > this.#options.clock.wallMs()) continue;
        const planned = this.#planned.get(accountId);
        if (planned === undefined || planned.account.changeMark !== installed.changeMark) continue;
        expired = true;
        const key = `${accountId}:${installed.changeMark}`;
        if (!this.#credentialExpiryAlerted.has(key)) {
          this.#credentialExpiryAlerted.add(key);
          this.#alert("credential_expired_unchanged", accountId);
        }
      }
    }
    this.#credentialExpiredUnchanged = expired;
  }

  // --- park, fail, alert ---------------------------------------------------

  #park(planned: PlannedAccount, reason: ParkReason): void {
    this.#parked.park(planned.accountId, planned.vendor, reason, planned.account.changeMark, planned.account.sourceId);
    this.#log({ level: "warn", event: "account_parked", account_id: planned.accountId, vendor: planned.vendor, reason });
  }

  #fail(replica: ReplicaRuntime, code: string, minDelayMs = 0): void {
    replica.failureStreak += 1;
    replica.lastError = code;
    const delay = Math.max(minDelayMs, Math.min(60_000, 1_000 * 2 ** Math.min(replica.failureStreak - 1, 6)));
    replica.nextAttemptMono = this.#options.clock.monoMs() + delay;
    this.#log({ level: "warn", event: "replica_step_failed", origin: replica.origin, code, retry_in_ms: delay });
  }

  #clearFailure(replica: ReplicaRuntime): void {
    replica.failureStreak = 0;
    replica.nextAttemptMono = 0;
    replica.lastError = null;
  }

  #versionFailure(error: unknown): void {
    if (error instanceof DaemonVersionError) {
      if (error.code === "second_writer") this.#raiseSecondWriter();
      if (error.code === "probe_exhausted") this.#versionProbeExhausted = true;
      this.#alert("version_stopped", error.code);
      return;
    }
    this.#alert("version_stopped", "persist_failed");
  }

  #alert(event: string, detail: string): void {
    const key = `${event}:${detail}`;
    if (this.#alerted.has(key)) return;
    this.#alerted.add(key);
    this.#alerts.push({ atMs: this.#options.clock.wallMs(), event, detail });
    while (this.#alerts.length > MAX_ALERTS) this.#alerts.shift();
    this.#log({ level: "error", event: "alert", alert: event, detail });
  }

  // --- HTTP and state ------------------------------------------------------

  async #get(replica: ReplicaRuntime, path: string) {
    return this.#request(`${replica.origin}${path}`, {
      method: "GET",
      headers: { accept: "application/json", "user-agent": "gray-relay-daemon/0" },
      ...(replica.tlsSpkiSha256 === null ? {} : { expectedSpkiSha256: replica.tlsSpkiSha256 }),
      ...this.#tunnelKeysetOf(replica),
      timeoutMs: 20_000,
    });
  }

  async #post(replica: ReplicaRuntime, path: string, body: string) {
    return this.#request(`${replica.origin}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", "user-agent": "gray-relay-daemon/0" },
      body: new TextEncoder().encode(body),
      ...(replica.tlsSpkiSha256 === null ? {} : { expectedSpkiSha256: replica.tlsSpkiSha256 }),
      ...this.#tunnelKeysetOf(replica),
      timeoutMs: 60_000,
    });
  }

  /**
   * A relay-stack replica reaches its own boot through the entry (`?keyset=`, docs/design/relay-zero-downtime.md). Only
   * a stack replica gets an address keyset, and it keeps it once it is no longer one: the whole-relay revoke of a boot
   * leaving supervision (a drained or dropped second replica, a removed or replaced instance) goes to that boot, not to
   * the entry's newest.
   */
  #tunnelKeysetOf(replica: ReplicaRuntime): { readonly tunnelKeyset?: string } {
    return replica.addressKeyset !== null && tunnelOriginOf(replica.origin) !== null ? { tunnelKeyset: replica.addressKeyset } : {};
  }

  async #request(url: string, init: Parameters<RelayDaemonOptions["fetch"]>[1]) {
    try {
      return await this.#options.fetch(url, init);
    } catch (error) {
      if (error instanceof DaemonTransportError) throw error;
      const code = this.#errorCode(error);
      throw new DaemonTransportError(code);
    }
  }

  #isPinFailure(error: unknown): boolean {
    return this.#errorCode(error) === "tls_spki_mismatch";
  }

  #errorCode(error: unknown): string {
    if (error instanceof DaemonTransportError) return error.code;
    if (error instanceof RelayKitError) return error.code;
    if (error instanceof RelayConnectorError) return error.code;
    if (error instanceof Error) {
      const withCode = error as Error & { readonly code?: unknown };
      if (typeof withCode.code === "string") return withCode.code;
      if (error.message.includes("tls_spki_mismatch")) return "tls_spki_mismatch";
      return error.name;
    }
    return "error";
  }

  async #writeState(): Promise<void> {
    const run = this.#stateWriteTail.then(async () => {
      await this.#options.stateStore.write(this.#state);
    });
    this.#stateWriteTail = run.then(
      () => undefined,
      () => undefined,
    );
    await run;
    // From here the file exists and holds `#state`; a later configured-origin adoption may write it.
    this.#stateIntact = true;
  }

  #log(event: DaemonLogEvent): void {
    try {
      this.#options.log(event);
    } catch {
      // A logging failure must never change a supervision decision.
    }
  }

  #plannedSorted(): readonly PlannedAccount[] {
    return [...this.#planned.values()].sort((left, right) => left.accountId.localeCompare(right.accountId));
  }

  #sourceSignal(): AbortSignal {
    // The source adapter owns its own I/O timeout; the daemon deliberately starts no timer here,
    // so the injected step scheduler is the only time source in a test.
    return new AbortController().signal;
  }

  #newReplica(origin: string, binding: LaneBinding | null = this.#config.lane.instances.get(origin) ?? null): ReplicaRuntime {
    return {
      origin,
      binding,
      queue: new ReplicaQueue(),
      phase: "unknown",
      checked: null,
      keysetDigest: null,
      tlsSpkiSha256: null,
      composeHash: null,
      osImageHash: null,
      relayImage: null,
      policyInstalled: false,
      policyVersion: null,
      credentialVersion: null,
      installed: new Map(),
      leaseExpiresAtSecs: null,
      leaseExpiresAtMs: null,
      lastUploadMono: null,
      lastPushAtMs: null,
      lastHealthzMono: Number.NEGATIVE_INFINITY,
      observedDigests: [],
      digestChanges: 0,
      alternating: false,
      reattestRequested: false,
      reattestReason: null,
      resealRequested: false,
      nextAttemptMono: 0,
      failureStreak: 0,
      unknownRelayStreak: 0,
      lastError: null,
      terminal: false,
      retired: false,
      schedulerApiVersion: null,
      addressKeyset: null,
    };
  }
}

/** The one constructor: parse config, verify the policy bundle, build the handler. */
export function createRelayDaemon(options: RelayDaemonOptions): RelayDaemon {
  return new RelayDaemonImpl(options);
}

// --- helpers ---------------------------------------------------------------

function decodeJson(body: Uint8Array): Json | null {
  try {
    return parseStrict(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body));
  } catch {
    return null;
  }
}

/** The one shape a lane refusal code may have: lower-case, digits, underscore, at most 64. */
export const REFUSAL_CODE = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * The refusal code of a non-2xx answer, or null for a 2xx. Both lane body shapes are accepted.
 * R26: remote text is echoed nowhere unless it is a plausible closed code; anything else becomes
 * `http_<status>`, which also routes 5xx/429 into the transient rule (R06).
 */
export function refusalCode(response: { readonly status: number; readonly body: Uint8Array }): string | null {
  if (response.status >= 200 && response.status < 300) return null;
  const value = decodeJson(response.body);
  if (isObject(value)) {
    const error = value["error"];
    if (typeof error === "string" && REFUSAL_CODE.test(error)) return error;
    if (isObject(error)) {
      const code = error["code"];
      if (typeof code === "string" && REFUSAL_CODE.test(code)) return code;
    }
  }
  return `http_${response.status}`;
}

/** R04: a source error that names one account, so the rest of the bundle can still install. */
export function isPerAccountSourceError(error: unknown): boolean {
  return error instanceof RelayKitError && (error.code === "source_not_found" || error.code === "source_shape_changed");
}

/** P12: whether two named instances are the same app at the same origin with the same KMS. */
/** A keyset digest as the entry names it in `?keyset=`: 64 hex, without `sha256:`. */
function bareKeyset(digest: string): string {
  return digest.startsWith("sha256:") ? digest.slice("sha256:".length) : digest;
}

/** The boots of the entry's boots-route answer for `relayId`, newest first; none for an answer of another shape. */
export function bootRowsOf(value: Json, relayId: string): { readonly keyset: string; readonly appId: string | null }[] {
  if (!isObject(value) || value.relay_id !== relayId || !Array.isArray(value.boots)) return [];
  const out: { keyset: string; appId: string | null }[] = [];
  for (const row of value.boots) {
    if (!isObject(row) || typeof row.keyset !== "string" || !/^[0-9a-f]{64}$/.test(row.keyset)) return [];
    const appId = typeof row.app_id === "string" && /^[0-9a-f]{40}$/.test(row.app_id) ? row.app_id : null;
    out.push({ keyset: row.keyset, appId });
  }
  return out;
}

function sameStackInstance(left: StackInstanceValues, right: StackInstanceValues): boolean {
  return left.laneOrigin === right.laneOrigin && sameBinding(left, right);
}

function sameBinding(left: LaneBinding, right: LaneBinding): boolean {
  return left.appId === right.appId && left.kmsCaPubkey === right.kmsCaPubkey;
}

function bindingOf(instance: LaneBinding): LaneBinding {
  return { appId: instance.appId, kmsCaPubkey: instance.kmsCaPubkey };
}

/** One header by name, case-insensitively, from the daemon's response shape. */
export function headerValue(response: { readonly headers: Readonly<Record<string, string | string[] | undefined>> }, name: string): string | null {
  const wanted = name.toLowerCase();
  for (const key of Object.keys(response.headers)) {
    if (key.toLowerCase() !== wanted) continue;
    const value = response.headers[key];
    if (value === undefined) return null;
    return Array.isArray(value) ? (value[0] ?? null) : value;
  }
  return null;
}

function sameVersion(value: Json, expected: bigint): boolean {
  if (typeof value === "bigint") return value === expected;
  if (typeof value === "number") return Number.isSafeInteger(value) && BigInt(value) === expected;
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    try {
      return BigInt(value) === expected;
    } catch {
      return false;
    }
  }
  return false;
}

function requiredString(value: JsonObject, member: string): string {
  const found = value[member];
  if (typeof found !== "string") throw new RelayKitError("invalid_policy_bundle", member);
  return found;
}
