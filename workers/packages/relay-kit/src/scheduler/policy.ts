/**
 * The reference scheduler's policy: a small, in-memory pool with weighted round-robin per
 * vendor/model, cool-downs learned from the TEE's outcome reports, an operator reset, and in-flight
 * slots held as time-bounded leases.
 *
 * This is deliberately not a production pool manager. It exists so a relay can see the scheduler
 * protocol work end to end and so this package can test the TEE's client against a real server; a
 * production relay keeps its account-pool logic (ban detection, subscription renewal, regional
 * fairness, persistence) on its own systems and implements the same three routes.
 *
 * Rules, in one place:
 *
 * - A pick considers only accounts of the requested vendor that the asking replica has installed,
 *   that list the model (or `"*"`), that are enabled, not cooling down, under `max_concurrency`,
 *   and not already tried for this request.
 * - Among the eligible ones the choice is smooth weighted round-robin (nginx's algorithm) **per
 *   vendor and model**, not globally: a burst of Claude requests must not starve GPT accounts, and a
 *   shared pool that serves two models must rotate independently for each.
 * - `rate_limited` and `overloaded` start a cool-down; `retry_after_ms` from the report wins over the
 *   configured default when it is present (the TEE's `OutcomeReport` cannot carry one today — see
 *   IMPLEMENTATION_NOTES, “needed changes in @gray/relay-connector”).
 * - `auth_failed` and `quota_exhausted` disable the account until the operator resets it. With a
 *   per-replica installation map, a report is applied only to an account installed on the asking
 *   replica (D50): an entry naming another replica's account changes nothing, is not counted as
 *   accepted, and is counted in the answer's `rejected` field with the fixed reason
 *   `not_installed`. Without a per-replica map (the single-report reference case), a report for an
 *   account that is not configured is accepted and otherwise ignored: the TEE may still hold an
 *   account this relay removed.
 * - An optional `affinity` token keeps its account while that account is eligible and the token is
 *   inside the idle TTL; otherwise the normal pick runs and the token is rebound to the new
 *   account. The map is in memory, LRU-bounded, and never appears on a status or log surface.
 * - Every pick creates one in-flight **lease**, kept under the pick's `request_ref` and the asking
 *   replica as well as its account. A report frees the lease its `request_ref` names (D116): an
 *   account report then applies its outcome as below, and a lost pick's release (`not_sent`, D111)
 *   changes nothing else. Only a report without a ref (a TEE from before D116) frees by account: the
 *   oldest lease the asking replica made on it. A lease is the leasing replica's own (D50): another
 *   replica's report naming its ref changes nothing and is counted in `rejected`, and its ref-less
 *   report never frees it; a ref no live lease holds (already reported, expired) frees nothing, and
 *   an account report naming one still applies its outcome. A lease also
 *   expires after `inflightTtlMs`, so a lost report or a TEE crash between pick and report cannot
 *   leak a slot for the life of the process. Explicitly abandoning a request can call `release`.
 * - `setAccounts(snapshot)` replaces the known accounts and the per-replica installation map in one
 *   step. Accounts that remain keep their cool-down, disabled state, round-robin weight and live
 *   leases; removed accounts are forgotten and can no longer be picked.
 */
import {
  DEFAULT_OUTCOME_COOLDOWNS_MS,
  type LeaseTable,
  type Outcome,
  type PickDecision,
  type PickRequest,
  type Vendor,
} from "@gray/relay-connector";

/** One pool account as the scheduler knows it: metadata only, never a credential. */
export interface SchedulerAccount {
  readonly accountId: string;
  readonly vendor: Vendor;
  /** Exact public model ids this account serves, or `"*"` for every model of its vendor. */
  readonly models: readonly string[];
  readonly weight: bigint;
  readonly maxConcurrency: bigint;
}

/** One outcome as the scheduler applies it; `retryAfterMs` is the optional wire extension. */
export interface SchedulerOutcomeReport {
  /** The account a normal outcome names; absent on a lost pick's release (D111). */
  readonly account_id?: string;
  /** The pick's request_ref, its lease key (D116): a report naming it frees exactly that lease. */
  readonly request_ref?: string;
  readonly outcome: Outcome;
  readonly retry_after_ms?: bigint;
}

/**
 * The reference scheduler's answer to a report batch. `accepted` is what the signed v1 wire answer
 * carries; `rejected` exists only when at least one entry was refused, so an all-own batch keeps
 * the exact `{accepted}` answer it always had. D50's one fixed reason is `not_installed`.
 */
export interface SchedulerReportAnswer {
  readonly accepted: bigint;
  /** Entries naming an account not installed on the asking replica; absent when zero. */
  readonly rejected?: bigint;
  /** Present exactly with `rejected`. */
  readonly reason?: "not_installed";
}

/** The state an operator or a test may read for one account (never a credential). */
export interface SchedulerAccountState {
  readonly disabled: boolean;
  readonly disabledBy: Outcome | null;
  readonly cooldownUntilMs: number;
  readonly inFlight: number;
}

/** The accounts one replica holds: what the daemon wrote into the TEE's credential store. */
export interface SchedulerReplicaAccounts {
  readonly replicaId: string;
  readonly accountIds: readonly string[];
}

/**
 * What `setAccounts` replaces: every account the relay knows, plus which of them each replica has
 * installed. `replicas` omitted means "every account is installed on every replica", the standalone
 * reference scheduler's single-report case; a daemon with several boots passes the exact map.
 */
export interface SchedulerAccountsSnapshot {
  readonly accounts: readonly SchedulerAccount[];
  readonly replicas?: readonly SchedulerReplicaAccounts[];
}

/**
 * The interface the handler needs from a pool, so a relay can plug in its own picker without
 * subclassing `ReferenceScheduler` (whose private fields make the class nominal).
 *
 * `pick` must only return accounts `accountsFor(replicaId)` names; the handler also checks that and
 * fails closed with `unavailable` if a pool ever violates it. `report` applies metadata outcomes and
 * releases one lease per report, only for accounts installed on the asking replica; a foreign entry
 * changes nothing, is not accepted, and is counted in the answer's `rejected` field (D50). `release`
 * frees one lease early when a request is abandoned before its outcome. `leaseTable` serves the
 * signed fallback table, restricted to the asking replica.
 */
export interface SchedulerPool {
  pick(request: PickRequest, replicaId: string): PickDecision;
  report(reports: readonly SchedulerOutcomeReport[], replicaId: string): SchedulerReportAnswer;
  release(replicaId: string, accountId: string): boolean;
  accountsFor(replicaId: string): readonly string[];
  leaseTable(replicaId: string): LeaseTable;
  reset(accountId: string): number;
}

/** The largest `retry_after_ms` a report may ask for: one day. */
export const MAX_RETRY_AFTER_MS = 24n * 60n * 60n * 1000n;

/** How long one pick's in-flight slot is held without a report: the connector's lease default. */
export const DEFAULT_INFLIGHT_TTL_MS = 10 * 60_000;

/** The shortest and longest accepted in-flight lease; configuration bounds use these. */
export const MIN_INFLIGHT_TTL_MS = 1_000;
export const MAX_INFLIGHT_TTL_MS = 24 * 60 * 60_000;

/** How long an idle conversation stays on one account by default: 60 minutes. */
export const DEFAULT_AFFINITY_TTL_MS = 60 * 60_000;
/** The shortest and longest accepted affinity TTL: 1 minute to 720 minutes (12 hours). */
export const MIN_AFFINITY_TTL_MS = 60_000;
export const MAX_AFFINITY_TTL_MS = 720 * 60_000;
/** The derived affinity cap: this many conversations per pooled account, evicted least-recently-used. */
export const DEFAULT_AFFINITY_CAP_FACTOR = 4;
/** The largest configurable affinity cap. */
export const MAX_AFFINITY_CAP = 1_000_000;

export interface ReferenceSchedulerOptions {
  readonly accounts: readonly SchedulerAccount[];
  /** The initial per-replica installation map; omitted means every account on every replica. */
  readonly replicas?: readonly SchedulerReplicaAccounts[];
  readonly now: () => number;
  /** Cool-down for a `rate_limited` report without `retry_after_ms`. */
  readonly rateLimitedMs?: number;
  /** Cool-down for an `overloaded` report without `retry_after_ms`. */
  readonly overloadedMs?: number;
  /** How long a pick asks the caller to wait when the only obstacle is concurrency. */
  readonly busyRetryMs?: number;
  /** How long a generated lease table is valid. */
  readonly leaseTtlSeconds?: number;
  /** How long one in-flight pick lease lasts without a report. Default 10 minutes. */
  readonly inflightTtlMs?: number;
  /** How long an idle affinity binding lasts. Default 60 minutes; the range is 1-720 minutes. */
  readonly affinityTtlMs?: number;
  /** The affinity map cap. Default `max(1, accounts x 4)`; oldest bindings are evicted first. */
  readonly affinityCap?: number;
}

interface MutableState {
  disabled: boolean;
  disabledBy: Outcome | null;
  cooldownUntilMs: number;
}

/** One in-flight pick: its account, the replica that asked, its request_ref and when it stops holding a slot. */
interface InflightLease {
  readonly accountId: string;
  /** The asking replica (D50, D116); null for a direct library pick that named none. */
  readonly replicaId: string | null;
  readonly requestRef: string;
  readonly expiresAtMs: number;
}

/** One conversation-to-account binding; `expiresAtMs` is refreshed on every sticky pick. */
interface AffinityBinding {
  readonly accountId: string;
  readonly expiresAtMs: number;
}

export class ReferenceScheduler implements SchedulerPool {
  #accounts: readonly SchedulerAccount[];
  #byId = new Map<string, SchedulerAccount>();
  readonly #states = new Map<string, MutableState>();
  readonly #weights = new Map<string, bigint>();
  /** account id → its live leases, oldest first. */
  readonly #leases = new Map<string, InflightLease[]>();
  /** request_ref → the lease the pick made, for an exact release by the pick's report (D111, D116). */
  readonly #leaseRefs = new Map<string, InflightLease>();
  /** affinity token → account, in least-recently-used-first order. */
  readonly #affinity = new Map<string, AffinityBinding>();
  #installed: Map<string, Set<string>> | null;
  readonly #now: () => number;
  readonly #rateLimitedMs: number;
  readonly #overloadedMs: number;
  readonly #busyRetryMs: number;
  readonly #leaseTtlSeconds: number;
  readonly #inflightTtlMs: number;
  readonly #affinityTtlMs: number;
  readonly #affinityCapExplicit: boolean;
  #affinityCap: number;
  #leaseVersion = 0n;

  constructor(options: ReferenceSchedulerOptions) {
    this.#now = options.now;
    this.#rateLimitedMs = options.rateLimitedMs ?? DEFAULT_OUTCOME_COOLDOWNS_MS.rate_limited;
    this.#overloadedMs = options.overloadedMs ?? DEFAULT_OUTCOME_COOLDOWNS_MS.overloaded;
    this.#busyRetryMs = options.busyRetryMs ?? 250;
    this.#leaseTtlSeconds = options.leaseTtlSeconds ?? 60;
    this.#inflightTtlMs = options.inflightTtlMs ?? DEFAULT_INFLIGHT_TTL_MS;
    if (!Number.isSafeInteger(this.#inflightTtlMs) || this.#inflightTtlMs < MIN_INFLIGHT_TTL_MS || this.#inflightTtlMs > MAX_INFLIGHT_TTL_MS) {
      throw new RangeError(`inflightTtlMs must be an integer in [${MIN_INFLIGHT_TTL_MS}, ${MAX_INFLIGHT_TTL_MS}]`);
    }
    this.#affinityTtlMs = options.affinityTtlMs ?? DEFAULT_AFFINITY_TTL_MS;
    if (!Number.isSafeInteger(this.#affinityTtlMs) || this.#affinityTtlMs < MIN_AFFINITY_TTL_MS || this.#affinityTtlMs > MAX_AFFINITY_TTL_MS) {
      throw new RangeError(`affinityTtlMs must be an integer in [${MIN_AFFINITY_TTL_MS}, ${MAX_AFFINITY_TTL_MS}]`);
    }
    const affinityCap = options.affinityCap;
    if (affinityCap !== undefined && (!Number.isSafeInteger(affinityCap) || affinityCap < 1 || affinityCap > MAX_AFFINITY_CAP)) {
      throw new RangeError(`affinityCap must be an integer in [1, ${MAX_AFFINITY_CAP}]`);
    }
    this.#affinityCapExplicit = affinityCap !== undefined;
    this.#accounts = this.#validatedAccounts(options.accounts);
    this.#affinityCap = affinityCap ?? deriveAffinityCap(this.#accounts.length);
    for (const account of this.#accounts) this.#byId.set(account.accountId, account);
    this.#installed = this.#validatedInstalled(options.replicas ?? null, this.#byId);
    for (const account of this.#accounts) {
      this.#states.set(account.accountId, { disabled: false, disabledBy: null, cooldownUntilMs: 0 });
    }
  }

  /** The configured accounts, in configuration order. */
  get accounts(): readonly SchedulerAccount[] {
    return this.#accounts;
  }

  /**
   * Replace the pool in one step. Every member is validated before anything changes, so a refused
   * snapshot leaves the previous accounts, state and leases exactly as they were.
   */
  setAccounts(snapshot: SchedulerAccountsSnapshot): void {
    const accounts = this.#validatedAccounts(snapshot.accounts);
    const byId = new Map(accounts.map((account) => [account.accountId, account]));
    const installed = this.#validatedInstalled(snapshot.replicas ?? null, byId);
    // Only now is the snapshot known good; replace each map in place so an object a caller already
    // holds keeps observing the current pool.
    this.#accounts = accounts;
    this.#byId = byId;
    for (const account of accounts) {
      if (this.#states.has(account.accountId)) continue;
      this.#states.set(account.accountId, { disabled: false, disabledBy: null, cooldownUntilMs: 0 });
    }
    for (const accountId of [...this.#states.keys()]) {
      if (byId.has(accountId)) continue;
      this.#states.delete(accountId);
      for (const lease of this.#leases.get(accountId) ?? []) this.#forgetRef(lease);
      this.#leases.delete(accountId);
      for (const key of [...this.#weights.keys()]) {
        if (key.startsWith(`${accountId}\u0000`)) this.#weights.delete(key);
      }
    }
    this.#installed = installed;
    if (!this.#affinityCapExplicit) this.#affinityCap = deriveAffinityCap(accounts.length);
    for (const [token, binding] of [...this.#affinity]) {
      if (!byId.has(binding.accountId)) this.#affinity.delete(token);
    }
    this.#pruneAffinity(this.#now());
    this.#evictAffinity();
  }

  /** The account ids the given replica holds; every account when no per-replica map is configured. */
  accountsFor(replicaId: string): readonly string[] {
    if (this.#installed === null) return this.#accounts.map((account) => account.accountId);
    return [...(this.#installed.get(replicaId) ?? [])];
  }

  /** One signed pick: an account id, a wait, or unavailable. */
  pick(request: PickRequest, replicaId?: string): PickDecision {
    const nowMs = this.#now();
    this.#reap(nowMs);
    this.#pruneAffinity(nowMs);
    const affinity = request.affinity;
    const bound = affinity === undefined ? null : this.#lookupAffinity(affinity);
    const installed = replicaId === undefined || this.#installed === null ? null : (this.#installed.get(replicaId) ?? new Set<string>());
    const tried = new Set(request.previous.map((attempt) => attempt.account_id));
    const eligible: SchedulerAccount[] = [];
    let retryAt = Number.POSITIVE_INFINITY;
    for (const account of this.#accounts) {
      if (installed !== null && !installed.has(account.accountId)) continue;
      if (account.vendor !== request.vendor) continue;
      if (!servesModel(account, request.model)) continue;
      if (tried.has(account.accountId)) continue;
      const state = this.#states.get(account.accountId) as MutableState;
      if (state.disabled) continue;
      if (state.cooldownUntilMs > nowMs) {
        retryAt = Math.min(retryAt, state.cooldownUntilMs);
        continue;
      }
      const inFlight = this.#leases.get(account.accountId)?.length ?? 0;
      if (BigInt(inFlight) >= account.maxConcurrency) {
        retryAt = Math.min(retryAt, nowMs + this.#busyRetryMs);
        continue;
      }
      eligible.push(account);
    }
    if (eligible.length === 0) {
      if (Number.isFinite(retryAt)) {
        return { kind: "retry_after", retry_after_ms: BigInt(Math.max(1, Math.ceil(retryAt - nowMs))) };
      }
      return { kind: "unavailable" };
    }
    if (bound !== null && affinity !== undefined) {
      const sticky = eligible.find((account) => account.accountId === bound);
      if (sticky !== undefined) {
        this.#lease(sticky.accountId, request.request_ref, replicaId ?? null, nowMs);
        this.#bindAffinity(affinity, sticky.accountId, nowMs);
        return { kind: "account", account_id: sticky.accountId };
      }
    }
    const selected = this.#weighted(eligible, `${request.vendor}\u0000${request.model}`);
    this.#lease(selected.accountId, request.request_ref, replicaId ?? null, nowMs);
    if (affinity !== undefined) this.#bindAffinity(affinity, selected.accountId, nowMs);
    return { kind: "account", account_id: selected.accountId };
  }

  /**
   * Apply outcome reports in order. With a per-replica installation map, an entry is applied only
   * when its account is installed on the asking replica (D50); every other entry is refused before
   * it can release a lease or change state, and is counted in `rejected`. A `request_ref` is the
   * pick's lease key, never a release switch (D116): an account report naming one frees that lease
   * and still applies its outcome.
   */
  report(reports: readonly SchedulerOutcomeReport[], replicaId?: string): SchedulerReportAnswer {
    const nowMs = this.#now();
    this.#reap(nowMs);
    // `null` means "no restriction": no per-replica map (the standalone reference case) or no
    // replica id (a direct library call from before this parameter existed). The pool interface and
    // the handler always pass the authenticated asking replica, so the wire path is exact.
    const installed = this.#installed === null || replicaId === undefined ? null : (this.#installed.get(replicaId) ?? new Set<string>());
    let accepted = 0;
    let rejected = 0;
    for (const report of reports) {
      const accountId = report.account_id;
      if (accountId !== undefined && installed !== null && !installed.has(accountId)) {
        rejected += 1;
        continue;
      }
      const ref = report.request_ref;
      const lease = ref === undefined ? undefined : this.#leaseRefs.get(ref);
      // D50, D116: a ref is the leasing replica's own. Another replica's report naming it changes
      // nothing, so a TEE can never free (or cool down through) a pick another replica made.
      if (lease !== undefined && replicaId !== undefined && lease.replicaId !== replicaId) {
        rejected += 1;
        continue;
      }
      if (accountId === undefined) {
        // D111: a lost pick's release names only its ref (the TEE never learned the account). It
        // frees that lease, if one still holds it, and changes no state: no vendor saw the account.
        if (ref === undefined || report.outcome !== "not_sent") {
          rejected += 1;
          continue;
        }
        accepted += 1;
        if (lease !== undefined) this.#releaseLease(lease);
        continue;
      }
      accepted += 1;
      const account = this.#byId.get(accountId);
      if (account === undefined) continue;
      if (ref === undefined) {
        // A TEE from before D116 names no lease: free the account's oldest one that the asking
        // replica made (D50), so in a fleet whose TEEs run both versions a ref-less report never
        // takes the lease another replica's keyed report will name.
        this.#releaseOne(accountId, replicaId);
      } else if (lease !== undefined && lease.accountId === accountId) {
        // D116: exactly the lease this outcome ends; never another pick's, so a ref no live lease
        // holds frees nothing rather than the account's oldest slot.
        this.#releaseLease(lease);
      }
      // A release (`not_sent`) never cools or disables: it is the only release-only outcome.
      const state = this.#states.get(account.accountId) as MutableState;
      if (report.outcome === "rate_limited" || report.outcome === "overloaded") {
        const configured = report.outcome === "rate_limited" ? this.#rateLimitedMs : this.#overloadedMs;
        const asked = clampRetryAfter(report.retry_after_ms);
        const delay = asked === null ? configured : asked;
        state.cooldownUntilMs = Math.max(state.cooldownUntilMs, nowMs + delay);
      } else if (report.outcome === "auth_failed" || report.outcome === "quota_exhausted") {
        state.disabled = true;
        state.disabledBy = report.outcome;
      }
    }
    return rejected === 0
      ? { accepted: BigInt(accepted) }
      : { accepted: BigInt(accepted), rejected: BigInt(rejected), reason: "not_installed" };
  }

  /**
   * Release one in-flight lease without recording an outcome (a request abandoned before its
   * report). The lease expiry is the safety net; this is the precise path. With a `replicaId` the
   * lease is that replica's own oldest one (D50, D116; D120 F1): a replica can never free a lease
   * another replica made, so that replica's later keyed report still finds its lease.
   */
  release(replicaId: string, accountId: string): boolean;
  release(accountId: string): boolean;
  release(first: string, second?: string): boolean {
    const accountId = second ?? first;
    const replicaId = second === undefined ? undefined : first;
    this.#reap(this.#now());
    if (!this.#byId.has(accountId)) return false;
    return this.#releaseOne(accountId, replicaId);
  }

  /**
   * The lease table the TEE keeps as a fallback. It is generated fresh on every pull, so every pull
   * has a strictly greater version (the TEE's `LeaseTablePicker` refuses a non-increasing one) and a
   * new expiry. Disabled and cooling-down accounts are left out: the fallback must not pick them.
   * With a `replicaId`, only the accounts that replica holds are listed.
   */
  leaseTable(replicaId?: string): LeaseTable {
    const nowMs = this.#now();
    this.#reap(nowMs);
    const nowSecs = BigInt(Math.floor(nowMs / 1000));
    this.#leaseVersion += 1n;
    const installed = replicaId === undefined || this.#installed === null ? null : (this.#installed.get(replicaId) ?? new Set<string>());
    const accounts = this.#accounts
      .filter((account) => {
        if (installed !== null && !installed.has(account.accountId)) return false;
        const state = this.#states.get(account.accountId) as MutableState;
        return !state.disabled && state.cooldownUntilMs <= nowMs;
      })
      .map((account) => ({
        account_id: account.accountId,
        vendor: account.vendor,
        models: [...account.models],
        weight: account.weight,
        max_concurrency: account.maxConcurrency,
      }));
    return { version: this.#leaseVersion, expires_at: nowSecs + BigInt(this.#leaseTtlSeconds), accounts };
  }

  /**
   * Re-enable one account (or every account with `"*"`) and clear its cool-down. Returns how many
   * accounts changed state. In-flight leases are left alone: the requests that hold them are still
   * running and will release them with their reports (or their expiry).
   */
  reset(accountId: string): number {
    let changed = 0;
    const targets = accountId === "*" ? [...this.#states.keys()] : this.#byId.has(accountId) ? [accountId] : [];
    for (const id of targets) {
      const state = this.#states.get(id) as MutableState;
      if (state.disabled || state.cooldownUntilMs !== 0) changed += 1;
      state.disabled = false;
      state.disabledBy = null;
      state.cooldownUntilMs = 0;
    }
    return changed;
  }

  /** A read-only view of one account's state, for the operator and the tests. */
  stateOf(accountId: string): SchedulerAccountState | null {
    this.#reap(this.#now());
    const state = this.#states.get(accountId);
    if (state === undefined) return null;
    return {
      disabled: state.disabled,
      disabledBy: state.disabledBy,
      cooldownUntilMs: state.cooldownUntilMs,
      inFlight: this.#leases.get(accountId)?.length ?? 0,
    };
  }

  #validatedAccounts(accounts: readonly SchedulerAccount[]): readonly SchedulerAccount[] {
    const ids = new Set<string>();
    for (const account of accounts) {
      if (ids.has(account.accountId)) throw new Error(`duplicate scheduler account ${account.accountId}`);
      ids.add(account.accountId);
    }
    return [...accounts];
  }

  #validatedInstalled(replicas: readonly SchedulerReplicaAccounts[] | null, byId: ReadonlyMap<string, SchedulerAccount>): Map<string, Set<string>> | null {
    if (replicas === null) return null;
    const installed = new Map<string, Set<string>>();
    for (const replica of replicas) {
      if (installed.has(replica.replicaId)) throw new Error(`duplicate scheduler replica ${replica.replicaId}`);
      const ids = new Set(replica.accountIds);
      for (const accountId of ids) {
        if (!byId.has(accountId)) throw new Error(`replica ${replica.replicaId} names unknown account ${accountId}`);
      }
      installed.set(replica.replicaId, ids);
    }
    return installed;
  }

  #weighted(eligible: readonly SchedulerAccount[], key: string): SchedulerAccount {
    let total = 0n;
    for (const account of eligible) {
      const weightKey = `${account.accountId}\u0000${key}`;
      this.#weights.set(weightKey, (this.#weights.get(weightKey) ?? 0n) + account.weight);
      total += account.weight;
    }
    let selected = eligible[0] as SchedulerAccount;
    let selectedWeight = this.#weights.get(`${selected.accountId}\u0000${key}`) as bigint;
    for (let index = 1; index < eligible.length; index += 1) {
      const account = eligible[index] as SchedulerAccount;
      const weight = this.#weights.get(`${account.accountId}\u0000${key}`) as bigint;
      if (weight > selectedWeight) {
        selected = account;
        selectedWeight = weight;
      }
    }
    this.#weights.set(`${selected.accountId}\u0000${key}`, selectedWeight - total);
    return selected;
  }

  /** Hold one in-flight slot for a pick, under its account and its request_ref, for the asking replica. */
  #lease(accountId: string, requestRef: string, replicaId: string | null, nowMs: number): void {
    const lease: InflightLease = { accountId, replicaId, requestRef, expiresAtMs: nowMs + this.#inflightTtlMs };
    const leases = this.#leases.get(accountId) ?? [];
    leases.push(lease);
    this.#leases.set(accountId, leases);
    this.#leaseRefs.set(requestRef, lease);
  }

  /** The account an affinity token is bound to, or null. Expired entries are pruned per pick. */
  #lookupAffinity(token: string): string | null {
    return this.#affinity.get(token)?.accountId ?? null;
  }

  /** Bind or rebind a token, move it to the most-recently-used end and refresh its idle TTL. */
  #bindAffinity(token: string, accountId: string, nowMs: number): void {
    this.#affinity.delete(token);
    this.#affinity.set(token, { accountId, expiresAtMs: nowMs + this.#affinityTtlMs });
    this.#evictAffinity();
  }

  /** Drop expired bindings from the front: insertion order is expiry order (one constant TTL). */
  #pruneAffinity(nowMs: number): void {
    for (const [token, binding] of this.#affinity) {
      if (binding.expiresAtMs > nowMs) break;
      this.#affinity.delete(token);
    }
  }

  /** Evict the least-recently-used bindings beyond the configured cap. */
  #evictAffinity(): void {
    while (this.#affinity.size > this.#affinityCap) {
      const oldest = this.#affinity.keys().next().value;
      if (oldest === undefined) break;
      this.#affinity.delete(oldest);
    }
  }

  /** Drop leases whose expiry has passed: the slot is reclaimed, never leaked for the process. */
  #reap(nowMs: number): void {
    for (const [accountId, leases] of this.#leases) {
      if (leases.length === 0) {
        this.#leases.delete(accountId);
        continue;
      }
      if ((leases[0] as InflightLease).expiresAtMs > nowMs) continue;
      const live = leases.filter((lease) => lease.expiresAtMs > nowMs);
      for (const lease of leases) {
        if (lease.expiresAtMs <= nowMs) this.#forgetRef(lease);
      }
      if (live.length === 0) this.#leases.delete(accountId);
      else this.#leases.set(accountId, live);
    }
  }

  /**
   * Free an account's oldest lease; with `replicaId`, its oldest lease that replica made (D50, D116).
   * Without one (a report or a one-argument `release` from a direct library call naming no replica),
   * any replica's.
   */
  #releaseOne(accountId: string, replicaId?: string): boolean {
    const leases = this.#leases.get(accountId);
    if (leases === undefined || leases.length === 0) return false;
    const index = replicaId === undefined ? 0 : leases.findIndex((lease) => lease.replicaId === replicaId);
    if (index < 0) return false;
    const [released] = leases.splice(index, 1) as [InflightLease];
    this.#forgetRef(released);
    if (leases.length === 0) this.#leases.delete(accountId);
    return true;
  }

  /** Free exactly one lease (D111, D116): the one a report's request_ref names. */
  #releaseLease(lease: InflightLease): void {
    this.#forgetRef(lease);
    const leases = this.#leases.get(lease.accountId);
    if (leases === undefined) return;
    const index = leases.indexOf(lease);
    if (index >= 0) leases.splice(index, 1);
    if (leases.length === 0) this.#leases.delete(lease.accountId);
  }

  /**
   * Drop a lease's ref from the index, only while the index still names this lease: a later pick that
   * reused the ref (a test's fixed ref) keeps its own entry when the older lease goes.
   */
  #forgetRef(lease: InflightLease): void {
    if (this.#leaseRefs.get(lease.requestRef) === lease) this.#leaseRefs.delete(lease.requestRef);
  }
}

/** The default affinity cap: four conversations per pooled account, at least one. */
export function deriveAffinityCap(accountCount: number): number {
  return Math.min(MAX_AFFINITY_CAP, Math.max(1, accountCount * DEFAULT_AFFINITY_CAP_FACTOR));
}

/** Whether an account serves `model` (a `"*"` entry serves every model). */
export function servesModel(account: SchedulerAccount, model: string): boolean {
  return account.models.includes("*") || account.models.includes(model);
}

/** A report's retry hint, clamped to the accepted range; null when absent or out of range. */
function clampRetryAfter(value: bigint | undefined): number | null {
  if (typeof value !== "bigint" || value < 1n || value > MAX_RETRY_AFTER_MS) return null;
  return Number(value);
}