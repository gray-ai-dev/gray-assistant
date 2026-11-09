/**
 * The scheduler's pool, wired to the source snapshot, the per-replica installed maps and the TEE's
 * outcome reports (design v2 §A.4, critique R2/R7/R15; the daemon's job in §A.5 item 7).
 *
 * `ReferenceScheduler` is reused unchanged for the weighted pick, cool-downs, concurrency leases and
 * lease table. This class owns the three facts the reference scheduler cannot know:
 *
 * - **Eligibility**: source status `banned`/`disabled` never enters a pick; `limited` enters only
 *   after `limitedUntilMs`. An account can stay sealed in the TEE and still be out of the pool; the
 *   filter is re-applied on every tick, so a limited account comes back on time, not on the next
 *   poll.
 * - **Exact installation**: a pick may only name an account the asking replica's accepted bundle
 *   carried. `setInstalled` is called after every accepted upload, and the reference scheduler gets
 *   the intersection as its `replicas` map.
 * - **`auth_failed` without write-back** (design v2 §A.9): the reference scheduler disables the
 *   account; this wrapper remembers the source `changeMark` at that instant and re-enables it only
 *   when the source says the account changed. No write reaches the relay's software.
 */
import type { Outcome, PickDecision, PickRequest, LeaseTable, Vendor } from "@gray/relay-connector";
import {
  ReferenceScheduler,
  type SchedulerAccount,
  type SchedulerAccountsSnapshot,
  type SchedulerOutcomeReport,
  type SchedulerPool,
  type SchedulerReportAnswer,
} from "../scheduler/policy.ts";
import { metadataParkReason, type ParkRegistry, type PlannedAccount } from "./eligibility.ts";

/** One planned account plus whether it may be picked now (status/time rules). */
export interface PoolAccount {
  readonly planned: PlannedAccount;
  readonly pickEligible: boolean;
}

export interface DaemonSchedulerPoolOptions {
  readonly now: () => number;
  readonly parked: ParkRegistry;
  readonly inflightTtlMs: number;
  readonly affinityTtlMs?: number;
  readonly affinityCap?: number;
  readonly rateLimitedMs: number;
  readonly overloadedMs: number;
}

export class DaemonSchedulerPool implements SchedulerPool {
  readonly #reference: ReferenceScheduler;
  readonly #now: () => number;
  readonly #parked: ParkRegistry;
  #accounts: readonly PlannedAccount[] = [];
  #eligible = new Map<string, boolean>();
  readonly #installed = new Map<string, Set<string>>();
  readonly #authFailedMarks = new Map<string, string>();
  #replicaOrder: string[] = [];

  constructor(options: DaemonSchedulerPoolOptions) {
    this.#now = options.now;
    this.#parked = options.parked;
    this.#reference = new ReferenceScheduler({
      accounts: [],
      replicas: [],
      now: options.now,
      inflightTtlMs: options.inflightTtlMs,
      ...(options.affinityTtlMs === undefined ? {} : { affinityTtlMs: options.affinityTtlMs }),
      ...(options.affinityCap === undefined ? {} : { affinityCap: options.affinityCap }),
      rateLimitedMs: options.rateLimitedMs,
      overloadedMs: options.overloadedMs,
    });
  }

  /** Replace the source-derived accounts and their pick eligibility, then rebuild the pool. */
  setSource(accounts: readonly PoolAccount[], replicaOrder: readonly string[]): void {
    this.#accounts = accounts.map((entry) => entry.planned);
    this.#eligible = new Map(accounts.map((entry) => [entry.planned.accountId, entry.pickEligible]));
    this.#replicaOrder = [...replicaOrder];
    for (const replicaId of replicaOrder) if (!this.#installed.has(replicaId)) this.#installed.set(replicaId, new Set());
    this.#dropAuthFailedWhereChanged();
    this.refresh();
  }

  /** The exact account ids a replica's last accepted bundle installed. */
  setInstalled(replicaId: string, accountIds: Iterable<string>): void {
    if (!this.#installed.has(replicaId)) this.#replicaOrder.push(replicaId);
    this.#installed.set(replicaId, new Set(accountIds));
    this.refresh();
  }

  /** Remove one account from a replica (after an accepted revoke). */
  uninstall(replicaId: string, accountId: string): void {
    this.#installed.get(replicaId)?.delete(accountId);
    this.refresh();
  }

  /** A replica that is gone (config removal or withdrawal) leaves the pick surface entirely. */
  removeReplica(replicaId: string): void {
    this.#installed.delete(replicaId);
    this.#replicaOrder = this.#replicaOrder.filter((id) => id !== replicaId);
    this.refresh();
  }

  /** Stop a boot from answering picks while keeping its accounts out of every other replica. */
  clearReplica(replicaId: string): void {
    this.#installed.set(replicaId, new Set());
    this.refresh();
  }

  /** How many accounts this replica may be picked for (status only). */
  installedCount(replicaId: string): number {
    return this.#installed.get(replicaId)?.size ?? 0;
  }

  /** The reference scheduler's own state, for `status()`; never a credential. */
  stateOf(accountId: string) {
    return this.#reference.stateOf(accountId);
  }

  // --- SchedulerPool -------------------------------------------------------

  pick(request: PickRequest, replicaId: string): PickDecision {
    return this.#reference.pick(request, replicaId);
  }

  report(reports: readonly SchedulerOutcomeReport[], replicaId: string): SchedulerReportAnswer {
    const answer = this.#reference.report(reports, replicaId);
    const current = new Map(this.#accounts.map((planned) => [planned.accountId, planned.account.changeMark]));
    // D50: the in-memory auth_failed exclusion is set only from a report for an account this
    // replica actually installed. The reference scheduler re-checks the same set and refuses the
    // entry; without this guard a foreign report would still leave a mark that survives a refresh.
    const installed = new Set(this.accountsFor(replicaId));
    for (const report of reports) {
      if (report.outcome !== "auth_failed" && report.outcome !== "quota_exhausted") continue;
      // A lost pick's release names no account (D111): it only frees a lease and never marks one.
      if (report.account_id === undefined) continue;
      if (!installed.has(report.account_id)) continue;
      // D116: the mark follows the reference scheduler's decision, so the two layers agree: an entry
      // it refused (another replica's lease key) left the account enabled and leaves no mark. The
      // installed set holds pooled accounts only, so every account here has reference state.
      if (this.#reference.stateOf(report.account_id)?.disabled !== true) continue;
      const mark = current.get(report.account_id);
      if (mark !== undefined) this.#authFailedMarks.set(report.account_id, mark);
    }
    return answer;
  }

  release(replicaId: string, accountId: string): boolean {
    return this.#reference.release(replicaId, accountId);
  }

  accountsFor(replicaId: string): readonly string[] {
    return this.#reference.accountsFor(replicaId);
  }

  leaseTable(replicaId: string): LeaseTable {
    return this.#reference.leaseTable(replicaId);
  }

  reset(accountId: string): number {
    // R19: an operator reset (`*` for all) clears the in-memory auth_failed exclusion itself; the
    // reference scheduler's reset alone would not survive the next `refresh()`, which re-applies
    // the marks.
    let cleared = 0;
    if (accountId === "*") {
      cleared = this.#authFailedMarks.size;
      this.#authFailedMarks.clear();
    } else if (this.#authFailedMarks.delete(accountId)) {
      cleared = 1;
    }
    // An account filtered out of `setAccounts` has no reference state to clear, so the mark is the
    // only evidence of the reset; count it so the operator route answers `reset: true`. Rebuild the
    // pool so an account excluded only by the mark is pickable again on the next request.
    const changed = this.#reference.reset(accountId);
    this.refresh();
    return changed + cleared;
  }

  /** One operator/test view of the pool's accounts; no credential is ever a member. */
  get accounts(): readonly SchedulerAccount[] {
    return this.#reference.accounts;
  }

  /** Rebuild the reference scheduler's snapshot from the current source and installation facts. */
  refresh(): void {
    const eligible = this.#accounts.filter((planned) => {
      if (this.#parked.has(planned.accountId)) return false;
      if (metadataParkReason(planned.account) !== null) return false;
      // R19: an ineligible account is left out of `setAccounts`, which would erase the reference
      // scheduler's disabled state. The mark is the durable exclusion; apply it here as well.
      if (this.#authFailedMarks.has(planned.accountId)) return false;
      return this.#eligible.get(planned.accountId) === true;
    });
    const accounts: SchedulerAccount[] = eligible.map((planned) => ({
      accountId: planned.accountId,
      vendor: planned.vendor as Vendor,
      models: planned.account.models === "*" ? ["*"] : [...planned.account.models],
      weight: planned.account.weight > 0n ? planned.account.weight : 1n,
      maxConcurrency: planned.account.maxConcurrency > 0n ? planned.account.maxConcurrency : 1n,
    }));
    const known = new Set(accounts.map((account) => account.accountId));
    const replicas = this.#replicaOrder.map((replicaId) => ({
      replicaId,
      accountIds: [...(this.#installed.get(replicaId) ?? [])].filter((id) => known.has(id)).sort(),
    }));
    const snapshot: SchedulerAccountsSnapshot = { accounts, replicas };
    this.#reference.setAccounts(snapshot);
  }

  /** `auth_failed` is an in-memory exclusion: clear it when the source's mark moves. */
  #dropAuthFailedWhereChanged(): void {
    const current = new Map(this.#accounts.map((planned) => [planned.accountId, planned.account.changeMark]));
    for (const [accountId, mark] of [...this.#authFailedMarks]) {
      const now = current.get(accountId);
      // R19: an account that is merely absent from this poll (or temporarily ineligible) keeps its
      // exclusion. Only a moved changeMark or an explicit reset clears it.
      if (now === undefined) continue;
      if (now === mark) continue;
      this.#authFailedMarks.delete(accountId);
      this.#reference.reset(accountId);
    }
  }
}

/** The outcome names the pool applies as an exclusion (a quota failure is the same as auth for us). */
export const EXCLUDING_OUTCOMES: readonly Outcome[] = ["auth_failed", "quota_exhausted"];
