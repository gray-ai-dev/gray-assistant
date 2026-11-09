/**
 * The relay-owned version counter (design v2 §A.3, critique R9, research F3).
 *
 * The rule is
 *
 *     next = max(last_issued + 1, wall_ms)
 *
 * allocated **when a message leaves a replica's single-flight queue** and persisted **before** the
 * message is sent. The wall-clock floor is what keeps a relay that lost its state file ahead of the
 * versions a TEE may remember from before the loss; the +1 is what keeps two messages inside one
 * millisecond apart.
 *
 * A refusal is not just an error:
 *
 * - `bundle_rollback` with a **lost** state file means the TEE remembers a higher version than this
 *   process can name. The next allocation jumps upward, doubling each attempt, bounded in count.
 * - `bundle_replay`/`bundle_rollback` with an **intact** file means a second writer, a restored
 *   backup or a leaked key. Writing stops and the alert is `second_writer`; this is the only
 *   two-agent detector the relay side has.
 * - A replay of an attempt that had already been sent once is idempotence, not a second writer: the
 *   TEE may have applied the timed-out request before the retry. Only a first-attempt replay with
 *   an intact file is suspicious.
 *
 * Allocation is serialized across replicas inside this object, because the ledger is one per relay
 * and a replay window is per relay, not per replica.
 */

/** The first upward probe's jump: one minute of wall-clock milliseconds. */
export const PROBE_BASE_MS = 60_000n;

/** How many upward probes before the ledger stops; the TEE would have to be years ahead to need more. */
export const MAX_PROBE_ATTEMPTS = 8;

/** The largest a u64 version may be. */
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** Why the ledger will not allocate another version. */
export class DaemonVersionError extends Error {
  override readonly name = "DaemonVersionError";
  readonly code: "second_writer" | "probe_exhausted" | "persist_failed";

  constructor(code: "second_writer" | "probe_exhausted" | "persist_failed") {
    super(`daemon version: ${code}`);
    this.code = code;
  }
}

/** What a rollback or replay refusal means for the next step. */
export type VersionRefusalAction =
  | { readonly action: "probe"; readonly attempt: number; readonly jumpMs: bigint }
  | { readonly action: "installed" }
  | { readonly action: "second_writer" }
  | { readonly action: "exhausted" };

export interface VersionLedgerOptions {
  /** The `last_version` the state file held; 0 when there was no file. */
  readonly initial: bigint;
  /** Whether the state file was read intact. A missing or corrupt file starts in probe mode. */
  readonly intact: boolean;
  /** The wall clock in Unix milliseconds. */
  readonly now: () => number;
  /** Persist one allocation before its message is sent. A throw stops the ledger. */
  readonly persist: (lastVersion: bigint) => Promise<void>;
}

export class VersionLedger {
  #last: bigint;
  readonly #intact: boolean;
  readonly #now: () => number;
  readonly #persist: (lastVersion: bigint) => Promise<void>;
  #probeJump = 0n;
  #probeAttempts = 0;
  #stopped: DaemonVersionError["code"] | null = null;
  #tail: Promise<void> = Promise.resolve();
  #allocated = 0;

  constructor(options: VersionLedgerOptions) {
    if (options.initial < 0n || options.initial > U64_MAX) throw new RangeError("a last_version is a u64");
    this.#last = options.initial;
    this.#intact = options.intact;
    this.#now = options.now;
    this.#persist = options.persist;
  }

  /** The last persisted version. */
  get lastIssued(): bigint {
    return this.#last;
  }

  /** False once a lost file has been seen: the next rollback becomes a probe, not an alert. */
  get intact(): boolean {
    return this.#intact;
  }

  /** The reason writing stopped, or null. */
  get stopped(): DaemonVersionError["code"] | null {
    return this.#stopped;
  }

  get probeAttempts(): number {
    return this.#probeAttempts;
  }

  /** How many versions this process allocated (a status number, not a credential). */
  get allocated(): number {
    return this.#allocated;
  }

  /**
   * Allocate and persist the next version. Serialized: two replicas can never interleave an
   * allocation and a persist. A persist failure stops the ledger, because a message whose version
   * is not durable must never be sent.
   */
  allocate(): Promise<bigint> {
    const run = this.#tail.then(async () => {
      if (this.#stopped !== null) throw new DaemonVersionError(this.#stopped);
      const wall = BigInt(Math.max(0, Math.floor(this.#now())));
      let next = this.#last + 1n;
      if (wall > next) next = wall;
      if (this.#probeJump > 0n) {
        next += this.#probeJump;
        // R20: the jump belongs to the next allocation only. The daemon passes attempt 1 every
        // time, so adding an ever-growing jump to every later message would drift forever.
        this.#probeJump = 0n;
      }
      if (next > U64_MAX) {
        this.#stopped = "probe_exhausted";
        throw new DaemonVersionError("probe_exhausted");
      }
      const previous = this.#last;
      this.#last = next;
      try {
        await this.#persist(next);
      } catch {
        this.#last = previous;
        this.#stopped = "persist_failed";
        throw new DaemonVersionError("persist_failed");
      }
      this.#allocated += 1;
      return next;
    });
    this.#tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * Apply a `bundle_rollback` refusal. `attempt` is the 1-based attempt of the message that was
   * refused (1 = the first send). With an intact file this is a second writer; with a lost file it
   * schedules an exponentially larger jump for the next `allocate`.
   */
  onRollback(attempt: number): VersionRefusalAction {
    if (this.#stopped !== null) return { action: this.#stopped === "probe_exhausted" ? "exhausted" : "second_writer" };
    if (this.#intact) {
      this.#stopped = "second_writer";
      return { action: "second_writer" };
    }
    // R20: the bound is the ledger's own probe count, not the caller's attempt. Every daemon
    // upload passes attempt 1, so trusting it would let a rollback loop probe without end.
    if (this.#probeAttempts >= MAX_PROBE_ATTEMPTS) {
      this.#stopped = "probe_exhausted";
      return { action: "exhausted" };
    }
    this.#probeAttempts += 1;
    const jump = PROBE_BASE_MS * (1n << BigInt(this.#probeAttempts));
    this.#probeJump = jump;
    return { action: "probe", attempt: this.#probeAttempts, jumpMs: jump };
  }

  /**
   * Apply a `bundle_replay`/`version_replay` refusal. A replay of a retried message, or a replay
   * while the file is lost, is the idempotent case (the TEE already applied it); a first-attempt
   * replay with an intact file is a second writer.
   */
  onReplay(attempt: number): VersionRefusalAction {
    if (this.#stopped !== null) return { action: this.#stopped === "probe_exhausted" ? "exhausted" : "second_writer" };
    if (attempt > 1 || !this.#intact) return { action: "installed" };
    this.#stopped = "second_writer";
    return { action: "second_writer" };
  }

  /** Stop writing after a condition only an operator can resolve (a second writer, a lost file). */
  stop(code: DaemonVersionError["code"]): void {
    this.#stopped = code;
  }
}
