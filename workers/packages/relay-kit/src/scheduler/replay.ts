/**
 * The scheduler's single nonce window: one per handler, shared by every verified replica.
 *
 * `@gray/relay-connector`'s `SchedulerReplayWindow` is the reference for the rule (a nonce is
 * accepted once inside the timestamp window), but it has two properties this handler cannot live
 * with: its cap is fixed at construction, and every `accept` scans the whole map to prune. A busy
 * relay with one shared window across replicas would pay that scan on every signed call. This window
 *
 * - takes its cap from the scheduler configuration (`replay_cap`, validated with bounds);
 * - remembers insertion order, so pruning stops at the first entry whose acceptance window has not
 *   passed (a Map iterates in insertion order, and every entry is inserted with the same window);
 * - fails closed when the cap is reached: a full window refuses a new nonce rather than forgetting a
 *   live one.
 *
 * Time is injected; tests advance it explicitly. A clock that moves backwards prunes nothing (the
 * first entry is still unexpired, so the loop stops), which keeps every live nonce remembered.
 */

/** The default cap: the connector's own window default, one hundred thousand live nonces. */
export const DEFAULT_REPLAY_CAP = 100_000;

/** The largest cap a scheduler configuration may set: one million live nonces (about 128 MiB). */
export const MAX_REPLAY_CAP = 1_000_000;

/** The smallest cap: one live nonce is a valid (if useless) window, and the parser accepts it. */
export const MIN_REPLAY_CAP = 1;

export interface SchedulerNonceWindowOptions {
  /** How long one nonce is remembered: always `2 × maxSkewMs` in the handler, so it covers the
   * whole range a signed timestamp is accepted in. */
  readonly windowMs: number;
  /** The greatest number of live nonces; the cap from `replay_cap`. Default {@link DEFAULT_REPLAY_CAP}. */
  readonly maxEntries?: number;
}

/** One relay-wide nonce memory, shared by every replica the handler has verified. */
export class SchedulerNonceWindow {
  readonly #windowMs: number;
  readonly #maxEntries: number;
  /** nonce → the instant (exclusive) after which it is no longer live. Insertion ordered. */
  readonly #seen = new Map<string, number>();

  constructor(options: SchedulerNonceWindowOptions) {
    if (!Number.isSafeInteger(options.windowMs) || options.windowMs < 1) {
      throw new RangeError("the nonce window must be a positive integer number of milliseconds");
    }
    const maxEntries = options.maxEntries ?? DEFAULT_REPLAY_CAP;
    if (!Number.isSafeInteger(maxEntries) || maxEntries < MIN_REPLAY_CAP || maxEntries > MAX_REPLAY_CAP) {
      throw new RangeError(`the nonce cap must be an integer in [${MIN_REPLAY_CAP}, ${MAX_REPLAY_CAP}]`);
    }
    this.#windowMs = options.windowMs;
    this.#maxEntries = maxEntries;
  }

  /** Whether `nonce` is new; a repeat inside the window fails closed, as does a full window. */
  accept(nonce: string, nowMs: number): boolean {
    this.prune(nowMs);
    const expiresAt = this.#seen.get(nonce);
    if (expiresAt !== undefined && expiresAt > nowMs) return false;
    if (this.#seen.size >= this.#maxEntries) return false;
    this.#seen.set(nonce, nowMs + this.#windowMs);
    return true;
  }

  /**
   * Forget nonces whose acceptance window has passed. Insertion order and one fixed window mean the
   * first live entry ends the scan: everything after it was inserted later and is at least as fresh.
   */
  prune(nowMs: number): void {
    for (const [nonce, expiresAt] of this.#seen) {
      if (expiresAt > nowMs) break;
      this.#seen.delete(nonce);
    }
  }

  /** How many live nonces the window holds right now (after the last accept/prune). */
  get size(): number {
    return this.#seen.size;
  }
}