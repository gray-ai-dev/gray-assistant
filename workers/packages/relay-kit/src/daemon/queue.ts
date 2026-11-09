/**
 * One single-flight queue per replica (design v2 §A.5, critique R8). Bundle, update and revoke all
 * share a replica's version sequence and account map, so they are serialized here: a renewal can
 * never interleave with a token push or a revoke, and the version is allocated inside the critical
 * section, immediately before the message leaves it.
 *
 * The queue is deliberately tiny and pure. It runs tasks in arrival order, keeps a count for
 * `status`, and never rejects its own chain: a failed task does not poison the next one.
 */
export class ReplicaQueue {
  #tail: Promise<void> = Promise.resolve();
  #pending = 0;
  #busy = false;

  /** Enqueue one task; its promise settles with the task's result. */
  run<T>(task: () => Promise<T>): Promise<T> {
    this.#pending += 1;
    const run = this.#tail.then(async () => {
      this.#busy = true;
      try {
        return await task();
      } finally {
        this.#busy = false;
      }
    });
    this.#tail = run.then(
      () => {
        this.#pending -= 1;
      },
      () => {
        this.#pending -= 1;
      },
    );
    return run;
  }

  /** Tasks enqueued and not yet finished (the running one included). */
  get pending(): number {
    return this.#pending;
  }

  /** Whether a task is running right now. */
  get busy(): boolean {
    return this.#busy;
  }

  /** Resolves when every task enqueued so far has settled. */
  async idle(): Promise<void> {
    await this.#tail;
  }
}
