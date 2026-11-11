/**
 * The CLI's exclusive lock around a `control.json` read-modify-write (K5-7, D38).
 *
 * Two operator commands (`pause` and `releases accept`, say) can run at once; without a lock each
 * reads the same document and the second write drops the first edit. The lock is one file beside
 * `control.json`, created with `O_EXCL` and holding the holder's pid, acquisition time, a random
 * 128-bit token and, where Linux `/proc` says, the holder process's start identity:
 *
 * ```json
 * {"pid":1234,"started_at_ms":1790000000000,"token":"<32 lower-case hex>","process_start":"<boot id>:<start ticks>"}
 * ```
 *
 * The token is the lock's identity. A stale lock is taken over by renaming the current file to a
 * private claim name and re-reading the claim: if its bytes are still the ones that were judged
 * stale, the claim is unlinked and this waiter creates a fresh lock; if another waiter replaced it
 * first, the claim is restored with an exclusive `link` only when the lock path is still empty, and
 * a path another waiter already took is left untouched. Restoring never renames onto the lock path,
 * so it can never replace a live holder's file (D80). `release` uses the same compare-and-rename and
 * removes the file only while it still carries this holder's token, so a holder whose lock was
 * replaced can never delete the new holder's lock. The pid and start time stay in the file for the
 * error message.
 *
 * A lock is stale, and replaced at once (a killed holder must not block the operator forever), when
 * its holder is gone:
 *
 * - it names this process's pid with a token this process does not hold. One pid belongs to one
 *   process at a time, so an earlier process with the same pid wrote it. That is the agent's case:
 *   it is PID 1 in its container, so after an OOM kill or a `SIGKILL` inside a login write the
 *   restarted agent is PID 1 again. The tokens this process holds are kept in memory, so two
 *   holders in one process still exclude each other;
 * - its pid no longer exists;
 * - its pid exists but is another process now: the recorded start identity (the boot id and the
 *   process's start time, `processStartIdentity`) differs from that pid's current one. That is a CLI
 *   command `docker compose exec`'d into a restarted agent's container, which sees PID 1 alive. A
 *   lock without the identity (an older command, or a system without `/proc`) is judged by the pid
 *   alone.
 *
 * Pids are numbered per PID namespace, so every holder of one lock must run in the same container:
 * CLI commands go through `docker compose exec` into the agent's container, never a separate
 * `docker compose run` container sharing the state volume.
 *
 * A malformed lock is treated as held until it is a couple of seconds old, so the tiny window
 * between `open` and `write` cannot be stolen. Waiting is bounded; a live holder ends in one plain
 * error naming the lock file, never a hang. `isAlive`, the start identity, the clock, the sleep and
 * the pid are injectable, so the tests run without a timer.
 */
import { randomBytes } from "node:crypto";
import { closeSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parsePlain } from "@gray/json";
import { RelayKitError } from "../errors.ts";

/** The lock file beside a control file. */
export function controlLockFile(controlFile: string): string {
  return `${resolve(controlFile)}.lock`;
}

/** A malformed lock younger than this may be a live holder between `open` and `write`. */
export const MALFORMED_LOCK_STALE_MS = 2_000;

/** The defaults: wait up to five seconds, polling every 25 ms. */
export const DEFAULT_CONTROL_LOCK_TIMEOUT_MS = 5_000;
export const DEFAULT_CONTROL_LOCK_POLL_MS = 25;

const TOKEN_HEX = /^[0-9a-f]{32}$/;
const PROCESS_START = /^[0-9a-f-]{1,64}:[0-9]{1,20}$/u;

/**
 * The tokens of the locks this process holds right now. A lock carrying this process's pid and a
 * token not in this set was written by an earlier process that had the same pid.
 */
const heldTokens = new Set<string>();

export interface ControlLockOptions {
  /** How long to wait for a live holder before the plain error. Default 5000 ms. */
  readonly timeoutMs?: number;
  readonly pollMs?: number;
  /** The clock used for the deadline and the recorded start time. Default `Date.now`. */
  readonly nowMs?: () => number;
  /** How to wait. Default a real `setTimeout`; the tests pass an immediate resolver. */
  readonly sleep?: (ms: number) => Promise<void>;
  /** The holder pid written to the lock. Default `process.pid`. */
  readonly pid?: number;
  /** Whether a pid is alive. Default `process.kill(pid, 0)`. */
  readonly isAlive?: (pid: number) => boolean;
  /**
   * A pid's start identity, or null when unknown. Default `processStartIdentity`, which for this
   * holder's own identity is read only when `pid` is this process's.
   */
  readonly processStart?: (pid: number) => string | null;
}

/** One acquired lock; `release` removes it (only while it still carries this holder's token). */
export interface ControlLock {
  release(): void;
  readonly path: string;
  readonly pid: number;
  /** The random 128-bit identity written to the lock file (D38). */
  readonly token: string;
}

interface LockHolder {
  readonly pid: number;
  readonly startedAtMs: number;
  /** Absent in a lock written by an older command; such a file is compared by its exact bytes. */
  readonly token: string | null;
  /** The holder's `processStartIdentity` when it wrote the lock; absent where it was unknown. */
  readonly processStart: string | null;
}

interface LockRead {
  readonly holder: LockHolder | null;
  readonly text: string;
}

/** A pid is alive unless `process.kill(pid, 0)` says it is gone (EPERM means alive). */
function defaultIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * A pid's start identity on Linux: the boot id (`/proc/sys/kernel/random/boot_id`, a new random
 * UUID on every boot) and the process's start time in clock ticks after boot (`/proc/<pid>/stat`
 * field 22, `starttime`; proc_pid_stat(5)). A pid the kernel hands to a later process comes with a
 * later start time, so the pair tells a reused pid from the process that wrote a lock. Null where
 * `/proc` does not say (macOS, a pid hidden by `hidepid`, a pid that is gone).
 */
export function processStartIdentity(pid: number): string | null {
  let boot: string;
  let stat: string;
  try {
    boot = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  } catch {
    return null;
  }
  // Field 2 (`comm`) is in parentheses and may itself contain spaces and ")" (proc_pid_stat(5)), so
  // the fields are counted from the last ")": the first one after it is field 3 (`state`).
  const fields = stat.slice(stat.lastIndexOf(")") + 1).trim().split(" ");
  const identity = `${boot}:${fields[22 - 3] ?? ""}`;
  return PROCESS_START.test(identity) ? identity : null;
}

function parseLock(text: string): LockHolder | null {
  let value: unknown;
  try {
    value = parsePlain(text);
  } catch {
    return null;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as { pid?: unknown; started_at_ms?: unknown; token?: unknown; process_start?: unknown };
  if (typeof record.pid !== "number" || !Number.isSafeInteger(record.pid) || record.pid <= 0) return null;
  if (typeof record.started_at_ms !== "number" || !Number.isSafeInteger(record.started_at_ms) || record.started_at_ms < 0) return null;
  if (record.token !== undefined && (typeof record.token !== "string" || !TOKEN_HEX.test(record.token))) return null;
  if (record.process_start !== undefined && (typeof record.process_start !== "string" || !PROCESS_START.test(record.process_start))) return null;
  return { pid: record.pid, startedAtMs: record.started_at_ms, token: record.token ?? null, processStart: record.process_start ?? null };
}

/** Whether a well-formed lock's holder is gone (the rules in the header). */
function holderGone(holder: LockHolder, ownPid: number, isAlive: (pid: number) => boolean, processStart: (pid: number) => string | null): boolean {
  if (holder.pid === ownPid) return holder.token === null || !heldTokens.has(holder.token);
  if (!isAlive(holder.pid)) return true;
  if (holder.processStart === null) return false;
  const current = processStart(holder.pid);
  return current !== null && current !== holder.processStart;
}

function readLock(path: string): LockRead | null {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  return { holder: parseLock(text), text };
}

function randomToken(): string {
  return randomBytes(16).toString("hex");
}

function claimName(path: string): string {
  return `${path}.claim-${process.pid}-${randomToken()}`;
}

/** Move whatever is at `path` to a private claim name. Null when the file vanished first. */
function claimLock(path: string): { readonly path: string; readonly text: string } | null {
  const claim = claimName(path);
  try {
    renameSync(path, claim);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  try {
    return { path: claim, text: readFileSync(claim, "utf8") };
  } catch {
    // Do not leave the lock stranded under the claim name.
    restoreClaim(claim, path);
    return null;
  }
}

/**
 * Put a claimed lock back at `path` without replacing a newer lock: `link` is create-only, so it
 * fails with EEXIST when another waiter already created one. The claim is then dropped (the moved
 * lock has been superseded at the path). There is deliberately no rename fallback: a restore must
 * never replace the file at the lock path, not even on a filesystem that refuses hard links (D80);
 * in that case the moved lock is dropped and this waiter's acquisition loop starts over. `release`
 * never reaches a token it does not own.
 *
 * `link` is injectable so a test can prove the no-rename rule on a hard-link refusal without a
 * real unsupported filesystem; production always passes `fs.linkSync`.
 */
export function restoreClaim(claim: string, path: string, link: (existingPath: string, newPath: string) => void = linkSync): void {
  try {
    link(claim, path);
  } catch {
    // EEXIST: another command holds the path now; leave its file alone. Any other refusal (for
    // example a filesystem without hard links) means we cannot restore safely; never rename over
    // whatever is at the path.
  }
  try {
    unlinkSync(claim);
  } catch {
    // Already gone; nothing to clean up.
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

/**
 * Acquire the exclusive lock. A missing directory (the control directory is not created yet) is
 * created by the caller's write path; the caller passes the same directory, which already exists
 * when a control command runs.
 */
export async function acquireControlLock(lockFile: string, options: ControlLockOptions = {}): Promise<ControlLock> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_CONTROL_LOCK_TIMEOUT_MS;
  const pollMs = options.pollMs ?? DEFAULT_CONTROL_LOCK_POLL_MS;
  const now = options.nowMs ?? Date.now;
  const sleep = options.sleep ?? defaultSleep;
  const pid = options.pid ?? process.pid;
  const isAlive = options.isAlive ?? defaultIsAlive;
  const processStart = options.processStart ?? processStartIdentity;
  const path = resolve(lockFile);
  // A first control command may run before the agent has created the state directory.
  mkdirSync(dirname(path), { recursive: true });
  const deadline = now() + timeoutMs;
  const token = randomToken();
  // An injected pid is not this process, so `/proc` cannot say when it started.
  const ownStart = options.processStart !== undefined ? options.processStart(pid) : pid === process.pid ? processStartIdentity(pid) : null;
  for (;;) {
    try {
      const fd = openSync(path, "wx", 0o600);
      try {
        writeSync(fd, JSON.stringify({ pid, started_at_ms: now(), token, ...(ownStart === null ? {} : { process_start: ownStart }) }), null, "utf8");
      } finally {
        closeSync(fd);
      }
      // Synchronously after the write: no other holder in this process runs in between.
      heldTokens.add(token);
      let released = false;
      return {
        path,
        pid,
        token,
        release(): void {
          if (released) return;
          released = true;
          heldTokens.delete(token);
          // Compare-and-rename (D38): move the current file aside and delete *that file* only when
          // it still names this holder. A replaced lock is put back, never unlinked.
          const claim = claimLock(path);
          if (claim === null) return;
          const holder = parseLock(claim.text);
          if (holder !== null && holder.token === token) {
            try {
              unlinkSync(claim.path);
            } catch {
              // Another command already removed the claimed file.
            }
            return;
          }
          restoreClaim(claim.path, path);
        },
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const observed = readLock(path);
    if (observed === null) continue;
    let takeOver: boolean;
    if (observed.holder !== null) {
      takeOver = holderGone(observed.holder, pid, isAlive, processStart);
    } else {
      let ageMs = Number.POSITIVE_INFINITY;
      try {
        ageMs = now() - statSync(path).mtimeMs;
      } catch {
        // It vanished between the open and the stat: retry at once.
      }
      takeOver = ageMs > MALFORMED_LOCK_STALE_MS;
    }
    if (takeOver) {
      const claim = claimLock(path);
      if (claim === null) continue;
      // The file may have changed between `readLock` and the rename. Only the exact bytes that
      // were judged stale may be removed; anything else goes back untouched.
      if (claim.text === observed.text) {
        try {
          unlinkSync(claim.path);
        } catch {
          // Another waiter removed the claim first; the next open decides.
        }
        continue;
      }
      restoreClaim(claim.path, path);
    }
    if (now() >= deadline) {
      const current = readLock(path);
      const held = current?.holder == null ? "" : ` by pid ${current.holder.pid} since ${current.holder.startedAtMs}`;
      throw new RelayKitError("usage", `another gray-assistant control command holds ${path}${held}; retry`);
    }
    await sleep(pollMs);
  }
}
