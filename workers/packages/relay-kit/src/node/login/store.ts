/**
 * The login records on disk (`./record.ts` has the format): one 0600 file per login in a 0700
 * directory of the agent's state volume, written by the same atomic writer as `state.json` and
 * `control.json` (fresh temporary file, fsync, rename, directory fsync), so a crash leaves the old
 * or the new token family, never half of each.
 *
 * Two processes write a record: `gray-assistant login codex` (a sign-in) and the agent's refresher (a
 * rotation). Each takes the login's lock (`<name>.json.lock`, the CLI's control lock: pid, start
 * time, a random token and the holder process's start identity, created with O_EXCL) for its
 * read-compare-write, and neither holds it across a network call. The agent is PID 1 in its
 * container, so a lock it left when it was killed names the pid of its restarted self; the control
 * lock's holder rules (`../control-lock.ts`) take such a lock over instead of waiting for it. A
 * record is read with the private-file rule of every relay secret: no symbolic link, no group or
 * other bits.
 */
import { chmodSync, lstatSync, mkdirSync, readdirSync, type Stats } from "node:fs";
import { join, resolve } from "node:path";
import { RelayKitError } from "../../errors.ts";
import { acquireControlLock, type ControlLockOptions } from "../control-lock.ts";
import { writeAtomicPrivateFile } from "../daemon/atomic-file.ts";
import { isGroupOrOtherReadable, readPrivateFile } from "../files.ts";
import { LOGIN_NAME, MAX_LOGIN_RECORD_BYTES, loginRecordText, parseLoginRecordText, type LoginRecord } from "./record.ts";

/** Refuse a name that is not a plain file name under the logins directory. */
export function assertLoginName(name: string): string {
  if (!LOGIN_NAME.test(name)) throw new RelayKitError("usage", "a login name is 1-63 characters of a-z, 0-9, _ and -, starting with a letter or digit");
  return name;
}

export function loginRecordPath(dir: string, name: string): string {
  return join(resolve(dir), `${assertLoginName(name)}.json`);
}

function lstatOrNull(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch {
    return null;
  }
}

/** Create the directory 0700, or refuse one that is a symbolic link or open to group or others. */
export function ensureLoginDirectory(dir: string): void {
  const path = resolve(dir);
  const existing = lstatOrNull(path);
  if (existing === null) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
    // `mkdir`'s mode is masked by the umask; set it exactly.
    chmodSync(path, 0o700);
    return;
  }
  if (existing.isSymbolicLink() || !existing.isDirectory()) throw new RelayKitError("invalid_login", "the logins directory is not a directory");
  if (isGroupOrOtherReadable(existing.mode)) throw new RelayKitError("invalid_login", "the logins directory is open to group or others; chmod 700 it");
}

/** One record, or null when the login has never been signed in. A broken record throws `invalid_login`. */
export function readLoginRecord(dir: string, name: string): LoginRecord | null {
  const path = loginRecordPath(dir, name);
  if (lstatOrNull(path) === null) return null;
  const record = parseLoginRecordText(readPrivateFile(path, "login record", MAX_LOGIN_RECORD_BYTES));
  if (record.login !== name) throw new RelayKitError("invalid_login", "login");
  return record;
}

/** Write one record atomically as 0600 (the caller holds the login's lock). */
export function writeLoginRecord(dir: string, record: LoginRecord): void {
  ensureLoginDirectory(dir);
  writeAtomicPrivateFile(loginRecordPath(dir, record.login), loginRecordText(record));
}

/** The names of every record in the directory, sorted; an absent directory has none. */
export function listLoginNames(dir: string): readonly string[] {
  let entries: string[];
  try {
    entries = readdirSync(resolve(dir));
  } catch {
    return [];
  }
  return entries
    .filter((entry) => entry.endsWith(".json"))
    .map((entry) => entry.slice(0, -".json".length))
    .filter((name) => LOGIN_NAME.test(name))
    .sort();
}

/** Run `body` while holding the login's lock; the lock is released however `body` ends. */
export async function withLoginLock<T>(dir: string, name: string, body: () => T | Promise<T>, options: ControlLockOptions = {}): Promise<T> {
  ensureLoginDirectory(dir);
  const lock = await acquireControlLock(`${loginRecordPath(dir, name)}.lock`, options);
  try {
    return await body();
  } finally {
    lock.release();
  }
}
