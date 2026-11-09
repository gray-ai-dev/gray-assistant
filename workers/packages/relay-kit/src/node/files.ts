/**
 * The Node side's file rules. They are here, not in the pure modules, because permissions and paths
 * are the operator's environment.
 *
 * A key file is read only when it is a regular file (not a symlink) with no group or other bits
 * (0600, or stricter). That is a refusal, not a warning: a seed another local account can read is a
 * seed that can sign bundles and scheduler answers. Account and token files hold secrets too, but
 * the task names key files; those two get a warning on stderr instead, so an operator with a
 * conventional umask can still work while seeing what is loose.
 *
 * Every read has a byte cap, and every error message says what failed, never what was in the file: a
 * platform JSON error can echo a snippet of a credential.
 */
import { chmodSync, closeSync, constants, lstatSync, mkdirSync, openSync, readFileSync, rmSync, statSync, writeSync, type Stats } from "node:fs";
import { utf8Text } from "@gray/relay-connector";
import { RelayKitError } from "../errors.ts";

/** What a file is, for an error message; never its contents. */
export type FileKind = string;

function statOf(path: string, what: FileKind): Stats {
  try {
    return lstatSync(path);
  } catch {
    throw new RelayKitError("io", `cannot read ${what} ${path}`);
  }
}

/** Read a regular file's bytes, refusing a symlink and a directory, with a size cap. */
export function readFileBytes(path: string, what: FileKind, maxBytes: number): Uint8Array {
  const stat = statOf(path, what);
  if (stat.isSymbolicLink()) throw new RelayKitError("io", `${what} ${path} is a symbolic link`);
  if (!stat.isFile()) throw new RelayKitError("io", `${what} ${path} is not a regular file`);
  if (stat.size > maxBytes) throw new RelayKitError("io", `${what} ${path} is larger than ${maxBytes} bytes`);
  try {
    return new Uint8Array(readFileSync(path));
  } catch {
    throw new RelayKitError("io", `cannot read ${what} ${path}`);
  }
}

/** Read strict UTF-8 text from a regular file. */
export function readFileText(path: string, what: FileKind, maxBytes: number): string {
  const bytes = readFileBytes(path, what, maxBytes);
  try {
    return utf8Text(bytes);
  } catch {
    throw new RelayKitError("io", `${what} ${path} is not valid UTF-8`);
  }
}

/** Whether a stat mode lets group or others read the file. Windows has no such bits. */
export function isGroupOrOtherReadable(mode: number): boolean {
  if (process.platform === "win32") return false;
  return (mode & 0o077) !== 0;
}

/** Read a key file only when it is private; returns its text. */
export function readPrivateFile(path: string, what: FileKind, maxBytes: number): string {
  const stat = statOf(path, what);
  if (stat.isSymbolicLink()) throw new RelayKitError("unsafe_key_file", `${what} ${path} is a symbolic link`);
  if (!stat.isFile()) throw new RelayKitError("unsafe_key_file", `${what} ${path} is not a regular file`);
  if (isGroupOrOtherReadable(stat.mode)) {
    throw new RelayKitError("unsafe_key_file", `${what} ${path} is readable by group or others; chmod 600 it`);
  }
  if (stat.size > maxBytes) throw new RelayKitError("io", `${what} ${path} is larger than ${maxBytes} bytes`);
  return readFileText(path, what, maxBytes);
}

/** Warn (never refuse) when a secret-bearing input other than a key file is group/other readable. */
export function warnLoosePermissions(path: string, what: FileKind, warn: (line: string) => void): void {
  try {
    const stat = statSync(path);
    if (isGroupOrOtherReadable(stat.mode)) warn(`warning: ${what} ${path} is readable by group or others; chmod 600 it`);
  } catch {
    // The read that follows reports the real error.
  }
}

/**
 * Write text or bytes as 0600, refusing to replace an existing file unless `force`.
 *
 * Always exclusive-create with O_NOFOLLOW: a symlink at the target — including a dangling one,
 * which `existsSync` cannot see — is refused, and `keygen`'s "no overwrite" rule cannot be raced
 * through a pre-planted link. `force` still means replacing an existing regular file: it is
 * unlinked first, then recreated exclusively, so the write never goes through a link.
 */
export function writePrivateFile(path: string, text: string | Uint8Array, options: { readonly force?: boolean } = {}): void {
  if (options.force) {
    try {
      const existing = lstatSync(path);
      // Never write through a symbolic link: the link could point anywhere the operator did not mean.
      if (!existing.isFile() || existing.isSymbolicLink()) throw new RelayKitError("io", `${path} is not a regular file`);
    } catch (error) {
      if (error instanceof RelayKitError) throw error;
      // ENOENT is fine: there is nothing to replace.
    }
    try {
      rmSync(path, { force: true });
    } catch {
      throw new RelayKitError("io", `cannot replace ${path}`);
    }
  }
  try {
    const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      if (typeof text === "string") writeSync(fd, text);
      else for (let at = 0; at < text.length; ) at += writeSync(fd, text, at, text.length - at);
    } finally {
      closeSync(fd);
    }
    chmodSync(path, 0o600);
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code === "EEXIST" || code === "ELOOP") {
      // EEXIST: something is already there. ELOOP (Linux): the path itself is a symlink, possibly
      // dangling. Either way we refuse rather than follow it.
      try {
        if (lstatSync(path).isSymbolicLink()) throw new RelayKitError("io", `${path} is a symbolic link`);
      } catch (statError) {
        if (statError instanceof RelayKitError) throw statError;
      }
      throw new RelayKitError("io", `${path} already exists (pass --force)`);
    }
    throw new RelayKitError("io", `cannot write ${path}`);
  }
}

/** Create a directory (and its parents) for the key file, private when this process creates it. */
export function ensureDirectory(path: string): void {
  try {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  } catch {
    throw new RelayKitError("io", `cannot create ${path}`);
  }
  const stat = statSync(path);
  if (!stat.isDirectory()) throw new RelayKitError("io", `${path} is not a directory`);
}
