/**
 * The one atomic writer the daemon's state file and the CLI's control file share: a fresh 0600
 * temporary file beside the target, write, fsync the file, rename over the target, then fsync the
 * directory. A crash leaves either the old or the new complete document, never a torn one; the
 * temporary name is random and removed on failure.
 *
 * The two documents are separate files on purpose (K5-3): the daemon writes `state.json`, the CLI
 * writes `control.json`, so neither writer's rename can replace the other's edit.
 */
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, resolve } from "node:path";

/** Read a text file, or null when it is missing or unreadable. Never throws. */
export function readAtomicDocument(path: string): string | null {
  try {
    return readFileSync(resolve(path), "utf8");
  } catch {
    return null;
  }
}

/** Write `text` as a 0600 file by atomic rename + fsync; throw only after cleaning the temporary. */
export function writeAtomicPrivateFile(path: string, text: string): void {
  const target = resolve(path);
  const directory = dirname(target);
  mkdirSync(directory, { recursive: true });
  const temporary = `${target}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
  let fileDescriptor: number | null = null;
  try {
    fileDescriptor = openSync(temporary, "wx", 0o600);
    writeSync(fileDescriptor, text, null, "utf8");
    fsyncSync(fileDescriptor);
    closeSync(fileDescriptor);
    fileDescriptor = null;
    renameSync(temporary, target);
    const directoryDescriptor = openSync(directory, "r");
    try {
      fsyncSync(directoryDescriptor);
    } finally {
      closeSync(directoryDescriptor);
    }
  } catch (error) {
    if (fileDescriptor !== null) {
      try {
        closeSync(fileDescriptor);
      } catch {
        // The write already failed; the temporary file is removed below when it exists.
      }
    }
    try {
      unlinkSync(temporary);
    } catch {
      // There may be no temporary file (the open itself failed).
    }
    throw error;
  }
}
