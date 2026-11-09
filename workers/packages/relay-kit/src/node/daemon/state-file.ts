/**
 * The daemon's state file, Node side: one JSON document with only `last_version` and
 * `release_first_seen`, written by atomic rename and fsync (see `atomic-file.ts`).
 *
 * The pure daemon only knows `DaemonStateStore`. This implementation reads a missing or malformed
 * file as a **lost** state (`intact: false`), which arms the version probe and records a warning in
 * the daemon; it never echoes the file's text, because a damaged file is not assumed to be
 * secret-free even though this writer never puts a secret in it. An older file that still carries
 * `paused`/`accepted_releases` is read as the legacy control pair once (K5-3); every write emits the
 * two-member shape and drops it.
 */
import { parseStrict } from "@gray/json";
import { daemonStateText, EMPTY_DAEMON_STATE, parseDaemonStateDocument } from "../../daemon/state.ts";
import type { DaemonState, DaemonStateLoad, DaemonStateStore } from "../../daemon/types.ts";
import { readAtomicDocument, writeAtomicPrivateFile } from "./atomic-file.ts";

/** The state file as a `DaemonStateStore`. */
export function createFileStateStore(path: string): DaemonStateStore {
  return {
    async read(): Promise<DaemonStateLoad> {
      const text = readAtomicDocument(path);
      if (text === null) return { state: EMPTY_DAEMON_STATE, intact: false, legacyControl: null };
      try {
        const parsed = parseDaemonStateDocument(parseStrict(text));
        return { state: parsed.state, intact: true, legacyControl: parsed.legacyControl };
      } catch {
        return { state: EMPTY_DAEMON_STATE, intact: false, legacyControl: null };
      }
    },
    async write(state: DaemonState): Promise<void> {
      writeAtomicPrivateFile(path, daemonStateText(state));
    },
  };
}
