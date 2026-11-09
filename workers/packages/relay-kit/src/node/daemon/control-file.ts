/**
 * `control.json` on disk, Node side. The file lives beside the daemon's state file (same state
 * directory, fixed name `control.json`) and holds the two members a person owns:
 *
 * ```json
 * {"accepted_releases":["<compose hash>"],"paused":false}
 * ```
 *
 * Only the CLI calls `write` (pause, resume, releases accept), through the same atomic rename +
 * fsync as the state file, 0600. The daemon receives this store through `DaemonControlStore`, whose
 * interface has no write member, so the agent cannot overwrite a control edit; its one member (P12's
 * `stack_instance`) goes through `../control.ts` `setStackInstanceState`, the CLI's locked merge. A missing or
 * malformed file is `intact: false`, never an exception: the daemon keeps its last view and can
 * still start from a legacy state file (K5-3 migration).
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseStrict } from "@gray/json";
import { daemonControlText, EMPTY_DAEMON_CONTROL, parseDaemonControlValue } from "../../daemon/control.ts";
import type { DaemonControl, DaemonControlLoad, DaemonControlStore } from "../../daemon/types.ts";
import { readAtomicDocument, writeAtomicPrivateFile } from "./atomic-file.ts";

/** The store the CLI uses: it adds the one write member the daemon's interface deliberately lacks. */
export interface WritableDaemonControlStore extends DaemonControlStore {
  write(control: DaemonControl): Promise<void>;
}

/** `control.json` beside a state file: the state volume's directory, one fixed name. */
export function controlFileBeside(stateFile: string): string {
  return join(dirname(resolve(stateFile)), "control.json");
}

/** What is actually on disk: a current document, no file, or a file that does not parse. */
export type ControlFileInspection =
  | { readonly kind: "ok"; readonly control: DaemonControl }
  | { readonly kind: "missing" }
  | { readonly kind: "malformed" };

/**
 * Inspect `control.json` without collapsing "missing" and "present but unreadable": the CLI's
 * setters refuse the second (R12), while a status read reports it as `source: "malformed"`. Only
 * ENOENT counts as missing; every other read or parse failure is malformed.
 */
export function inspectControlFile(path: string): ControlFileInspection {
  let text: string;
  try {
    text = readFileSync(resolve(path), "utf8");
  } catch (error) {
    // Only ENOENT is missing (R12). Every other read failure is a file that exists and cannot be
    // trusted, which a setter must refuse rather than overwrite.
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? { kind: "missing" } : { kind: "malformed" };
  }
  try {
    return { kind: "ok", control: parseDaemonControlValue(parseStrict(text)) };
  } catch {
    return { kind: "malformed" };
  }
}

/** The control file as a writable store (the CLI is the only writer). */
export function createFileControlStore(path: string): WritableDaemonControlStore {
  return {
    async read(): Promise<DaemonControlLoad> {
      const text = readAtomicDocument(path);
      if (text === null) return { control: EMPTY_DAEMON_CONTROL, intact: false };
      try {
        return { control: parseDaemonControlValue(parseStrict(text)), intact: true };
      } catch {
        return { control: EMPTY_DAEMON_CONTROL, intact: false };
      }
    },
    async write(control: DaemonControl): Promise<void> {
      writeAtomicPrivateFile(path, daemonControlText(control));
    },
  };
}
