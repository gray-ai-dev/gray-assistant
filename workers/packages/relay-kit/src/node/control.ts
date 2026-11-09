/**
 * The operator's file-level controls: `pause`, `resume`, `releases accept`, (S11b) `releases
 * reject|unreject` and (S53) `stack rollout|rollback`; and (P12) the agent's adopted stack instance and its pairing
 * acceptances. They write the
 * CLI-owned `control.json` beside the daemon's state file (atomic rename + fsync, 0600) and never
 * the state file, so a running daemon's version/first-seen write cannot erase a control edit and a
 * control edit cannot erase a version.
 *
 * Two control commands at once are serialized by a lock beside `control.json` (K5-7): each reads,
 * merges and writes under the lock, so `pause` and `releases accept` running together keep both
 * edits. A corrupt `control.json` is never treated as missing: a setter refuses with a usage error
 * naming the file and leaves its bytes alone, while `readControlView` reports `source: "malformed"`
 * so `status` and `doctor` still print (R12).
 *
 * Migration (K5-3): a state file left by an older agent still carries `paused`/`accepted_releases`.
 * A control command reads those fields when there is no control file yet, merges its own edit, and
 * writes the result to `control.json`; that write is what moves them. From then on the legacy fields
 * in the older file are ignored (the daemon reads control.json first, and its next state write emits
 * only the two current members).
 */
import { EMPTY_DAEMON_CONTROL, withAcceptedRelease, withPairingAcceptances, withPaused, withRejectedRelease, withStackImage, withStackInstance, withoutRejectedRelease } from "../daemon/control.ts";
import { RelayKitError } from "../errors.ts";
import { acquireControlLock, controlLockFile, type ControlLockOptions } from "./control-lock.ts";
import { createFileControlStore, inspectControlFile } from "./daemon/control-file.ts";
import { createFileStateStore } from "./daemon/state-file.ts";
import type { DaemonControl, DaemonStackInstance } from "../daemon/types.ts";

/** What a control command starts from, and whether it came from `control.json` or the legacy state. */
export interface ControlView {
  readonly control: DaemonControl;
  /** `control`: a current control file; `legacy`: the old state file's pair; `malformed`: a
   *  control file exists but does not parse; `empty`: neither. */
  readonly source: "control" | "legacy" | "malformed" | "empty";
  /** The state file's version counter, for display only; a control command never writes it. */
  readonly lastVersion: bigint;
  /** The daemon-owned first-seen map, for `status`/`doctor`; a control command never writes it. */
  readonly releaseFirstSeen: Readonly<Record<string, number>>;
  /** The same for the list's OS images (S11b). */
  readonly osImageFirstSeen: Readonly<Record<string, number>>;
}

/** What a setter may inject: the acceptance clock and the lock's wait/pid seam (the tests). */
export interface ControlCommandOptions {
  readonly nowMs?: number;
  readonly lock?: ControlLockOptions;
}

/** The control file is the current document; the state file is consulted only for migration. */
export async function readControlView(stateFile: string, controlFile: string): Promise<ControlView> {
  const state = await createFileStateStore(stateFile).read();
  const inspection = inspectControlFile(controlFile);
  if (inspection.kind === "ok") {
    return { control: inspection.control, source: "control", lastVersion: state.state.lastVersion, releaseFirstSeen: state.state.releaseFirstSeen, osImageFirstSeen: state.state.osImageFirstSeen ?? {} };
  }
  if (inspection.kind === "malformed") {
    // The file is the authority and it is unreadable: never fall back to the stale legacy pair, and
    // never throw. `status`/`doctor` print the source; only a setter refuses.
    return { control: EMPTY_DAEMON_CONTROL, source: "malformed", lastVersion: state.state.lastVersion, releaseFirstSeen: state.state.releaseFirstSeen, osImageFirstSeen: state.state.osImageFirstSeen ?? {} };
  }
  if (state.legacyControl !== null) {
    return { control: state.legacyControl, source: "legacy", lastVersion: state.state.lastVersion, releaseFirstSeen: state.state.releaseFirstSeen, osImageFirstSeen: state.state.osImageFirstSeen ?? {} };
  }
  return { control: EMPTY_DAEMON_CONTROL, source: "empty", lastVersion: state.state.lastVersion, releaseFirstSeen: state.state.releaseFirstSeen, osImageFirstSeen: state.state.osImageFirstSeen ?? {} };
}

/**
 * The read side of a setter, under the lock: a malformed control file is a usage refusal (only
 * ENOENT is missing), and a missing one migrates the legacy state pair once.
 */
async function readWritableControl(stateFile: string, controlFile: string): Promise<ControlView> {
  const state = await createFileStateStore(stateFile).read();
  const inspection = inspectControlFile(controlFile);
  if (inspection.kind === "malformed") {
    throw new RelayKitError(
      "usage",
      `control.json ${controlFile} is malformed; repair or remove it (the pause flag and accepted releases live in this file, so it is never overwritten)`,
    );
  }
  if (inspection.kind === "ok") {
    return { control: inspection.control, source: "control", lastVersion: state.state.lastVersion, releaseFirstSeen: state.state.releaseFirstSeen, osImageFirstSeen: state.state.osImageFirstSeen ?? {} };
  }
  if (state.legacyControl !== null) {
    return { control: state.legacyControl, source: "legacy", lastVersion: state.state.lastVersion, releaseFirstSeen: state.state.releaseFirstSeen, osImageFirstSeen: state.state.osImageFirstSeen ?? {} };
  }
  return { control: EMPTY_DAEMON_CONTROL, source: "empty", lastVersion: state.state.lastVersion, releaseFirstSeen: state.state.releaseFirstSeen, osImageFirstSeen: state.state.osImageFirstSeen ?? {} };
}

/** Run one locked read-modify-write of `control.json`. */
async function withControlLock(
  controlFile: string,
  stateFile: string,
  options: ControlCommandOptions,
  edit: (control: DaemonControl) => DaemonControl,
): Promise<ControlView> {
  const lock = await acquireControlLock(controlLockFile(controlFile), options.lock ?? {});
  try {
    const view = await readWritableControl(stateFile, controlFile);
    const next = edit(view.control);
    await createFileControlStore(controlFile).write(next);
    return { ...view, control: next };
  } finally {
    lock.release();
  }
}

/** Persist `paused` in `control.json`, keeping the accepted set (and migrating it once). */
export async function setPausedState(controlFile: string, stateFile: string, paused: boolean, options: ControlCommandOptions = {}): Promise<ControlView> {
  return withControlLock(controlFile, stateFile, options, (control) => withPaused(control, paused));
}

/**
 * The agent's first sight of a compose hash or (S11b) an OS image hash, from its state file, or null when it has none.
 * The agent persists a sight before it acts on it, and an acceptance counts only when its stamp is at or after it
 * (R27); `releases accept` reads this to stamp after it. An unreadable state file has no sight.
 */
export async function readFirstSight(stateFile: string, kind: "release" | "os_image", hash: string): Promise<number | null> {
  const { state } = await createFileStateStore(stateFile).read();
  const firstSeen = kind === "release" ? state.releaseFirstSeen : (state.osImageFirstSeen ?? {});
  return firstSeen[hash] ?? null;
}

/**
 * Add one hash (a compose hash, or an OS image hash, S11b) to `control.json`'s accepted set, stamped
 * now, keeping `paused` and the rest; an earlier rejection of it is withdrawn.
 */
export async function acceptReleaseState(controlFile: string, stateFile: string, composeHash: string, options: ControlCommandOptions = {}): Promise<ControlView> {
  const acceptedAtMs = options.nowMs ?? Date.now();
  return withControlLock(controlFile, stateFile, options, (control) => withAcceptedRelease(control, composeHash, acceptedAtMs));
}

/**
 * The running agent's pairing acceptances (the config's `releases.accepted_at_pairing`): each hash accepted as
 * `releases accept` does, stamped `acceptedAtMs` (after the agent's first sight of it), and recorded in
 * `accepted_at_pairing`. Under the lock a hash the file rejects or already took at pairing is left alone.
 */
export async function acceptPairingReleasesState(controlFile: string, stateFile: string, hashes: readonly string[], acceptedAtMs: number, options: ControlCommandOptions = {}): Promise<ControlView> {
  return withControlLock(controlFile, stateFile, options, (control) => withPairingAcceptances(control, hashes, acceptedAtMs));
}

/** S11b's veto: add one hash to `control.json`'s rejected set; an acceptance of it is withdrawn. */
export async function rejectReleaseState(controlFile: string, stateFile: string, hash: string, options: ControlCommandOptions = {}): Promise<ControlView> {
  return withControlLock(controlFile, stateFile, options, (control) => withRejectedRelease(control, hash));
}

/** Withdraw a veto: the hash is judged by the normal rule again (its delay, or `releases accept`). */
export async function unrejectReleaseState(controlFile: string, stateFile: string, hash: string, options: ControlCommandOptions = {}): Promise<ControlView> {
  return withControlLock(controlFile, stateFile, options, (control) => withoutRejectedRelease(control, hash));
}

/**
 * S53: `image` becomes control.json's current relay image and the one it replaces the previous one (`fallback`, the
 * config's `stack.current_image`, when control.json names none). The caller has checked it is one of the relay's.
 */
export async function setStackImageState(controlFile: string, stateFile: string, image: string, fallback: string, options: ControlCommandOptions = {}): Promise<ControlView> {
  return withControlLock(controlFile, stateFile, options, (control) => withStackImage(control, image, fallback));
}

/**
 * P12: the running agent's one control.json member, the stack instance it adopted from Gray's answer once a boot's
 * quote proved it (null removes it). The same locked read-merge-write as the CLI's setters, so an operator command at
 * the same moment keeps its edit, and a malformed file is refused rather than overwritten.
 */
export async function setStackInstanceState(controlFile: string, stateFile: string, instance: DaemonStackInstance | null, options: ControlCommandOptions = {}): Promise<ControlView> {
  return withControlLock(controlFile, stateFile, options, (control) => withStackInstance(control, instance));
}
