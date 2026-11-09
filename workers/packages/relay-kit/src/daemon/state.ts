/**
 * The daemon's one durable document (design v2 §A.2, critique R21, K5-3):
 *
 * ```json
 * {"configured_origins":["https://lane.example"],"last_version":41,
 *  "os_image_first_seen":{"<os image hash>":1790000000000},
 *  "release_first_seen":{"<compose hash>":1790000000000}}
 * ```

 * `os_image_first_seen` (S11b) is the same first-sight record for the OS images of the list. A file
 * written before S11b has no such member: the daemon then adopts the OS images listed at its first
 * poll as seen long ago (they were already trusted), and its next write adds the member. A state
 * file that is missing or lost adopts nothing.
 *
 * It holds only the fields the agent owns: the version counter, when the relay first saw each
 * release, and the lane origins the last started process was configured with (so an origin removed
 * from the config by a later start still gets its signed whole-relay revoke, R28). `paused` and `accepted_releases` moved to the CLI-owned `control.json`
 * (`src/daemon/control.ts`) so a concurrent CLI control edit and a daemon version write can never
 * erase each other. The old four-member shape is still *read* for one migration: the legacy fields
 * come back in `DaemonStateLoad.legacyControl` and the daemon adopts them at start when there is no
 * control file yet. Every write emits the current shape, so the daemon's next state write
 * drops the legacy fields.
 *
 * `last_version` is a decimal integer in the file (the workspace's u64 rule), so a 64-bit value is
 * exact. The Node implementation (`src/node/daemon/state-file.ts`) writes it by atomic rename +
 * fsync; this module is the pure shape and an in-memory store for tests and workerd.
 */
import { toJsonString, type JsonObject } from "@gray/json";
import { z } from "zod";
import { RelayKitError } from "../errors.ts";
import type { DaemonControl, DaemonState, DaemonStateLoad, DaemonStateStore } from "./types.ts";

const HASH = /^[0-9a-f]{64}$/;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** The empty state: version 0, no releases or OS images seen (so nothing is adopted, S11b). */
export const EMPTY_DAEMON_STATE: DaemonState = Object.freeze({
  lastVersion: 0n,
  releaseFirstSeen: Object.freeze({}),
  osImageFirstSeen: Object.freeze({}),
  configuredOrigins: Object.freeze([]),
});

const stateSchema = z
  .object({
    last_version: z.union([z.bigint().min(0n).max(U64_MAX), z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)]),
    release_first_seen: z.record(z.string().regex(HASH), z.union([z.bigint().min(0n), z.number().int().min(0)])),
    // S11b. Optional so a pre-S11b file parses; its absence is what arms the one-time adoption.
    os_image_first_seen: z.record(z.string().regex(HASH), z.union([z.bigint().min(0n), z.number().int().min(0)])).optional(),
    // R28: the lane origins of the last start. Optional so a pre-R28 file (and its tests) parse.
    configured_origins: z.array(z.string().max(2048)).max(16).optional(),
    // The pre-K5-3 control fields. Optional so both the current and the legacy shape parse.
    paused: z.boolean().optional(),
    accepted_releases: z.array(z.string().regex(HASH)).max(1024).optional(),
  })
  .strict();

/** One parsed state document: the daemon's two fields and any legacy control fields found. */
export interface ParsedDaemonState {
  readonly state: DaemonState;
  readonly legacyControl: DaemonControl | null;
}

/** Parse a state document, accepting the current shape and the one legacy shape. Never echoes it. */
export function parseDaemonStateDocument(value: unknown): ParsedDaemonState {
  const parsed = stateSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("usage", "invalid daemon state");
  const firstSeen = millisecondsOf(parsed.data.release_first_seen);
  const osImageFirstSeen = parsed.data.os_image_first_seen === undefined ? undefined : millisecondsOf(parsed.data.os_image_first_seen);
  const legacy = parsed.data.paused === undefined && parsed.data.accepted_releases === undefined
    ? null
    : {
        paused: parsed.data.paused ?? false,
        acceptedReleases: [...new Set(parsed.data.accepted_releases ?? [])].sort(),
      };
  return {
    state: {
      lastVersion: typeof parsed.data.last_version === "bigint" ? parsed.data.last_version : BigInt(parsed.data.last_version),
      releaseFirstSeen: firstSeen,
      ...(osImageFirstSeen === undefined ? {} : { osImageFirstSeen }),
      configuredOrigins: [...new Set(parsed.data.configured_origins ?? [])].sort(),
    },
    legacyControl: legacy,
  };
}

function millisecondsOf(record: Readonly<Record<string, bigint | number>>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const key of Object.keys(record).sort()) {
    const seen = record[key] ?? 0;
    out[key] = typeof seen === "bigint" ? Number(seen) : seen;
  }
  return out;
}

/** The daemon's two fields from a state document (the legacy control pair is dropped). */
export function parseDaemonStateValue(value: unknown): DaemonState {
  return parseDaemonStateDocument(value).state;
}

/** The file value; `toJsonString` keeps the bigint an integer, not a float. */
export function daemonStateValue(state: DaemonState): JsonObject {
  const integers = (record: Readonly<Record<string, number>>): JsonObject => {
    const out: JsonObject = {};
    for (const key of Object.keys(record).sort()) out[key] = BigInt(record[key] as number);
    return out;
  };
  return {
    configured_origins: [...(state.configuredOrigins ?? [])],
    last_version: state.lastVersion,
    ...(state.osImageFirstSeen === undefined ? {} : { os_image_first_seen: integers(state.osImageFirstSeen) }),
    release_first_seen: integers(state.releaseFirstSeen),
  };
}

/** The exact bytes a state file holds. */
export function daemonStateText(state: DaemonState): string {
  return toJsonString(daemonStateValue(state));
}

/** An in-memory state store: tests and workerd, and the reference for the file's rules. */
export interface MemoryStateStore extends DaemonStateStore {
  current(): DaemonState;
  readonly writes: number;
  /** Force the next read to report a lost file (the version probe path). */
  lose(): void;
}

export function createMemoryStateStore(
  initial: Partial<DaemonState> = {},
  options: { readonly intact?: boolean; readonly legacyControl?: DaemonControl } = {},
): MemoryStateStore {
  let state: DaemonState = {
    lastVersion: initial.lastVersion ?? EMPTY_DAEMON_STATE.lastVersion,
    releaseFirstSeen: { ...(initial.releaseFirstSeen ?? EMPTY_DAEMON_STATE.releaseFirstSeen) },
    ...(initial.osImageFirstSeen === undefined ? {} : { osImageFirstSeen: { ...initial.osImageFirstSeen } }),
    configuredOrigins: [...(initial.configuredOrigins ?? [])],
  };
  let legacyControl = options.legacyControl === undefined ? null : cloneControl(options.legacyControl);
  let intact = options.intact ?? true;
  let writes = 0;
  return {
    async read(): Promise<DaemonStateLoad> {
      return { state: cloneState(state), intact, legacyControl: legacyControl === null ? null : cloneControl(legacyControl) };
    },
    async write(next: DaemonState): Promise<void> {
      state = cloneState(next);
      legacyControl = null;
      writes += 1;
      intact = true;
    },
    current(): DaemonState {
      return cloneState(state);
    },
    get writes(): number {
      return writes;
    },
    lose(): void {
      state = cloneState(EMPTY_DAEMON_STATE);
      legacyControl = null;
      intact = false;
    },
  };
}

function cloneState(state: DaemonState): DaemonState {
  return {
    lastVersion: state.lastVersion,
    releaseFirstSeen: { ...state.releaseFirstSeen },
    ...(state.osImageFirstSeen === undefined ? {} : { osImageFirstSeen: { ...state.osImageFirstSeen } }),
    configuredOrigins: [...(state.configuredOrigins ?? [])],
  };
}

function cloneControl(control: DaemonControl): DaemonControl {
  return {
    paused: control.paused,
    acceptedReleases: [...control.acceptedReleases],
    ...(control.acceptedAtMs === undefined ? {} : { acceptedAtMs: { ...control.acceptedAtMs } }),
    ...(control.rejectedReleases === undefined ? {} : { rejectedReleases: [...control.rejectedReleases] }),
  };
}
