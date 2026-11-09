/**
 * The operator's control document, `control.json`, beside the daemon's state file:
 *
 * ```json
 * {"accepted_at_ms":{"<hash>":1790000000000},"accepted_releases":["<hash>"],"paused":false,
 *  "rejected_releases":["<hash>"],
 *  "stack_current_image":"<registry>/<repo>@sha256:<64 hex>","stack_previous_image":"<registry>/<repo>@sha256:<64 hex>",
 *  "stack_instance":{"adopted_ms":1790000000000,"app_id":"<40 hex>","kms_ca_pubkey":"<182 hex>","lane_origin":"https://…"}}
 * ```

 * A hash is a release's compose hash or, since S11b, an OS image hash from the same signed list:
 * `releases accept` takes either. `rejected_releases` (S11b) is the operator's veto: a rejected hash
 * is never acceptable, by delay or otherwise, until `releases accept` or `releases unreject` removes
 * it. The two sets are disjoint; accepting a hash clears its rejection and rejecting it clears its
 * acceptance.
 *
 * `accepted_at_ms` records when each acceptance was made. An acceptance only shortens a release's
 * first-sight delay when it is at or after that sight: a release the operator accepted, that Gray
 * then withdrew and that a still-fresh older list re-lists, waits a full new delay (R05/R27).
 *
 * `accepted_at_pairing` names the acceptances the agent made because `init --pair` recorded the releases Gray listed
 * when the relay paired (the config's `releases.accepted_at_pairing`). Each is an ordinary acceptance in
 * `accepted_releases`/`accepted_at_ms`, stamped at or after the agent's own first sight; this member says where it
 * came from and that it was made, so it is never made again (a withdrawn and re-listed release waits its delay). A
 * rejection removes the acceptance but not the record.
 *
 * `stack_current_image` and `stack_previous_image` (S53) are the relay image the token service names from now on
 * and the one before it: `gray-assistant stack rollout <image>` sets the first and moves the old one to the second,
 * `stack rollback` swaps them. The daemon still checks the current one against `stack.relay_images` at every token
 * request (an image removed from the config is never named, whatever this file says).
 *
 * `stack_instance` (P12, docs/relay-stack-provisioner.md §9) is the relay-stack instance adopted from Gray's answer
 * with `stack.instance: "gray"`, once a boot's quote proved it: the app id, its lane origin, the KMS CA key and when.
 * The running agent writes this member (`setStackInstanceState`) and its pairing acceptances (`acceptPairingReleasesState`),
 * under the same lock and read-merge-write as the CLI, so neither erases the other's edit.
 *
 * Only `gray-assistant pause|resume|releases accept|reject|unreject|stack rollout|rollback` write the rest (the CLI, in
 * `src/node/control.ts`, by atomic rename + fsync, 0600). A running daemon reads it at the start of every tick;
 * `DaemonControlStore` is read-only, so a daemon state write can never erase a control edit. The daemon's own state
 * file holds only the version ledger and first-seen times.
 *
 * This module is pure: the shape, the canonical text, the merge rules and an in-memory store for
 * tests and workerd. The Node file is `src/node/daemon/control-file.ts`.
 *
 * The document carries no credential, no token, no account id and no source id: a paused flag and
 * hashes from the public, signed release list.
 */
import { toJsonString, type JsonObject } from "@gray/json";
import { isStackRelayImage } from "@gray/lane-verify";
import { z } from "zod";
import { RelayKitError } from "../errors.ts";
import { APP_ID_PATTERN, KMS_CA_PUBKEY_PATTERN } from "../lane-binding.ts";
import { normalizeHttpsOrigin } from "../verified-report.ts";
import type { DaemonControl, DaemonControlLoad, DaemonControlStore, DaemonStackInstance } from "./types.ts";

const HASH = /^[0-9a-f]{64}$/;
/** S53's images, in the form the config takes (`isStackRelayImage`). */
const imageSchema = z.string().refine((value) => isStackRelayImage(value));
/** P12's adopted instance: the three values in the config's own forms, and when it was adopted. */
const stackInstanceSchema = z
  .object({
    app_id: z.string().regex(APP_ID_PATTERN),
    lane_origin: z.string().refine((value) => sameOrigin(value)),
    kms_ca_pubkey: z.string().regex(KMS_CA_PUBKEY_PATTERN),
    adopted_ms: z.union([z.bigint().min(0n), z.number().int().min(0)]),
  })
  .strict();

/** An https origin already in its normalized form (what the daemon writes). */
function sameOrigin(value: string): boolean {
  try {
    return normalizeHttpsOrigin(value) === value;
  } catch {
    return false;
  }
}

/** The empty control: not paused, no manual acceptances or rejections. */
export const EMPTY_DAEMON_CONTROL: DaemonControl = Object.freeze({
  paused: false,
  acceptedReleases: Object.freeze([]),
});

const controlSchema = z
  .object({
    paused: z.boolean(),
    accepted_releases: z.array(z.string().regex(HASH)).max(1024).optional(),
    accepted_at_ms: z.record(z.string().regex(HASH), z.union([z.bigint().min(0n), z.number().int().min(0)])).optional(),
    rejected_releases: z.array(z.string().regex(HASH)).max(1024).optional(),
    accepted_at_pairing: z.array(z.string().regex(HASH)).max(1024).optional(),
    stack_current_image: imageSchema.optional(),
    stack_previous_image: imageSchema.optional(),
    stack_instance: stackInstanceSchema.optional(),
  })
  .strict();

/** Parse a control document, refusing anything that is not exactly this shape. Never echoes it. */
export function parseDaemonControlValue(value: unknown): DaemonControl {
  const parsed = controlSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("usage", "invalid control file");
  const acceptedReleases = parsed.data.accepted_releases ?? [];
  const rejectedReleases = parsed.data.rejected_releases ?? [];
  const rawStamps = parsed.data.accepted_at_ms ?? {};
  const acceptedAtMs: Record<string, number> = {};
  const accepted = new Set(acceptedReleases);
  // No writer puts one hash in both sets; a file that does is not this document.
  if (rejectedReleases.some((hash) => accepted.has(hash))) throw new RelayKitError("usage", "invalid control file");
  for (const hash of Object.keys(rawStamps)) {
    if (!accepted.has(hash)) throw new RelayKitError("usage", "invalid control file");
    const at = rawStamps[hash] as bigint | number;
    const asNumber = typeof at === "bigint" ? (at <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(at) : Number.NaN) : at;
    if (!Number.isSafeInteger(asNumber)) throw new RelayKitError("usage", "invalid control file");
    acceptedAtMs[hash] = asNumber;
  }
  return normalizeControl({
    paused: parsed.data.paused,
    acceptedReleases,
    ...(Object.keys(acceptedAtMs).length === 0 ? {} : { acceptedAtMs }),
    ...(rejectedReleases.length === 0 ? {} : { rejectedReleases }),
    ...(parsed.data.accepted_at_pairing === undefined ? {} : { acceptedAtPairing: parsed.data.accepted_at_pairing }),
    ...(parsed.data.stack_current_image === undefined ? {} : { stackCurrentImage: parsed.data.stack_current_image }),
    ...(parsed.data.stack_previous_image === undefined ? {} : { stackPreviousImage: parsed.data.stack_previous_image }),
    ...(parsed.data.stack_instance === undefined ? {} : { stackInstance: stackInstanceOf(parsed.data.stack_instance) }),
  });
}

/** The file's `stack_instance` in memory; a time past the safe integers is not this document. */
function stackInstanceOf(value: z.infer<typeof stackInstanceSchema>): DaemonStackInstance {
  const at = value.adopted_ms;
  const adoptedMs = typeof at === "bigint" ? (at <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(at) : Number.NaN) : at;
  if (!Number.isSafeInteger(adoptedMs)) throw new RelayKitError("usage", "invalid control file");
  return { appId: value.app_id, laneOrigin: value.lane_origin, kmsCaPubkey: value.kms_ca_pubkey, adoptedMs };
}

/** The normalized control: acceptances are unique and sorted, so two writers agree on the bytes. */
export function normalizeControl(control: DaemonControl): DaemonControl {
  const acceptedReleases = [...new Set(control.acceptedReleases)].sort();
  const acceptedAtMs: Record<string, number> = {};
  const stamps = control.acceptedAtMs ?? {};
  for (const hash of acceptedReleases) {
    const at = stamps[hash];
    if (at !== undefined) acceptedAtMs[hash] = at;
  }
  const rejectedReleases = [...new Set(control.rejectedReleases ?? [])].sort();
  return {
    paused: control.paused,
    acceptedReleases,
    ...(Object.keys(acceptedAtMs).length === 0 ? {} : { acceptedAtMs }),
    ...(rejectedReleases.length === 0 ? {} : { rejectedReleases }),
    ...keptMembersOf(control),
  };
}

/** The pairing record and the S53 and P12 members a control carries, each only when set: no setter but their own changes them. */
function keptMembersOf(control: DaemonControl): Pick<DaemonControl, "acceptedAtPairing" | "stackCurrentImage" | "stackPreviousImage" | "stackInstance"> {
  const pairing = [...new Set(control.acceptedAtPairing ?? [])].sort();
  return {
    ...(pairing.length === 0 ? {} : { acceptedAtPairing: pairing }),
    ...(control.stackCurrentImage === undefined ? {} : { stackCurrentImage: control.stackCurrentImage }),
    ...(control.stackPreviousImage === undefined ? {} : { stackPreviousImage: control.stackPreviousImage }),
    ...(control.stackInstance === undefined ? {} : { stackInstance: control.stackInstance }),
  };
}

/** P12: the adopted stack instance set (or removed with null), everything else kept. */
export function withStackInstance(control: DaemonControl, instance: DaemonStackInstance | null): DaemonControl {
  const { stackInstance: _dropped, ...rest } = normalizeControl(control);
  return instance === null ? rest : { ...rest, stackInstance: { ...instance } };
}

/**
 * S53: `image` becomes the current relay image and the one it replaces (the control's, else `fallback`, the
 * config's) the previous one. Rolling out the current image again changes nothing.
 */
export function withStackImage(control: DaemonControl, image: string, fallback: string): DaemonControl {
  const current = normalizeControl(control);
  const was = current.stackCurrentImage ?? fallback;
  if (was === image) return current.stackCurrentImage === undefined ? { ...current, stackCurrentImage: image } : current;
  return { ...current, stackCurrentImage: image, stackPreviousImage: was };
}

/** `paused` changed, everything else kept. */
export function withPaused(control: DaemonControl, paused: boolean): DaemonControl {
  return { ...normalizeControl(control), paused };
}

/** One hash added to the accepted set, stamped at `acceptedAtMs` when given, and no longer rejected. */
export function withAcceptedRelease(control: DaemonControl, composeHash: string, acceptedAtMs?: number): DaemonControl {
  const current = normalizeControl(control);
  const accepted = new Set([...current.acceptedReleases, composeHash]);
  const stamps: Record<string, number> = { ...(current.acceptedAtMs ?? {}) };
  if (acceptedAtMs !== undefined) stamps[composeHash] = acceptedAtMs;
  return normalizeControl({
    paused: current.paused,
    acceptedReleases: [...accepted].sort(),
    ...(Object.keys(stamps).length === 0 ? {} : { acceptedAtMs: stamps }),
    rejectedReleases: (current.rejectedReleases ?? []).filter((hash) => hash !== composeHash),
    ...keptMembersOf(current),
  });
}

/**
 * The agent's pairing acceptances: each hash accepted as `releases accept` does, stamped `acceptedAtMs`, and recorded in
 * `accepted_at_pairing`. A hash the control already rejects (the operator's veto wins) or already took at pairing is
 * left alone, so the edit is right however the file changed since the agent decided.
 */
export function withPairingAcceptances(control: DaemonControl, hashes: readonly string[], acceptedAtMs: number): DaemonControl {
  let next = normalizeControl(control);
  const rejected = new Set(next.rejectedReleases ?? []);
  const taken = new Set(next.acceptedAtPairing ?? []);
  const fresh = [...new Set(hashes)].filter((hash) => !rejected.has(hash) && !taken.has(hash));
  for (const hash of fresh) next = withAcceptedRelease(next, hash, acceptedAtMs);
  return normalizeControl({ ...next, acceptedAtPairing: [...taken, ...fresh] });
}

/** S11b's veto: one hash added to the rejected set and removed from the accepted set (and its stamp). */
export function withRejectedRelease(control: DaemonControl, hash: string): DaemonControl {
  const current = normalizeControl(control);
  const stamps: Record<string, number> = { ...(current.acceptedAtMs ?? {}) };
  delete stamps[hash];
  return normalizeControl({
    paused: current.paused,
    acceptedReleases: current.acceptedReleases.filter((accepted) => accepted !== hash),
    acceptedAtMs: stamps,
    rejectedReleases: [...(current.rejectedReleases ?? []), hash],
    ...keptMembersOf(current),
  });
}

/** The veto withdrawn: the hash goes back to the normal rule (its delay, or a manual accept). */
export function withoutRejectedRelease(control: DaemonControl, hash: string): DaemonControl {
  const current = normalizeControl(control);
  return normalizeControl({ ...current, rejectedReleases: (current.rejectedReleases ?? []).filter((rejected) => rejected !== hash) });
}

/** The file value; `toJsonString` sorts the members and writes no float. */
export function daemonControlValue(control: DaemonControl): JsonObject {
  const normalized = normalizeControl(control);
  const acceptedAtMs: JsonObject = {};
  for (const hash of Object.keys(normalized.acceptedAtMs ?? {}).sort()) {
    acceptedAtMs[hash] = BigInt((normalized.acceptedAtMs as Record<string, number>)[hash] as number);
  }
  return {
    ...(Object.keys(acceptedAtMs).length === 0 ? {} : { accepted_at_ms: acceptedAtMs }),
    accepted_releases: [...normalized.acceptedReleases],
    paused: control.paused,
    // Written only when non-empty, so a control file without a veto keeps its bytes (k5 vectors).
    ...((normalized.rejectedReleases ?? []).length === 0 ? {} : { rejected_releases: [...(normalized.rejectedReleases as string[])] }),
    ...(normalized.acceptedAtPairing === undefined ? {} : { accepted_at_pairing: [...normalized.acceptedAtPairing] }),
    ...(normalized.stackCurrentImage === undefined ? {} : { stack_current_image: normalized.stackCurrentImage }),
    ...(normalized.stackPreviousImage === undefined ? {} : { stack_previous_image: normalized.stackPreviousImage }),
    ...(normalized.stackInstance === undefined
      ? {}
      : {
          stack_instance: {
            adopted_ms: BigInt(normalized.stackInstance.adoptedMs),
            app_id: normalized.stackInstance.appId,
            kms_ca_pubkey: normalized.stackInstance.kmsCaPubkey,
            lane_origin: normalized.stackInstance.laneOrigin,
          },
        }),
  };
}

/** The exact bytes a control file holds. */
export function daemonControlText(control: DaemonControl): string {
  return toJsonString(daemonControlValue(control));
}

/** The same bytes, or null for a control read that was not this shape. */
export function daemonControlTextOrNull(control: DaemonControl | null): string | null {
  return control === null ? null : daemonControlText(control);
}

/** An in-memory control store: tests and workerd, and the reference for the file's rules. */
export interface MemoryControlStore extends DaemonControlStore {
  current(): DaemonControl;
  readonly writes: number;
  /** Force the next read to report a missing/unreadable file (the migration path). */
  lose(): void;
  write(control: DaemonControl): Promise<void>;
}

export function createMemoryControlStore(initial: Partial<DaemonControl> = {}, options: { readonly intact?: boolean } = {}): MemoryControlStore {
  let control = normalizeControl({
    paused: initial.paused ?? EMPTY_DAEMON_CONTROL.paused,
    acceptedReleases: [...(initial.acceptedReleases ?? EMPTY_DAEMON_CONTROL.acceptedReleases)],
    ...(initial.acceptedAtMs === undefined ? {} : { acceptedAtMs: { ...initial.acceptedAtMs } }),
    ...(initial.rejectedReleases === undefined ? {} : { rejectedReleases: [...initial.rejectedReleases] }),
    ...(initial.acceptedAtPairing === undefined ? {} : { acceptedAtPairing: [...initial.acceptedAtPairing] }),
    ...(initial.stackCurrentImage === undefined ? {} : { stackCurrentImage: initial.stackCurrentImage }),
    ...(initial.stackPreviousImage === undefined ? {} : { stackPreviousImage: initial.stackPreviousImage }),
    ...(initial.stackInstance === undefined ? {} : { stackInstance: { ...initial.stackInstance } }),
  });
  let intact = options.intact ?? true;
  let writes = 0;
  return {
    async read(): Promise<DaemonControlLoad> {
      return { control: normalizeControl(control), intact };
    },
    async write(next: DaemonControl): Promise<void> {
      control = normalizeControl(next);
      writes += 1;
      intact = true;
    },
    current(): DaemonControl {
      return normalizeControl(control);
    },
    get writes(): number {
      return writes;
    },
    lose(): void {
      control = EMPTY_DAEMON_CONTROL;
      intact = false;
    },
  };
}
