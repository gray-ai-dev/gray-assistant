/**
 * The operator's release decisions, shared by `gray-assistant releases accept|reject|unreject` and the local page
 * (`./ui/api.ts`): judge an id against the current signed release list, then write `control.json` under its lock
 * (`./control.ts`). Nothing here prints; each caller words the outcome its own way.
 */
import type { RelayDaemonConfig } from "../daemon/config.ts";
import { RelayKitError } from "../errors.ts";
import { acceptReleaseState, readFirstSight, rejectReleaseState, unrejectReleaseState, type ControlView } from "./control.ts";

/** The signed list `releases` judges ids against; a list that cannot be read is one usage-free refusal. */
export async function releaseListForCommand(config: { readonly daemon: Pick<RelayDaemonConfig, "lane"> }, nowMs: number) {
  const { fetchReleaseList, ReleaseListError } = await import("../daemon/releases.ts");
  const { createPlainDaemonFetch } = await import("./release-list-source.ts");
  try {
    return await fetchReleaseList(createPlainDaemonFetch(), config.daemon.lane.releaseList, {
      publicKey: config.daemon.lane.releasePublicKey,
      maxAgeSeconds: config.daemon.lane.releaseListMaxAgeSeconds,
      nowMs,
      freshness: config.daemon.lane.releaseFreshness,
    });
  } catch (error) {
    // The closed codes name what failed (fetch_failed, bad_signature, stale, …) and, D137, which part
    // is stale; never the body.
    if (error instanceof ReleaseListError) {
      throw new RelayKitError("io", `the signed release list: ${error.code}${error.staleness === null ? "" : ` (${error.staleness})`}`);
    }
    throw error;
  }
}

/** A counted acceptance: the stamp is at or after the agent's first sight of the hash, so the agent honours it. */
interface CountedAcceptance {
  readonly ok: true;
  /** The agent's first sight of the hash (the state file's), and the stamp written, never before it. */
  readonly firstSeenMs: number;
  readonly acceptedAtMs: number;
  /** Whether the command had to wait for the agent to see the hash first. */
  readonly waited: boolean;
  readonly view: ControlView;
}

/** What `releases accept <id>` did. */
export type AcceptReleaseOutcome =
  | (CountedAcceptance & { readonly kind: "release"; readonly composeHash: string; readonly gitCommit: string | null })
  | (CountedAcceptance & {
      readonly kind: "os_image";
      readonly osImageHash: string;
      /** `ok`, or `osImageProvenance`'s code when the entry does not prove a production image. */
      readonly provenance: string;
    })
  | { readonly ok: false; readonly code: "os_image_dev" | "not_listed" }
  | {
      readonly ok: false;
      /**
       * The agent has no first sight of the hash (its state file names none), so no acceptance could count (R27):
       * the agent is not running, the caller did not wait, or the agent did not see it within the wait.
       */
      readonly code: "not_seen";
      readonly kind: "release" | "os_image";
      readonly hash: string;
      readonly agentRunning: boolean;
      readonly waitedMs: number;
    };

/** How `acceptReleaseId` waits for the agent's first sight of a hash it has not seen yet. */
export interface FirstSightWait {
  /** The longest wait; 0 refuses at once. */
  readonly waitMs: number;
  /** Whether an agent runs for this config (a fresh status file); a stopped agent records no sight, so it is not waited for. */
  readonly agentRunning: boolean;
  readonly sleep: (ms: number) => Promise<void>;
  /** Called once, when the wait starts (the CLI says what it waits for). */
  readonly onWait?: (hash: string) => void;
}

/** How often the wait re-reads the state file: the agent's tick is a second by default. */
const FIRST_SIGHT_POLL_MS = 1_000;

/**
 * Accept a release of the signed list by its compose hash, git commit or tag, or one of its OS images by hash
 * (S11b). A dstack dev image is never accepted; an unlisted id is refused. Writes `control.json`.
 *
 * An acceptance counts only when its stamp is at or after the agent's first sight of the hash (R27), so this never
 * reports one that does not. When the state file already holds the sight, the stamp is now (never before the sight).
 * When it does not and the agent runs, a first acceptance is written: it does not count, but it makes the agent read
 * Gray's list at once (`#reloadControl`) instead of at its next `release_poll`. Once the state file shows the sight,
 * the acceptance is stamped again, after it. With no sight at the end of the wait, or no agent to wait for, the
 * outcome is `not_seen`, and the caller says the acceptance does not count and what to do.
 */
export async function acceptReleaseId(
  config: { readonly daemon: Pick<RelayDaemonConfig, "lane" | "stateFile"> },
  controlFile: string,
  id: string,
  now: () => number,
  wait: FirstSightWait,
): Promise<AcceptReleaseOutcome> {
  const verified = await releaseListForCommand(config, now());
  const entry = verified.list.releases.find((release) => release.compose_hash === id || release.git_commit === id || release.git_tag === id);
  // S11b: an OS image of the list is accepted the same way, by its hash.
  const osImage = entry === undefined ? verified.list.osImages.find((image) => image.os_image_hash === id) : undefined;
  if (entry === undefined && osImage === undefined) return { ok: false, code: "not_listed" };
  let provenance = "ok";
  if (osImage !== undefined) {
    const { osImageProvenance } = await import("@gray/lane-verify");
    const proven = osImageProvenance(osImage);
    // A verified dev image is refused whatever is accepted; recording it would mislead.
    if (proven.ok && proven.isDev) return { ok: false, code: "os_image_dev" };
    provenance = proven.ok ? "ok" : proven.code;
  }
  const kind = entry === undefined ? "os_image" : "release";
  const hash = entry === undefined ? id : entry.compose_hash;
  const stateFile = config.daemon.stateFile;
  let firstSeenMs = await readFirstSight(stateFile, kind, hash);
  let waited = false;
  if (firstSeenMs === null) {
    if (wait.waitMs <= 0 || !wait.agentRunning) return { ok: false, code: "not_seen", kind, hash, agentRunning: wait.agentRunning, waitedMs: 0 };
    await acceptReleaseState(controlFile, stateFile, hash, { nowMs: now() });
    wait.onWait?.(hash);
    let waitedMs = 0;
    while (firstSeenMs === null && waitedMs < wait.waitMs) {
      await wait.sleep(FIRST_SIGHT_POLL_MS);
      waitedMs += FIRST_SIGHT_POLL_MS;
      firstSeenMs = await readFirstSight(stateFile, kind, hash);
    }
    if (firstSeenMs === null) return { ok: false, code: "not_seen", kind, hash, agentRunning: true, waitedMs };
    waited = true;
  }
  // Never before the sight, even when this host's clock stepped back since the agent recorded it.
  const acceptedAtMs = Math.max(now(), firstSeenMs);
  const view = await acceptReleaseState(controlFile, stateFile, hash, { nowMs: acceptedAtMs });
  const counted = { ok: true as const, firstSeenMs, acceptedAtMs, waited, view };
  return entry === undefined
    ? { ...counted, kind: "os_image", osImageHash: hash, provenance }
    : { ...counted, kind: "release", composeHash: hash, gitCommit: entry.git_commit };
}

/**
 * S11b's veto. `reject` takes a compose hash or an OS image hash from the current signed list (as `accept` does)
 * and records it in `control.json`'s `rejected_releases`; `unreject` removes it, also for a hash that has since
 * left the list, so a stale veto can always be cleared.
 */
export async function vetoRelease(
  config: { readonly daemon: Pick<RelayDaemonConfig, "lane" | "stateFile"> },
  controlFile: string,
  verb: "reject" | "unreject",
  hash: string,
  nowMs: number,
): Promise<{ readonly ok: true; readonly view: ControlView } | { readonly ok: false; readonly code: "not_listed" }> {
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new RelayKitError("usage", `releases ${verb} takes a compose hash or an OS image hash (64 lower-case hex)`);
  if (verb === "reject") {
    const verified = await releaseListForCommand(config, nowMs);
    const listed = verified.list.releases.some((release) => release.compose_hash === hash) || verified.list.osImages.some((image) => image.os_image_hash === hash);
    if (!listed) return { ok: false, code: "not_listed" };
  }
  const view = verb === "reject" ? await rejectReleaseState(controlFile, config.daemon.stateFile, hash) : await unrejectReleaseState(controlFile, config.daemon.stateFile, hash);
  return { ok: true, view };
}
