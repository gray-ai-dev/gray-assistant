/**
 * What the running agent last said about itself, for the local page: the status snapshot `gray-assistant run` writes after
 * every tick (`../daemon/status-file.ts`), read the way `gray-assistant status` reads it. The page is often open while the
 * agent is not running (a first install, a restart), so every member here says "unknown" rather than guessing.
 */
import { get, isObject, type Json, type JsonObject } from "@gray/json";
import type { LoadedRelayConfig } from "../config-file.ts";
import { readDaemonStatusFile } from "../daemon/status-file.ts";

/** Whether the agent runs, by its snapshot's age (R23's rule, as `gray-assistant status`). */
export type UiAgentState = "running" | "stopped" | "stale" | "not_running";

/** One replica (lane origin) as the page shows it. */
export interface UiReplica {
  readonly origin: string;
  readonly phase: string;
  readonly lastError: string | null;
  readonly lastPushAtMs: number | null;
}

/** Where one account's credential is, by the agent's last snapshot. */
export interface UiSealed {
  /** `sealed` on every serving replica; `partly` on some; `waiting` on none yet; `parked` excluded with a reason. */
  readonly state: "sealed" | "partly" | "waiting" | "parked" | "unknown";
  readonly version: string | null;
  readonly atMs: number | null;
  readonly reason: string | null;
}

export interface UiReleaseRow {
  readonly kind: "release" | "os_image";
  readonly hash: string;
  readonly gitCommit: string | null;
  readonly version: string | null;
  readonly firstSeenMs: number | null;
  readonly acceptableAtMs: number | null;
  readonly acceptable: boolean;
  readonly accepted: boolean;
  /** The acceptance is the one `init --pair` recorded (the release was in Gray's list when the relay paired). */
  readonly acceptedAtPairing: boolean;
  readonly rejected: boolean;
  /** Why an OS image is not acceptable (`os_image_dev`, `os_image_unverified`, …); null otherwise. */
  readonly refusal: string | null;
}

export interface UiAgentView {
  readonly state: UiAgentState;
  /** When the snapshot was written; null without one. */
  readonly asOfMs: number | null;
  readonly ready: boolean;
  readonly reasons: readonly string[];
  readonly paused: boolean;
  readonly sourceHealthy: boolean | null;
  readonly sourceLastPollAtMs: number | null;
  readonly replicas: readonly UiReplica[];
  readonly releases: readonly UiReleaseRow[];
  readonly releaseList: { readonly currentUntilMs: number | null; readonly lastError: string | null } | null;
  /** Per source id: the replicas that hold it, with the sealing version and time. */
  readonly sealedBySource: ReadonlyMap<string, readonly { readonly origin: string; readonly version: string; readonly atMs: number }[]>;
  /** Per source id: why the agent parked it. */
  readonly parkedBySource: ReadonlyMap<string, string>;
  /** The relay tunnel and its CT monitor's verdict (status.json's `tunnel`, `../tunnel/status.ts`); null without one. */
  readonly tunnel: UiTunnel | null;
}

/** The relay tunnel as the page shows it: its word, its name, and how many certificates CT shows that it did not obtain. */
export interface UiTunnel {
  readonly state: "connected" | "down";
  readonly name: string;
  readonly ct: { readonly state: "ok" | "alert" | "unknown"; readonly findings: number; readonly checkedMs: number | null } | null;
}

function objectOf(value: Json | undefined): JsonObject | null {
  return isObject(value) ? value : null;
}

function arrayOf(value: Json | undefined): readonly Json[] {
  return Array.isArray(value) ? value : [];
}

function numeric(value: Json | undefined): number | null {
  return typeof value === "number" ? value : typeof value === "bigint" ? Number(value) : null;
}

function text(value: Json | undefined): string | null {
  return typeof value === "string" ? value : null;
}

const EMPTY: Omit<UiAgentView, "state" | "asOfMs"> = {
  ready: false,
  reasons: [],
  paused: false,
  sourceHealthy: null,
  sourceLastPollAtMs: null,
  replicas: [],
  releases: [],
  releaseList: null,
  sealedBySource: new Map(),
  parkedBySource: new Map(),
  tunnel: null,
};

/** The snapshot's `tunnel` member as the page reads it; null for none or one this version cannot read. */
function tunnelOf(value: JsonObject | null): UiTunnel | null {
  if (value === null) return null;
  const state = text(get(value, "state"));
  const name = text(get(value, "name"));
  if ((state !== "connected" && state !== "down") || name === null) return null;
  const ct = objectOf(get(value, "ct"));
  const ctState = ct === null ? null : text(get(ct, "state"));
  return {
    state,
    name,
    ct: ct === null || (ctState !== "ok" && ctState !== "alert" && ctState !== "unknown") ? null : { state: ctState, findings: arrayOf(get(ct, "findings")).length, checkedMs: numeric(get(ct, "checked_ms")) },
  };
}

/** Read the agent's snapshot; a missing or unreadable one is `not_running`. */
export function readAgentView(config: LoadedRelayConfig, nowMs: number): UiAgentView {
  let snapshot: JsonObject | null;
  try {
    snapshot = readDaemonStatusFile(config.daemon.statusFile);
  } catch {
    snapshot = null;
  }
  if (snapshot === null) return { state: "not_running", asOfMs: null, ...EMPTY };
  const status = objectOf(get(snapshot, "status"));
  const health = objectOf(get(snapshot, "health"));
  const writtenAt = numeric(get(snapshot, "written_at_ms"));
  const reasons = health === null ? [] : arrayOf(get(health, "reasons")).map(String);
  // R23: older than 3 ticks + one 60 s request timeout is not a running agent.
  const staleAfterMs = 3 * config.daemon.tickMs + 60_000;
  const stale = writtenAt === null || nowMs - writtenAt > staleAfterMs;
  const state: UiAgentState = reasons.includes("stopped") ? "stopped" : stale ? "stale" : "running";
  const source = status === null ? null : objectOf(get(status, "source"));
  const replicas: UiReplica[] = [];
  const sealed = new Map<string, { origin: string; version: string; atMs: number }[]>();
  for (const value of status === null ? [] : arrayOf(get(status, "replicas"))) {
    const replica = objectOf(value);
    if (replica === null) continue;
    const origin = text(get(replica, "origin")) ?? "";
    replicas.push({ origin, phase: text(get(replica, "phase")) ?? "unknown", lastError: text(get(replica, "last_error")), lastPushAtMs: numeric(get(replica, "last_push_at_ms")) });
    for (const item of arrayOf(get(replica, "sealed_accounts"))) {
      const account = objectOf(item);
      const sourceId = account === null ? null : text(get(account, "source_id"));
      const version = account === null ? null : text(get(account, "version"));
      const atMs = account === null ? null : numeric(get(account, "at_ms"));
      if (sourceId === null || version === null || atMs === null) continue;
      const list = sealed.get(sourceId) ?? [];
      list.push({ origin, version, atMs });
      sealed.set(sourceId, list);
    }
  }
  const parked = new Map<string, string>();
  for (const value of status === null ? [] : arrayOf(get(status, "parked"))) {
    const account = objectOf(value);
    const sourceId = account === null ? null : (text(get(account, "source_id")) ?? text(get(account, "account_id")));
    if (sourceId !== null) parked.set(sourceId, text(get(account as JsonObject, "reason")) ?? "parked");
  }
  const releases: UiReleaseRow[] = [];
  for (const value of status === null ? [] : arrayOf(get(status, "releases"))) {
    const release = objectOf(value);
    if (release === null) continue;
    releases.push({
      kind: "release",
      hash: text(get(release, "compose_hash")) ?? "",
      gitCommit: text(get(release, "git_commit")),
      version: null,
      firstSeenMs: numeric(get(release, "first_seen_ms")),
      acceptableAtMs: numeric(get(release, "acceptable_at_ms")),
      acceptable: get(release, "acceptable") === true,
      accepted: get(release, "accepted") === true,
      acceptedAtPairing: get(release, "accepted_at_pairing") === true,
      rejected: get(release, "rejected") === true,
      refusal: null,
    });
  }
  for (const value of status === null ? [] : arrayOf(get(status, "os_images"))) {
    const image = objectOf(value);
    if (image === null) continue;
    releases.push({
      kind: "os_image",
      hash: text(get(image, "os_image_hash")) ?? "",
      gitCommit: null,
      version: text(get(image, "version")),
      firstSeenMs: numeric(get(image, "first_seen_ms")),
      acceptableAtMs: numeric(get(image, "acceptable_at_ms")),
      acceptable: get(image, "acceptable") === true,
      accepted: get(image, "accepted") === true,
      acceptedAtPairing: get(image, "accepted_at_pairing") === true,
      rejected: get(image, "rejected") === true,
      refusal: text(get(image, "refusal")),
    });
  }
  const list = status === null ? null : objectOf(get(status, "release_list"));
  return {
    state,
    asOfMs: writtenAt,
    ready: health !== null && get(health, "ready") === true && state === "running",
    reasons,
    paused: status !== null && get(status, "paused") === true,
    sourceHealthy: source === null ? null : get(source, "healthy") === true,
    sourceLastPollAtMs: source === null ? null : numeric(get(source, "last_poll_at_ms")),
    replicas,
    releases: releases.filter((row) => row.hash !== ""),
    releaseList: list === null ? null : { currentUntilMs: numeric(get(list, "current_until_ms")), lastError: text(get(list, "last_error")) },
    sealedBySource: sealed,
    parkedBySource: parked,
    tunnel: tunnelOf(objectOf(get(snapshot, "tunnel"))),
  };
}

/**
 * Where one account's credential is. `editedAtMs` is when this page last changed the account: until the agent's
 * source poll has read the file after that edit, the account waits, whatever an older seal said.
 */
export function sealedState(agent: UiAgentView, sourceId: string, options: { readonly editedAtMs: number | null; readonly selected: boolean; readonly active: boolean }): UiSealed {
  if (agent.state !== "running") return { state: "unknown", version: null, atMs: null, reason: null };
  const parked = agent.parkedBySource.get(sourceId);
  if (parked !== undefined) return { state: "parked", version: null, atMs: null, reason: parked };
  if (!options.selected) return { state: "parked", version: null, atMs: null, reason: "not_selected" };
  if (!options.active) return { state: "parked", version: null, atMs: null, reason: "status" };
  const held = agent.sealedBySource.get(sourceId) ?? [];
  const newest = held.reduce<{ version: string; atMs: number } | null>((best, item) => (best === null || item.atMs > best.atMs ? item : best), null);
  if (newest === null) return { state: "waiting", version: null, atMs: null, reason: null };
  if (options.editedAtMs !== null && newest.atMs < options.editedAtMs) return { state: "waiting", version: newest.version, atMs: newest.atMs, reason: "edited" };
  const serving = agent.replicas.filter((replica) => replica.phase === "serving").length;
  return { state: serving > 0 && held.length < serving ? "partly" : "sealed", version: newest.version, atMs: newest.atMs, reason: null };
}
