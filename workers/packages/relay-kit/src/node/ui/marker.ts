/**
 * How the agent knows the local page runs, so its signed status (S45) can carry `ui_port` and Gray's panel can link to
 * `http://127.0.0.1:<ui_port>/…`. The page may run in another process than the agent (`gray-assistant ui` beside `gray-assistant
 * run`, or in another container on the same state volume), so it says so in a small file beside `state.json`:
 * `ui.json`, `{"port": 7470, "written_at_ms": …}`, 0600, rewritten every `UI_MARKER_EVERY_MS` while the page runs and
 * removed when it stops. The agent counts it only while it is fresh (`UI_MARKER_FRESH_MS`), so a page that died without
 * removing it drops out of the status within minutes. The port is not a secret; the file holds nothing else.
 */
import { unlinkSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parsePlain, toJsonString } from "@gray/json";
import { writeAtomicPrivateFile } from "../daemon/atomic-file.ts";
import { readPrivateFile } from "../files.ts";

/** How often a running page rewrites its marker. */
export const UI_MARKER_EVERY_MS = 60_000;
/** How long a marker counts after it was written: three rewrites. */
export const UI_MARKER_FRESH_MS = 3 * UI_MARKER_EVERY_MS;

export function uiMarkerPath(stateFile: string): string {
  return join(dirname(resolve(stateFile)), "ui.json");
}

export function writeUiMarker(path: string, port: number, nowMs: number): void {
  writeAtomicPrivateFile(path, `${toJsonString({ port: BigInt(port), written_at_ms: BigInt(Math.trunc(nowMs)) })}\n`);
}

export function removeUiMarker(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    // Already gone, or never written.
  }
}

/** The port a fresh marker names; null for no marker, a stale one or anything unreadable. */
export function readUiPort(path: string, nowMs: number): number | null {
  try {
    const value = parsePlain(readPrivateFile(path, "ui marker", 1024)) as { port?: unknown; written_at_ms?: unknown } | null;
    if (value === null || typeof value !== "object") return null;
    const { port, written_at_ms: writtenAt } = value;
    if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65_535) return null;
    if (typeof writtenAt !== "number" || nowMs - writtenAt > UI_MARKER_FRESH_MS || writtenAt - nowMs > UI_MARKER_FRESH_MS) return null;
    return port;
  } catch {
    return null;
  }
}
