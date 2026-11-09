/**
 * The local page's own record of what it changed and who signed in: `ui-audit.jsonl` beside `state.json`, one JSON line
 * per event, appended with mode 0600. It names the action, its target (an account id, a login, a release hash), the
 * outcome and who did it (the passkey's id prefix in public mode, "link" for a one-time link on 127.0.0.1); never a key,
 * a token, a code or a cookie. A failed write is ignored: the page still works without its record.
 */
import { appendFileSync, chmodSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { toJsonString, type JsonObject } from "@gray/json";

export interface UiAuditEntry {
  readonly action: string;
  /** Who: `passkey:<first 12 characters of its id>` or `link`. */
  readonly who: string | null;
  readonly target?: string | null;
  readonly outcome: string;
}

export function uiAuditPath(stateFile: string): string {
  return join(dirname(resolve(stateFile)), "ui-audit.jsonl");
}

export function appendUiAudit(path: string, mode: "loopback" | "public", entry: UiAuditEntry, nowMs: number): void {
  const line: JsonObject = { at_ms: BigInt(Math.trunc(nowMs)), mode, action: entry.action, who: entry.who, target: entry.target ?? null, outcome: entry.outcome };
  try {
    const created = !existsSync(path);
    appendFileSync(path, `${toJsonString(line)}\n`, { mode: 0o600 });
    if (created) chmodSync(path, 0o600);
  } catch {
    // The record is a convenience for the operator; the action already happened or was refused.
  }
}
