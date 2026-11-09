/**
 * Delivery of the agent status to Gray (S45; the document is `../../daemon/agent-status.ts`): signed and POSTed to
 * `<stack.report_origin>/v1/lane-stack/agent-status`, beside the agent's own work and never in its way.
 *
 * - **When.** `check()` (run.ts calls it every `AGENT_STATUS_CHECK_MS`) builds the status and compares it with the
 *   last one Gray took, leaving out its times (`agentStatusChangeKey`): a change is sent once
 *   `AGENT_STATUS_MIN_INTERVAL_MS` (60 s) has passed since the last one Gray took; with no change the status is sent
 *   again after `AGENT_STATUS_HEARTBEAT_MS` (15 min), so the panel can tell a silent agent (`agent_silent`, two missed
 *   heartbeats) from a quiet one. `sendSoon()` (S58: the token service refused a booting VM with a new code) sends the
 *   newest status at once instead, past the minute's spacing but at most once per `AGENT_STATUS_URGENT_MS` (10 s); a
 *   failing send keeps its retry pause.
 * - **Retries.** A send that is not answered 2xx is tried again with the pull-token reporter's pause (1 s doubling to
 *   10 min, no limit on attempts), each time with the newest status, signed afresh: only the newest matters, the
 *   console keeps one. A 400 is not retried (the console says the body is not a status; the same one cannot pass) and
 *   is logged as an error; the next change or heartbeat sends again.
 * - **What it remembers.** Only in memory: after a restart the first check sends at once (run.ts makes the first
 *   check once the daemon's first tick read the release list and the source, at most `AGENT_STATUS_FIRST_WAIT_MS`
 *   after the start). `state()` is what
 *   `gray-assistant status` and `doctor` read, through the status snapshot.
 * - **The answer's instance (P12).** A 2xx answer names the relay's lane instance (`instance`,
 *   `@gray/control/stack-provision` `stackInstanceAnswerSchema`): it is handed to `onInstance` (the daemon adopts it
 *   only once a boot's quote proves it) before `send` resolves, and the last one is kept in `state()`. A malformed one
 *   is ignored with `agent_instance_malformed`; an older console's answer has none.
 *
 * `createAgentLoginReader` reads the relay's logins for the status: the records in the logins directory (as `doctor`
 * lists them) through the refresher's view, and which accounts of `accounts.json` name each.
 */
import { statSync } from "node:fs";
import { stackInstanceAnswerSchema, type StackInstanceAnswer } from "@gray/control/stack-provision";
import { get, isObject, parseStrict, toJsonString, type JsonObject } from "@gray/json";
import { AGENT_STATUS_PATH, agentStatusChangeKey, signAgentStatus, type AgentLogin } from "../../daemon/agent-status.ts";
import type { DaemonLog } from "../../daemon/types.ts";
import { readPrivateFile } from "../files.ts";
import { loginAgentView, type LoginRecord, type LoginSettings } from "../login/record.ts";
import { listLoginNames, readLoginRecord } from "../login/store.ts";
import { loginAccountIds } from "../source/file.ts";
import { MAX_SOURCE_FILE_BYTES } from "../source/limits.ts";

/** S45: a change is sent at most once a minute, and a status at least every 15 minutes. */
export const AGENT_STATUS_MIN_INTERVAL_MS = 60_000;
export const AGENT_STATUS_HEARTBEAT_MS = 15 * 60_000;
/** How often the agent looks for a change; a change waits for the minute's spacing anyway. */
export const AGENT_STATUS_CHECK_MS = 10_000;
/**
 * The longest the first status after a start waits for the daemon's first reads of the release list and the source
 * (run.ts; each read's own requests time out after 20 s). Gray's relay-stack steps name it as the first report's
 * bound (provider-setup/relay-stack.ts FIRST_REPORT_WITHIN_MS).
 */
export const AGENT_STATUS_FIRST_WAIT_MS = 45_000;
/** S58: a refusal of a booting VM sends the status at once, at most once per 10 s. */
export const AGENT_STATUS_URGENT_MS = 10_000;
const FIRST_RETRY_MS = 1000;
const MAX_RETRY_MS = 600_000;

/** One POST: Gray's status and up to 4 KiB of its answer. Rejects on a transport failure. */
export type AgentStatusPost = (url: string, body: string) => Promise<{ readonly status: number; readonly body: string }>;

/** What the agent last reported, for `gray-assistant status` and `doctor` (the status snapshot's `agent_status`). */
export interface AgentStatusReportState {
  /** The last status sent: when it was issued (and sent); null before the first. */
  readonly lastIssuedMs: number | null;
  /** When Gray last took a status (2xx), and whether it kept it (`recorded: false`: it has a newer one). */
  readonly lastAcceptedAtMs: number | null;
  readonly recorded: boolean | null;
  /** The last send Gray did not take: its HTTP status (null for no answer) and code; cleared when one is taken. */
  readonly lastFailure: { readonly status: number | null; readonly code: string; readonly atMs: number } | null;
  /** A changed status, or a failed one, waits to be sent. */
  readonly pending: boolean;
  /** When the next send is due; null when none is scheduled. */
  readonly nextAttemptAtMs: number | null;
  /** P12: the lane instance Gray's last answer named; null before one (or from a console that names none). */
  readonly instance?: StackInstanceAnswer | null;
}

export interface AgentStatusReporterOptions {
  /** `stack.report_origin`; the console's path is appended. */
  readonly reportOrigin: string;
  /** The relay key's 32-byte seed (its lane record's signing key). */
  readonly seed: Uint8Array;
  /** The unsigned status as of `nowMs` (`agentStatusDocument`). A throw skips that round and is logged once. */
  readonly build: (nowMs: number) => JsonObject;
  readonly nowMs: () => number;
  readonly post?: AgentStatusPost;
  readonly log: DaemonLog;
  /** P12: each well-formed `instance` of a 2xx answer, awaited before the send resolves (`RelayDaemon.onStackInstance`). */
  readonly onInstance?: (instance: StackInstanceAnswer) => Promise<void>;
  /** A timer seam for tests; returns a cancel function. */
  readonly setTimer?: (run: () => void, ms: number) => () => void;
}

export interface AgentStatusReporter {
  /** Build the status now and schedule its send: at once the first time, after the spacing on a change, else the heartbeat. */
  check(): Promise<void>;
  /** Send the newest status now (the timer's sends; tests). Resolves when the send and the check after it are done. */
  send(): Promise<void>;
  /** S58: send the newest status at once, past the minute's spacing, at most once per `AGENT_STATUS_URGENT_MS`. */
  sendSoon(): void;
  state(): AgentStatusReportState;
  stop(): void;
}

const defaultPost: AgentStatusPost = async (url, body) => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": "gray-assistant" },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(20_000),
  });
  const text = await response.text().catch(() => "");
  return { status: response.status, body: text.slice(0, 4096) };
};

const defaultTimer = (run: () => void, ms: number): (() => void) => {
  const timer = setTimeout(run, ms);
  timer.unref?.();
  return () => clearTimeout(timer);
};

/** The answer's `recorded`, or null when it has none. */
function recordedOf(body: string): boolean | null {
  try {
    const recorded = get(parseStrict(body), "recorded");
    return typeof recorded === "boolean" ? recorded : null;
  } catch {
    return null;
  }
}

/** P12: the answer's `instance`: null when it has none (an older console), `malformed` when it is not the schema's. */
function instanceOf(body: string): StackInstanceAnswer | null | "malformed" {
  let value: unknown;
  try {
    value = get(parseStrict(body), "instance");
  } catch {
    return null;
  }
  if (value === undefined) return null;
  const parsed = stackInstanceAnswerSchema.safeParse(value);
  return parsed.success ? parsed.data : "malformed";
}

/** The console's error code (`{"error": {"code": …}}`) when it is a closed word, else null. */
function codeOf(body: string): string | null {
  try {
    const error = get(parseStrict(body), "error");
    const code = isObject(error) ? get(error, "code") : undefined;
    return typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? code : null;
  } catch {
    return null;
  }
}

export function createAgentStatusReporter(options: AgentStatusReporterOptions): AgentStatusReporter {
  const url = `${options.reportOrigin}${AGENT_STATUS_PATH}`;
  const post = options.post ?? defaultPost;
  const setTimer = options.setTimer ?? defaultTimer;
  // The last status Gray took, or refused as no status (400), without its times, and when.
  let settledKey: string | null = null;
  let settledAtMs: number | null = null;
  let lastIssuedMs: number | null = null;
  let lastAcceptedAtMs: number | null = null;
  let recorded: boolean | null = null;
  let instance: StackInstanceAnswer | null = null;
  let lastFailure: AgentStatusReportState["lastFailure"] = null;
  let changed = false;
  let failing = false;
  let retryMs = FIRST_RETRY_MS;
  let cancel: (() => void) | null = null;
  let timerAtMs: number | null = null;
  let sending: Promise<void> | null = null;
  let buildFailed = false;
  let stopped = false;
  // S58: a send asked for at once, and when the last such send went.
  let urgent = false;
  let lastUrgentMs = Number.NEGATIVE_INFINITY;

  /** Schedule a send at `atMs`; an earlier one already scheduled stands. */
  const schedule = (atMs: number): void => {
    if (stopped || (cancel !== null && timerAtMs !== null && timerAtMs <= atMs)) return;
    cancel?.();
    timerAtMs = atMs;
    cancel = setTimer(
      () => {
        cancel = null;
        timerAtMs = null;
        void send();
      },
      Math.max(0, atMs - options.nowMs()),
    );
  };

  const build = (nowMs: number): JsonObject | null => {
    try {
      const status = options.build(nowMs);
      buildFailed = false;
      return status;
    } catch (error) {
      if (!buildFailed) options.log({ level: "error", event: "agent_status_build_failed", code: error instanceof Error ? error.name : "internal" });
      buildFailed = true;
      return null;
    }
  };

  async function check(): Promise<void> {
    // A send in flight checks again when it is done; a failed one waits for its retry.
    if (stopped || sending !== null || failing) return;
    const nowMs = options.nowMs();
    const status = build(nowMs);
    if (status === null) return;
    changed = agentStatusChangeKey(status) !== settledKey;
    if (settledAtMs === null) return schedule(nowMs);
    if (urgent && changed) return schedule(Math.max(nowMs, lastUrgentMs + AGENT_STATUS_URGENT_MS));
    // Nothing new to send at once: the status Gray has already says it.
    urgent = false;
    schedule(changed ? Math.max(nowMs, settledAtMs + AGENT_STATUS_MIN_INTERVAL_MS) : settledAtMs + AGENT_STATUS_HEARTBEAT_MS);
  }

  const fail = (nowMs: number, status: number | null, code: string): void => {
    failing = true;
    lastFailure = { status, code, atMs: nowMs };
    options.log({ level: "warn", event: "agent_status_report_failed", ...(status === null ? {} : { status }), code, retry_in_ms: retryMs });
    schedule(nowMs + retryMs);
    retryMs = Math.min(retryMs * 2, MAX_RETRY_MS);
  };

  async function round(): Promise<void> {
    const nowMs = options.nowMs();
    // This send carries what the urgent one was for.
    if (urgent) {
      urgent = false;
      lastUrgentMs = nowMs;
    }
    const status = build(nowMs);
    if (status === null) {
      // Nothing to send; look again at the next check.
      failing = false;
      return;
    }
    const key = agentStatusChangeKey(status);
    let answer: { readonly status: number; readonly body: string };
    try {
      const body = toJsonString(await signAgentStatus(status, options.seed));
      lastIssuedMs = nowMs;
      answer = await post(url, body);
    } catch {
      return fail(nowMs, null, "transport");
    }
    if (answer.status >= 200 && answer.status < 300) {
      settledKey = key;
      settledAtMs = nowMs;
      lastAcceptedAtMs = nowMs;
      recorded = recordedOf(answer.body);
      lastFailure = null;
      failing = false;
      retryMs = FIRST_RETRY_MS;
      options.log({ level: "info", event: "agent_status_reported", recorded: recorded ?? false });
      const named = instanceOf(answer.body);
      if (named === "malformed") {
        options.log({ level: "warn", event: "agent_instance_malformed" });
      } else if (named !== null) {
        instance = named;
        try {
          await options.onInstance?.(named);
        } catch (error) {
          options.log({ level: "error", event: "agent_instance_failed", code: error instanceof Error ? error.name : "internal" });
        }
      }
    } else if (answer.status === 400) {
      settledKey = key;
      settledAtMs = nowMs;
      lastFailure = { status: 400, code: codeOf(answer.body) ?? "invalid_request", atMs: nowMs };
      failing = false;
      retryMs = FIRST_RETRY_MS;
      options.log({ level: "error", event: "agent_status_report_refused", status: 400, code: lastFailure.code });
    } else {
      fail(nowMs, answer.status, codeOf(answer.body) ?? `http_${answer.status}`);
    }
  }

  async function send(): Promise<void> {
    if (stopped) return;
    if (sending !== null) return sending;
    // Sending now replaces a scheduled send (a retry keeps its own pause: it is scheduled again on failure).
    cancel?.();
    cancel = null;
    timerAtMs = null;
    sending = round().finally(() => {
      sending = null;
    });
    await sending;
    await check();
  }

  /** A send in flight checks again when it is done, and a failing one keeps its retry pause: both send the newest. */
  function sendSoon(): void {
    if (stopped) return;
    urgent = true;
    if (sending !== null || failing) return;
    void check();
  }

  return {
    check,
    send,
    sendSoon,
    state(): AgentStatusReportState {
      return { lastIssuedMs, lastAcceptedAtMs, recorded, lastFailure, pending: changed || failing, nextAttemptAtMs: timerAtMs, instance };
    },
    stop(): void {
      stopped = true;
      cancel?.();
      cancel = null;
      timerAtMs = null;
    },
  };
}

/** How long after the last status Gray took the report counts as current: a heartbeat and 5 minutes. */
export const AGENT_STATUS_CURRENT_MS = AGENT_STATUS_HEARTBEAT_MS + 5 * 60_000;

/** The next step for each answer of the console that sending again cannot fix. */
const REFUSAL_STEPS: Readonly<Record<string, string>> = {
  lane_stack_signature_invalid: "Gray holds another key for this relay (the one it paired, or its stack endpoint's lane record); pair this key (gray-assistant init --pair <code> --key <relay-key.json>)",
  lane_stack_relay_unknown: "Gray holds no key for this relay_id: register the relay in the panel and pair gray-assistant with it (or check relay_id)",
  lane_stack_agent_status_future: "this machine's clock is more than 5 minutes ahead; sync it (NTP)",
  lane_stack_agent_status_stale: "this machine's clock is more than an hour behind; sync it (NTP)",
  request_body_limit: "the status is over 256 KiB; report it to Gray",
  invalid_request: "Gray does not read this status; upgrade gray-assistant",
};

const ago = (ms: number): string => (ms < 120_000 ? `${Math.round(ms / 1000)} s` : `${Math.round(ms / 60_000)} min`);

/**
 * What `gray-assistant status` and `doctor` say of the agent status, from the snapshot's `agent_status` (`null`: the agent
 * has none, as without a `stack` section): `ok` while Gray took one within a heartbeat and 5 minutes and the last send
 * did not fail; `warn` while it is retrying a passing failure, or has not sent its first; `fail` for an answer sending
 * again cannot fix, or no status taken for longer than that.
 */
export function agentStatusVerdict(value: JsonObject | null, nowMs: number): { readonly status: "ok" | "warn" | "fail"; readonly message: string } {
  const num = (member: string, from: JsonObject | null = value): number | null => {
    const v = from === null ? undefined : get(from, member);
    return typeof v === "number" ? v : typeof v === "bigint" ? Number(v) : null;
  };
  const accepted = num("last_accepted_at_ms");
  const failureValue = value === null ? undefined : get(value, "last_failure");
  const failure = isObject(failureValue as never) ? (failureValue as JsonObject) : null;
  const next = num("next_attempt_at_ms");
  const retry = next === null ? "" : `; next try in ${ago(Math.max(0, next - nowMs))}`;
  const taken = accepted === null ? "Gray has taken none yet" : `Gray took the last one ${ago(nowMs - accepted)} ago`;
  if (failure !== null) {
    const code = String(get(failure, "code") ?? "unknown");
    const status = num("status", failure);
    const at = num("at_ms", failure);
    const what = `${status === null ? "no answer" : `${status}`} ${code}${at === null ? "" : ` ${ago(Math.max(0, nowMs - at))} ago`}`;
    // Own members only: the code is whatever Gray's answer named.
    const step = Object.hasOwn(REFUSAL_STEPS, code) ? REFUSAL_STEPS[code] : undefined;
    if (step !== undefined || status === 400) return { status: "fail", message: `the last report was refused (${what}): ${step ?? REFUSAL_STEPS.invalid_request}; ${taken}${retry}` };
    const current = accepted !== null && nowMs - accepted <= AGENT_STATUS_CURRENT_MS;
    return { status: current ? "warn" : "fail", message: `the last report failed (${what}), retrying; ${taken}${retry}` };
  }
  if (accepted === null) return { status: "warn", message: `no report taken yet${retry}` };
  if (nowMs - accepted > AGENT_STATUS_CURRENT_MS) return { status: "fail", message: `${taken}, longer than a heartbeat (15 min); is gray-assistant run running?` };
  const recorded = value === null ? null : get(value, "recorded");
  return { status: "ok", message: `reported; ${taken}${recorded === false ? " (it kept a newer one)" : ""}` };
}

/**
 * The relay's logins for the status: each record in `loginsDir` (sorted, as `doctor` lists them) through `view` (the
 * refresher's, so a rotation it could not write yet is what is reported), its state at `nowMs`
 * (`loginAgentView`), and the accounts of `accountsPath` that name it. `accounts.json` is read again only when its
 * size or time changed. A record that cannot be read is `unreadable`; one that went away meanwhile is left out.
 */
export function createAgentLoginReader(options: {
  readonly loginsDir: string;
  readonly accountsPath: string;
  readonly settings: Pick<LoginSettings, "refreshLeadSeconds" | "serveMarginSeconds">;
  readonly view?: (name: string, stored: LoginRecord | null) => LoginRecord | null;
}): (nowMs: number) => AgentLogin[] {
  let cached: { readonly key: string; readonly ids: Map<string, string[]> } | null = null;
  const accounts = (): Map<string, string[]> => {
    let key: string;
    try {
      const stat = statSync(options.accountsPath);
      key = `${stat.ino}:${stat.size}:${stat.mtimeMs}`;
    } catch {
      return new Map();
    }
    if (cached?.key === key) return cached.ids;
    let ids = new Map<string, string[]>();
    try {
      ids = loginAccountIds(parseStrict(readPrivateFile(options.accountsPath, "source accounts file", MAX_SOURCE_FILE_BYTES)));
    } catch {
      // The source's own read reports a broken file; the logins are still reported, with no accounts.
    }
    cached = { key, ids };
    return ids;
  };
  return (nowMs) => {
    const ids = accounts();
    const nowSecs = Math.floor(nowMs / 1000);
    const out: AgentLogin[] = [];
    for (const name of listLoginNames(options.loginsDir)) {
      const accountIds = ids.get(name) ?? [];
      let record: LoginRecord | null;
      try {
        const stored = readLoginRecord(options.loginsDir, name);
        record = options.view === undefined ? stored : options.view(name, stored);
      } catch {
        out.push({ login: name, state: "unreadable", failed: null, accessExpiresAtS: null, refreshedAtS: null, nextRefreshAtS: null, failures: null, accountIds });
        continue;
      }
      if (record === null) continue;
      out.push({ login: name, ...loginAgentView(record, nowSecs, options.settings), accountIds });
    }
    return out;
  };
}
