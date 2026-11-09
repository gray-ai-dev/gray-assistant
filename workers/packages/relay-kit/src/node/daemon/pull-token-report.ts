/**
 * Delivery of pull-token issue reports to Gray (S13): each issue the agent recorded is signed and
 * POSTed to `<stack.report_origin>/v1/lane-stack/pull-token-issues`, beside the token answer and never
 * in its way. A report that is not answered 2xx is sent again, with a doubling pause (1 s up to 10 min)
 * and no limit on attempts; the console stores a report once, so a repeat is harmless.
 *
 * The local issue record is the queue's memory: an issue counts as reported once its id is appended to
 * `<issue_log>.reported` (0600, append-only like the record), and a starting agent queues every
 * recorded issue whose id is not there. A 400 is the one answer that is not retried (the console says
 * the report is not one; sending it again cannot help), and it is logged.
 */
import { closeSync, constants, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { asStr, get, parseStrict } from "@gray/json";
import type { PullTokenIssue } from "../../daemon/pull-token.ts";
import { PULL_TOKEN_ISSUE_REPORT_PATH, pullTokenIssueRecord, pullTokenIssueReport } from "../../daemon/pull-token-report.ts";
import type { DaemonLog } from "../../daemon/types.ts";

/** The most unreported issues kept in memory; past it the oldest wait for the next start (they stay in the record). */
export const MAX_PENDING_ISSUE_REPORTS = 1000;
const FIRST_RETRY_MS = 1000;
const MAX_RETRY_MS = 600_000;

/** One POST; the agent passes global `fetch`, tests a fake. Resolves with the status, rejects on transport failure. */
export type IssueReportPost = (url: string, body: string) => Promise<number>;

export interface PullTokenReporterOptions {
  /** `<report_origin>` + the console's path. */
  readonly reportOrigin: string;
  readonly relayId: string;
  /** The relay key's 32-byte seed (its lane record's signing key). */
  readonly seed: Uint8Array;
  /** The S13 record (`stack.issue_log`); `<issue_log>.reported` sits beside it. */
  readonly issueLog: string;
  readonly post?: IssueReportPost;
  readonly log: DaemonLog;
  /** A timer seam for tests; returns a cancel function. */
  readonly setTimer?: (run: () => void, ms: number) => () => void;
}

export interface PullTokenReporter {
  /** Queue one issue; returns at once. */
  enqueue(issue: PullTokenIssue): void;
  /** Try every queued report now (the timer calls it; tests may). Resolves when the round is done. */
  flush(): Promise<void>;
  pending(): number;
  stop(): void;
}

/** The ids already reported, from `<issue_log>.reported`. */
function reportedIds(path: string): Set<string> {
  try {
    return new Set(readFileSync(path, "utf8").split("\n").filter((line) => line !== ""));
  } catch {
    return new Set();
  }
}

/** The recorded issues, oldest first; a line this version did not write (no `issue_id`) is skipped. */
function recordedIssues(path: string): PullTokenIssue[] {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  const out: PullTokenIssue[] = [];
  for (const line of text.split("\n")) {
    if (line === "") continue;
    try {
      // The agent's own line (pullTokenIssueLine); a torn or doubled one is skipped like any other.
      const value = parseStrict(line);
      const issueId = asStr(get(value, "issue_id"));
      const at = asStr(get(value, "at"));
      // v1.7: null for a token with no known expiry (the config has no stack.registry.expires_at).
      const expiresAt = get(value, "expires_at") === null ? null : asStr(get(value, "expires_at"));
      const atMs = at === undefined ? Number.NaN : Date.parse(at);
      const expiresAtMs = expiresAt === null ? null : expiresAt === undefined ? Number.NaN : Date.parse(expiresAt);
      if (issueId === undefined || expiresAt === undefined || !Number.isFinite(atMs) || (expiresAtMs !== null && !Number.isFinite(expiresAtMs))) continue;
      out.push({
        issueId,
        atMs,
        composeHash: String(get(value, "compose_hash")),
        quoteSha256: String(get(value, "quote_sha256")),
        // S54: lines from before S54 carry no nonce; the report to Gray does not name it either way.
        nonce: asStr(get(value, "nonce")) ?? "",
        relayImage: String(get(value, "relay_image")),
        expiresAt,
        expiresAtMs,
      });
    } catch {
      continue;
    }
  }
  return out;
}

function appendLine(path: string, line: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const descriptor = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
  try {
    writeSync(descriptor, `${line}\n`, null, "utf8");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

const defaultPost: IssueReportPost = async (url, body) => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": "gray-assistant" },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(20_000),
  });
  await response.arrayBuffer().catch(() => undefined);
  return response.status;
};

const defaultTimer = (run: () => void, ms: number): (() => void) => {
  const timer = setTimeout(run, ms);
  timer.unref?.();
  return () => clearTimeout(timer);
};

export function createPullTokenReporter(options: PullTokenReporterOptions): PullTokenReporter {
  const url = `${options.reportOrigin}${PULL_TOKEN_ISSUE_REPORT_PATH}`;
  const reportedPath = `${resolve(options.issueLog)}.reported`;
  const post = options.post ?? defaultPost;
  const setTimer = options.setTimer ?? defaultTimer;
  const queue = new Map<string, PullTokenIssue>();
  let retryMs = FIRST_RETRY_MS;
  let cancel: (() => void) | null = null;
  let running: Promise<void> | null = null;
  let stopped = false;

  const add = (issue: PullTokenIssue): void => {
    if (queue.has(issue.issueId)) return;
    if (queue.size >= MAX_PENDING_ISSUE_REPORTS) {
      const oldest = queue.keys().next().value as string;
      queue.delete(oldest);
      options.log({ level: "warn", event: "pull_token_report_dropped", issue_id: oldest, reason: "queue_full" });
    }
    queue.set(issue.issueId, issue);
  };

  const schedule = (ms: number): void => {
    if (stopped || cancel !== null) return;
    cancel = setTimer(() => {
      cancel = null;
      void flush();
    }, ms);
  };

  const round = async (): Promise<void> => {
    let failed = false;
    for (const [issueId, issue] of [...queue]) {
      if (stopped) return;
      let status: number;
      try {
        const report = await pullTokenIssueReport(pullTokenIssueRecord(options.relayId, issue), options.seed);
        status = await post(url, JSON.stringify(report));
      } catch {
        failed = true;
        options.log({ level: "warn", event: "pull_token_report_failed", issue_id: issueId, code: "transport" });
        continue;
      }
      if (status >= 200 && status < 300) {
        try {
          appendLine(reportedPath, issueId);
        } catch {
          // Unmarked, it is sent again after the next start; the console stores it once.
        }
        queue.delete(issueId);
        options.log({ level: "info", event: "pull_token_reported", issue_id: issueId });
      } else if (status === 400) {
        queue.delete(issueId);
        options.log({ level: "error", event: "pull_token_report_refused", issue_id: issueId, status });
      } else {
        failed = true;
        options.log({ level: "warn", event: "pull_token_report_failed", issue_id: issueId, status });
      }
    }
    if (queue.size === 0) {
      retryMs = FIRST_RETRY_MS;
    } else if (failed) {
      schedule(retryMs);
      retryMs = Math.min(retryMs * 2, MAX_RETRY_MS);
    } else {
      // Issues queued while this round ran.
      schedule(0);
    }
  };

  const flush = async (): Promise<void> => {
    if (running !== null) return running;
    // Running now replaces a scheduled round.
    cancel?.();
    cancel = null;
    running = round().finally(() => {
      running = null;
    });
    return running;
  };

  // What an earlier run recorded and did not report.
  const reported = reportedIds(reportedPath);
  for (const issue of recordedIssues(options.issueLog)) if (!reported.has(issue.issueId)) add(issue);
  if (queue.size > 0) schedule(0);

  return {
    enqueue(issue: PullTokenIssue): void {
      add(issue);
      if (running === null && cancel === null) schedule(0);
    },
    flush,
    pending(): number {
      return queue.size;
    },
    stop(): void {
      stopped = true;
      cancel?.();
      cancel = null;
    },
  };
}
