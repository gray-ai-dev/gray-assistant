/**
 * The agent's refresher for the relay's own logins (owner decision 2026-10-23: the relay refreshes
 * its subscription tokens itself; Gray does not copy tokens to it).
 *
 * `gray-assistant run` calls `tick()` on the source-poll cadence. For every record in the logins
 * directory it refreshes the ones that are due (`refreshDueAtSeconds`), one at a time:
 *
 * 1. read the record, take and release the login's lock once (a lock this process cannot take, or a
 *    directory it cannot write, skips the refresh instead of spending the refresh token on an answer
 *    it could not store), then send the refresh token to the issuer the record was signed in with
 *    (`refreshCodexTokens`), without holding the lock, from the login's own address (`./proxy.ts`: its account's
 *    proxy, else `source.logins.proxy`, else this host; never another one when the account's proxy fails);
 * 2. take the login's lock, re-read, and write only if `family` and `generation` are still the ones
 *    read in step 1 (a sign-in in between wins; its family is new). The rotated refresh token is
 *    persisted in the same atomic rename as the new access token, before anything uses it;
 * 3. the next source poll sees the record's new mark in the account's `changeMark`, and the daemon
 *    pushes the new access token to every replica as a sealed update (`token_pushed`).
 *
 * A transient failure (network, 5xx, 429, an unreadable answer) is retried after
 * `retryAfterSeconds`, persisted as `next_attempt_at`, so a restart loop does not hammer the issuer.
 * A permanent one (401, `invalid_grant`, a refresh token the issuer calls expired, reused or
 * invalidated, a token for another ChatGPT account) marks the record `failed`: the file source then
 * reports the account `disabled` at once, and only a new `gray-assistant login codex --force` clears it.
 * OpenAI refusing this host's region (`unsupported_region`) marks it `failed` too, so the agent status
 * names the reason and nothing retries it from here, but its access token is served until it expires.
 * Inside `serveMarginSeconds` of the access token's expiry the account is `disabled` as well, so an
 * expired token is never sealed or picked. Each transition is one structured log line; the line
 * names the login and a closed code, never a token.
 *
 * Every decision is held in memory before it is written. When a write fails (a full or read-only
 * volume, a lock it cannot take), the record this process decided on — a rotated token family, a
 * backoff, a `failed` mark — stays in memory keyed to the stored record it replaces, every later
 * tick retries the write before anything else, and every decision is made from the in-memory record.
 * So a refresh token that was spent or refused is never sent again, the backoff and the `failed`
 * mark hold without the disk, and `view` lets the file source serve a rotated access token that is
 * not on disk yet. Only a stop with a write still failing loses it (`login_persist_failed` with
 * `lost`), and that is logged.
 */
import { chatgptTokenClaims, RelayConnectorError } from "@gray/relay-connector";
import { RelayKitError } from "../../errors.ts";
import type { DaemonLogEvent } from "../../daemon/types.ts";
import type { ControlLockOptions } from "../control-lock.ts";
import { CodexOAuthError, refreshCodexTokens, UNSUPPORTED_REGION_TEXT, type CodexOAuthEndpoint, type CodexTokens } from "./codex-oauth.ts";
import type { LoginRoute, LoginRoutes } from "./proxy.ts";
import { loginUsable, refreshDueAtSeconds, type LoginFailure, type LoginRecord, type LoginSettings } from "./record.ts";
import { listLoginNames, readLoginRecord, withLoginLock, writeLoginRecord } from "./store.ts";

export interface LoginRefresherOptions {
  readonly settings: LoginSettings & { readonly dir: string };
  /** The issuer and client the agent trusts; a record signed in elsewhere is refused. */
  readonly endpoint: Omit<CodexOAuthEndpoint, "timeoutMs">;
  /**
   * Where each login's refresh leaves from (`./proxy.ts`): its account's own proxy, else `source.logins.proxy`, else
   * the host, read at every refresh. A refresh whose route cannot be read is skipped, never sent from another address.
   * Absent: `endpoint.fetch` for every login.
   */
  readonly routes?: Pick<LoginRoutes, "route">;
  readonly nowMs: () => number;
  readonly log: (event: DaemonLogEvent) => void;
  /** Writes one record while the caller holds its lock. Default `writeLoginRecord`; tests pass one that throws. */
  readonly writeRecord?: (dir: string, record: LoginRecord) => void;
  /** The login lock's wait and holder rules. Default the control lock's. */
  readonly lock?: ControlLockOptions;
}

export interface LoginRefresher {
  /** Refresh every due login once. Never throws; every failure is a log line and a record field. */
  tick(signal?: AbortSignal): Promise<void>;
  /**
   * Start no further refresh and resolve when the one in flight has finished and been written. A
   * refresh is not aborted on stop: once the issuer has rotated the refresh token, the answer is the
   * only copy of the new one, and dropping it would leave a spent token on disk (the next refresh
   * would then be refused as `refresh_token_reused`). A record still unwritten is tried once more.
   */
  stop(): Promise<void>;
  /**
   * The record to serve for `name`, given the one `stored` on disk: the record this process decided
   * on and could not write yet while `stored` is still the record it replaces, else `stored`.
   */
  view(name: string, stored: LoginRecord | null): LoginRecord | null;
}

/** The access token's expiry: its JWT `exp`, or the answer's `expires_in` when that is sooner. */
export function accessExpiry(tokens: CodexTokens, nowSecs: number): { readonly expiresAt: number; readonly accountId: string } | null {
  let claims;
  try {
    claims = chatgptTokenClaims(tokens.accessToken);
  } catch (error) {
    if (error instanceof RelayConnectorError) return null;
    throw error;
  }
  const fromJwt = Number(claims.expiresAt);
  const fromAnswer = tokens.expiresInSeconds === null ? Number.POSITIVE_INFINITY : nowSecs + tokens.expiresInSeconds;
  return { expiresAt: Math.min(fromJwt, fromAnswer), accountId: claims.accountId };
}

/** The record after a successful refresh, or the permanent failure the answer amounts to. */
export function refreshedRecord(record: LoginRecord, tokens: CodexTokens, nowSecs: number): LoginRecord | LoginFailure {
  const expiry = accessExpiry(tokens, nowSecs);
  if (expiry === null || expiry.expiresAt <= nowSecs) return "invalid_access_token";
  if (expiry.accountId !== record.accountId) return "account_mismatch";
  return {
    ...record,
    generation: record.generation + 1,
    accessToken: tokens.accessToken,
    accessExpiresAt: expiry.expiresAt,
    // No refresh token in the answer means the issuer did not rotate it (manager.rs `persist_tokens`).
    refreshToken: tokens.refreshToken ?? record.refreshToken,
    refreshedAt: nowSecs,
    failures: 0,
    nextAttemptAt: null,
  };
}

/** A record this process decided on but has not written, and the stored record it replaces. */
interface Unsaved {
  readonly base: LoginRecord;
  readonly next: LoginRecord;
  /** Whether `login_persist_failed` was logged for this record (once, not once per tick). */
  alerted: boolean;
}

function sameIdentity(left: LoginRecord, right: LoginRecord): boolean {
  return left.family === right.family && left.generation === right.generation;
}

/**
 * The log code of a failed read, lock or write: the kit's code, `lock_held` when the login lock's
 * wait ran out (the `usage` error `acquireControlLock` ends a wait with; nothing else under
 * `withLoginLock` throws `usage` for a listed login name), or the OS error code (`ENOSPC`, `EROFS`,
 * `EACCES`, ...). Never a path or a message.
 */
function errorCode(error: unknown): string {
  if (error instanceof RelayKitError) return error.code === "usage" ? "lock_held" : error.code;
  const errno = (error as NodeJS.ErrnoException | null)?.code;
  return typeof errno === "string" && /^E[A-Z0-9]{1,15}$/u.test(errno) ? errno : "io";
}

export function createLoginRefresher(options: LoginRefresherOptions): LoginRefresher {
  const { settings } = options;
  const endpoint: CodexOAuthEndpoint = { ...options.endpoint, timeoutMs: settings.requestTimeoutMs };
  const writeRecord = options.writeRecord ?? writeLoginRecord;
  const lockOptions = options.lock ?? {};
  // One "token is about to expire" line per family and generation, not one per tick.
  const expiryAlerted = new Set<string>();
  const unreadable = new Set<string>();
  // The last code a skipped refresh was logged with, per login: one line until it changes or clears.
  const skipped = new Map<string, string>();
  const unsaved = new Map<string, Unsaved>();

  const nowSecs = (): number => Math.floor(options.nowMs() / 1000);

  /**
   * Under the login's lock, write `next` if the stored record is still `base` (true), or report that
   * it already is `next` (true: an earlier write landed and failed only afterwards, at the directory
   * fsync); false when the login changed meanwhile (a sign-in, a removal).
   */
  async function commit(base: LoginRecord, next: LoginRecord): Promise<boolean> {
    return withLoginLock(settings.dir, base.login, () => {
      const stored = readLoginRecord(settings.dir, base.login);
      if (stored === null) return false;
      if (sameIdentity(stored, base)) {
        writeRecord(settings.dir, next);
        return true;
      }
      return !sameIdentity(next, base) && sameIdentity(stored, next);
    }, lockOptions);
  }

  /** Try to write the login's unsaved record. It is forgotten once written or superseded. */
  async function flush(name: string): Promise<"saved" | "superseded" | "unsaved"> {
    const entry = unsaved.get(name);
    if (entry === undefined) return "saved";
    let written: boolean;
    try {
      written = await commit(entry.base, entry.next);
    } catch (error) {
      if (!entry.alerted) {
        entry.alerted = true;
        // The decision stays in memory and is served and retried on every tick.
        options.log({ level: "error", event: "login_persist_failed", login: name, code: errorCode(error), generation: entry.next.generation, kept: true });
      }
      return "unsaved";
    }
    if (unsaved.get(name) === entry) unsaved.delete(name);
    return written ? "saved" : "superseded";
  }

  /** Decide `next` in place of `stored`: held in memory first, then written if possible. */
  async function decide(name: string, stored: LoginRecord, next: LoginRecord): Promise<"saved" | "superseded" | "unsaved"> {
    unsaved.set(name, { base: stored, next, alerted: false });
    return flush(name);
  }

  /**
   * The record to decide from this tick: the stored one, or this process's unwritten one after one
   * more try to write it. Null when there is nothing to refresh this tick.
   */
  async function current(name: string, stored: LoginRecord | null): Promise<LoginRecord | null> {
    const entry = unsaved.get(name);
    // A login that reads as absent may be a passing read error; keep what is in memory and wait.
    if (entry === undefined || stored === null) return stored;
    if (!sameIdentity(stored, entry.base) && !sameIdentity(stored, entry.next)) {
      // A sign-in replaced the login while the write was failing; its record wins.
      unsaved.delete(name);
      options.log({ level: "warn", event: "login_refresh_superseded", login: name });
      return stored;
    }
    const outcome = await flush(name);
    if (outcome === "superseded") return null;
    if (outcome === "saved" && entry.alerted) options.log({ level: "info", event: "login_persisted", login: name, generation: entry.next.generation });
    return entry.next;
  }

  async function refreshOne(name: string, signal: AbortSignal | undefined): Promise<void> {
    let stored: LoginRecord | null;
    try {
      stored = readLoginRecord(settings.dir, name);
      unreadable.delete(name);
    } catch (error) {
      if (!unreadable.has(name)) {
        unreadable.add(name);
        options.log({ level: "error", event: "login_unreadable", login: name, code: errorCode(error) });
      }
      return;
    }
    const record = await current(name, stored);
    if (stored === null || record === null || record.failed !== null) return;
    const now = nowSecs();
    if (!loginUsable(record, now, settings.serveMarginSeconds)) {
      const key = `${record.family}:${record.generation}`;
      if (!expiryAlerted.has(key)) {
        expiryAlerted.add(key);
        options.log({ level: "error", event: "login_expiring", login: name, expires_at: record.accessExpiresAt, failures: record.failures });
      }
    }
    const due = refreshDueAtSeconds(record, settings.refreshLeadSeconds);
    if (due === null || now < due) return;
    if (record.issuer !== endpoint.issuer || record.clientId !== endpoint.clientId) {
      await fail(stored, record, "issuer_mismatch");
      return;
    }
    // The address the refresh leaves from: the account's own proxy when it has one. When `accounts.json` cannot be
    // read the refresh is skipped like a lock it cannot take: another address would be a guess, and the token stays
    // unspent for the next tick.
    let route: LoginRoute | null = null;
    // The answer will have to be written under this lock; a lock this process cannot take now (a
    // live holder past the wait, a directory it may not write) skips the refresh, and the token
    // stays unspent for the next tick.
    try {
      if (options.routes !== undefined) route = options.routes.route(name);
      await withLoginLock(settings.dir, name, () => undefined, lockOptions);
      skipped.delete(name);
    } catch (error) {
      const code = errorCode(error);
      if (skipped.get(name) !== code) {
        skipped.set(name, code);
        options.log({ level: "warn", event: "login_refresh_skipped", login: name, code });
      }
      return;
    }
    // Which path the refresh took, for its log lines (`account_proxy`, `logins_proxy`, `host`); never a URL.
    const via = route === null ? {} : { via: route.via.kind };
    let tokens: CodexTokens;
    try {
      // Only this route's fetch: a proxy that cannot be reached fails the refresh, never sends it from elsewhere.
      tokens = await refreshCodexTokens(route === null ? endpoint : { ...endpoint, fetch: route.fetch }, record.refreshToken, signal);
    } catch (error) {
      const code = error instanceof CodexOAuthError ? error.code : "network";
      if (error instanceof CodexOAuthError && error.permanent) {
        await fail(stored, record, code as LoginFailure);
        return;
      }
      const next: LoginRecord = { ...record, failures: record.failures + 1, nextAttemptAt: nowSecs() + settings.retryAfterSeconds };
      // Held in memory even when the write fails, so no tick retries before `next_attempt_at`.
      await decide(name, stored, next);
      options.log({ level: "warn", event: "login_refresh_failed", login: name, code, failures: next.failures, retry_in_s: settings.retryAfterSeconds, ...via });
      return;
    }
    const next = refreshedRecord(record, tokens, nowSecs());
    if (typeof next === "string") {
      await fail(stored, record, next);
      return;
    }
    const outcome = await decide(name, stored, next);
    if (outcome === "superseded") {
      options.log({ level: "warn", event: "login_refresh_superseded", login: name });
      return;
    }
    options.log({
      level: "info",
      event: "login_refreshed",
      login: name,
      generation: next.generation,
      expires_at: next.accessExpiresAt,
      rotated: tokens.refreshToken !== null,
      persisted: outcome === "saved",
      ...via,
    });
  }

  async function fail(stored: LoginRecord, record: LoginRecord, code: LoginFailure): Promise<void> {
    // Held in memory even when the write fails: this family's refresh token is never sent again.
    await decide(record.login, stored, { ...record, failed: code, failedAt: nowSecs(), nextAttemptAt: null });
    options.log({
      level: "error",
      event: "login_failed",
      login: record.login,
      code,
      action: "gray-assistant login codex --force",
      // The access token is still served until it expires; the new sign-in must come from a supported region.
      ...(code === "unsupported_region" ? { expires_at: record.accessExpiresAt, detail: UNSUPPORTED_REGION_TEXT } : {}),
    });
  }

  let stopped = false;
  async function pass(signal: AbortSignal | undefined): Promise<void> {
    for (const name of listLoginNames(settings.dir)) {
      if (stopped || signal?.aborted === true) return;
      try {
        await refreshOne(name, signal);
      } catch (error) {
        options.log({ level: "error", event: "login_refresh_failed", login: name, code: error instanceof RelayKitError ? error.code : "internal" });
      }
    }
  }

  /** On stop: one last write of each unwritten record; what still fails is lost with the process. */
  async function flushAll(): Promise<void> {
    for (const [name, entry] of [...unsaved]) {
      if ((await flush(name)) !== "unsaved") continue;
      const rotated = !sameIdentity(entry.base, entry.next);
      options.log({ level: "error", event: "login_persist_failed", login: name, generation: entry.next.generation, lost: true, ...(rotated ? { action: "gray-assistant login codex --force" } : {}) });
    }
  }

  // Passes run one after another, never two at once (two would send the same refresh token twice,
  // and the second send is a reuse). A call while one pass runs queues one more, which starts after
  // it and so sees the caller's clock; a call while one is already queued shares that one.
  let tail: Promise<void> = Promise.resolve();
  let scheduled = 0;
  let stopping: Promise<void> | null = null;
  return {
    tick(signal?: AbortSignal): Promise<void> {
      if (scheduled >= 2) return tail;
      scheduled += 1;
      tail = tail
        .then(() => pass(signal))
        .catch(() => undefined)
        .finally(() => {
          scheduled -= 1;
        });
      return tail;
    },
    stop(): Promise<void> {
      stopped = true;
      stopping ??= tail.then(flushAll).catch(() => undefined);
      return stopping;
    },
    view(name: string, stored: LoginRecord | null): LoginRecord | null {
      const entry = unsaved.get(name);
      return entry !== undefined && stored !== null && sameIdentity(stored, entry.base) ? entry.next : stored;
    },
  };
}
