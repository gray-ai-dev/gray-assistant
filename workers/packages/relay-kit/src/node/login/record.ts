/**
 * One relay login: the OAuth token family the relay holds for its own ChatGPT/Codex sign-in, as
 * `gray-assistant login codex` writes it and the agent's refresher rotates it. It lives only in the
 * agent's state volume, beside `state.json` (`<state dir>/logins/<name>.json`, 0600 in a 0700
 * directory); the kit's read-only `accounts.json` names it with
 * `"credential": {"type": "oauth_login", "login": "<name>"}` and never holds a token.
 *
 * ```json
 * {"api_version":1,"login":"codex-relay-1","vendor":"chatgpt_codex",
 *  "issuer":"https://auth.openai.com","client_id":"app_EMoamEEZ73f0CkXaXp7hrann",
 *  "family":"<32 hex, one per sign-in>","generation":4,"account_id":"<chatgpt_account_id claim>",
 *  "access_token":"<JWT>","access_expires_at":1790864000,"refresh_token":"<opaque>",
 *  "signed_in_at":1790000000,"refreshed_at":1790518400,
 *  "failures":0,"next_attempt_at":null,"failed":null,"failed_at":null}
 * ```
 *
 * `handed_to_vm_at` (optional, unix seconds) says the login's refresh token was sealed to the relay's VM for an
 * account whose Token refresh is `gray`: Gray's egress refreshes it there from then on, so this host never refreshes it
 * again (OpenAI rotates a refresh token on use; two refreshers break the login). Its tokens here are updated only from
 * the VM's write-back (`../source/file.ts`); a new sign-in clears the mark.
 *
 * `family` and `generation` are the record's identity: a sign-in starts a new family at generation
 * 1, every rotation adds one. A writer re-reads the record under the login's lock and writes only if
 * both are still what it started from, so a refresh that raced a new sign-in never overwrites it
 * (the Codex CLI's guarded persist, openai/codex rust-v0.164.0 codex-rs/login/src/auth/manager.rs
 * `persist_tokens`). `account_id` is the access token's `chatgpt_account_id` claim at sign-in; a
 * refreshed token for another account is refused (the same file's account-mismatch rule).
 *
 * This file is pure (no `node:` import), so the file source can use the decisions below in workerd
 * tests too. Nothing here prints a token.
 */
import { parsePlain, toJsonString, type JsonObject } from "@gray/json";
import { MAX_CREDENTIAL_LENGTH } from "@gray/relay-connector";
import { z } from "zod";
import { RelayKitError } from "../../errors.ts";

/** A login name: a file name under the logins directory, so lower-case, no dot, no slash. */
export const LOGIN_NAME = /^[a-z0-9][a-z0-9_-]{0,62}$/u;

export const LOGIN_RECORD_API_VERSION = 1;

/** The record's largest size: two tokens at the credential cap plus the metadata. */
export const MAX_LOGIN_RECORD_BYTES = 4 * MAX_CREDENTIAL_LENGTH + 64 * 1024;

/** Why a login stopped refreshing; each needs a new `gray-assistant login codex --force`. */
export const LOGIN_FAILURES = [
  "unauthorized",
  "invalid_grant",
  "refresh_token_expired",
  "refresh_token_reused",
  "refresh_token_invalidated",
  "account_mismatch",
  "invalid_access_token",
  "issuer_mismatch",
  "unsupported_region",
] as const;
export type LoginFailure = (typeof LOGIN_FAILURES)[number];

const unixSeconds = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER / 1000);
const token = z.string().min(1).max(MAX_CREDENTIAL_LENGTH).regex(/^[!-~]+$/u);

const recordSchema = z
  .object({
    api_version: z.literal(LOGIN_RECORD_API_VERSION),
    login: z.string().regex(LOGIN_NAME),
    vendor: z.literal("chatgpt_codex"),
    issuer: z.string().url().max(2048),
    client_id: z.string().min(1).max(256),
    family: z.string().regex(/^[0-9a-f]{32}$/u),
    generation: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    account_id: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/u),
    access_token: token,
    access_expires_at: unixSeconds,
    refresh_token: token,
    signed_in_at: unixSeconds,
    refreshed_at: unixSeconds.nullable(),
    failures: z.number().int().min(0).max(1_000_000),
    next_attempt_at: unixSeconds.nullable(),
    failed: z.enum(LOGIN_FAILURES).nullable(),
    failed_at: unixSeconds.nullable(),
    handed_to_vm_at: unixSeconds.optional(),
  })
  .strict();

/** The parsed record, camelCase. */
export interface LoginRecord {
  readonly login: string;
  readonly vendor: "chatgpt_codex";
  readonly issuer: string;
  readonly clientId: string;
  readonly family: string;
  readonly generation: number;
  readonly accountId: string;
  readonly accessToken: string;
  readonly accessExpiresAt: number;
  readonly refreshToken: string;
  readonly signedInAt: number;
  readonly refreshedAt: number | null;
  readonly failures: number;
  readonly nextAttemptAt: number | null;
  readonly failed: LoginFailure | null;
  readonly failedAt: number | null;
  /** When the refresh token was sealed to the VM for a `gray` account; absent while this host refreshes the login. */
  readonly handedToVmAt?: number;
}

/** Parse a record's text. Errors name a member, never a value (the record holds two tokens). */
export function parseLoginRecordText(text: string): LoginRecord {
  let value: unknown;
  try {
    value = parsePlain(text);
  } catch {
    throw new RelayKitError("invalid_login", "the login record is not JSON");
  }
  const parsed = recordSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new RelayKitError("invalid_login", issue === undefined ? "record" : issue.path.map(String).join(".") || "record");
  }
  const data = parsed.data;
  return {
    login: data.login,
    vendor: data.vendor,
    issuer: data.issuer,
    clientId: data.client_id,
    family: data.family,
    generation: data.generation,
    accountId: data.account_id,
    accessToken: data.access_token,
    accessExpiresAt: data.access_expires_at,
    refreshToken: data.refresh_token,
    signedInAt: data.signed_in_at,
    refreshedAt: data.refreshed_at,
    failures: data.failures,
    nextAttemptAt: data.next_attempt_at,
    failed: data.failed,
    failedAt: data.failed_at,
    ...(data.handed_to_vm_at === undefined ? {} : { handedToVmAt: data.handed_to_vm_at }),
  };
}

/** The record's text (integers as JSON integers, one trailing newline). */
export function loginRecordText(record: LoginRecord): string {
  const value: JsonObject = {
    api_version: BigInt(LOGIN_RECORD_API_VERSION),
    login: record.login,
    vendor: record.vendor,
    issuer: record.issuer,
    client_id: record.clientId,
    family: record.family,
    generation: BigInt(record.generation),
    account_id: record.accountId,
    access_token: record.accessToken,
    access_expires_at: BigInt(record.accessExpiresAt),
    refresh_token: record.refreshToken,
    signed_in_at: BigInt(record.signedInAt),
    refreshed_at: record.refreshedAt === null ? null : BigInt(record.refreshedAt),
    failures: BigInt(record.failures),
    next_attempt_at: record.nextAttemptAt === null ? null : BigInt(record.nextAttemptAt),
    failed: record.failed,
    failed_at: record.failedAt === null ? null : BigInt(record.failedAt),
    ...(record.handedToVmAt === undefined ? {} : { handed_to_vm_at: BigInt(record.handedToVmAt) }),
  };
  return `${toJsonString(value)}\n`;
}

/**
 * The tunables of the relay's logins (`source.logins` in the config), each with its source:
 *
 * - `refreshLeadSeconds` 345600 (96 h): CLIProxyAPI v8.0.40 sdk/cliproxy/auth/types.go
 *   `CodexOuterRefreshLead`, "before the nominal 10-day Codex OAuth JWT expiration, refreshing
 *   tokens well ahead of early upstream access-token invalidation". A token that lives shorter than
 *   twice the lead is refreshed at half its life instead (`refreshDueAtSeconds`), so a shorter
 *   token lifetime cannot turn every check into a refresh.
 * - `serveMarginSeconds` 300: openai/codex rust-v0.164.0 manager.rs
 *   `CHATGPT_ACCESS_TOKEN_REFRESH_WINDOW_MINUTES` (5): the Codex CLI does not send an access token
 *   that expires within 5 minutes. Inside the margin the account is `disabled`, never picked.
 * - `retryAfterSeconds` 300: CLIProxyAPI v8.0.40 sdk/cliproxy/auth/conductor_refresh.go
 *   `refreshFailureBackoff` (5 min) after a transient failure.
 * - `requestTimeoutMs` 30000: CLIProxyAPI v8.0.40 internal/auth/codex/openai_auth.go
 *   `codexRefreshTimeout`.
 */
export interface LoginSettings {
  /** Where the login records live; null when the config gives no state directory to derive it from. */
  readonly dir: string | null;
  readonly refreshLeadSeconds: number;
  readonly serveMarginSeconds: number;
  readonly retryAfterSeconds: number;
  readonly requestTimeoutMs: number;
  /**
   * `source.logins.proxy`: the http(s) proxy of the login exchanges whose account has no proxy of its own
   * (`./proxy.ts`), or null for none.
   */
  readonly proxy: string | null;
}

export const DEFAULT_LOGIN_REFRESH_LEAD_SECONDS = 96 * 3600;
export const DEFAULT_LOGIN_SERVE_MARGIN_SECONDS = 300;
export const DEFAULT_LOGIN_RETRY_AFTER_SECONDS = 300;
export const DEFAULT_LOGIN_REQUEST_TIMEOUT_MS = 30_000;

/**
 * Whether the record's access token may be sealed and picked at `nowSecs`. A failed login's is not, but for
 * `unsupported_region`: OpenAI refused the relay host's region before it read the refresh token, so the access token
 * is as good as it was, and its accounts are served until it expires (the TEE replicas send the requests, not this host).
 */
export function loginUsable(record: LoginRecord, nowSecs: number, serveMarginSeconds: number): boolean {
  return (record.failed === null || record.failed === "unsupported_region") && nowSecs < record.accessExpiresAt - serveMarginSeconds;
}

/**
 * When the next refresh is due: `refreshLeadSeconds` before the access token expires, but never
 * earlier than half the token's life (from the last refresh or the sign-in), and never before the
 * backoff's `next_attempt_at`. Null for a failed login, which waits for a new sign-in, and for one handed to the VM,
 * which egress refreshes there.
 */
export function refreshDueAtSeconds(record: LoginRecord, refreshLeadSeconds: number): number | null {
  if (record.failed !== null || record.handedToVmAt !== undefined) return null;
  const issuedAt = record.refreshedAt ?? record.signedInAt;
  const lifetime = Math.max(0, record.accessExpiresAt - issuedAt);
  const lead = Math.min(refreshLeadSeconds, Math.floor(lifetime / 2));
  const due = record.accessExpiresAt - lead;
  return record.nextAttemptAt === null ? due : Math.max(due, record.nextAttemptAt);
}

/**
 * How the agent status names a login (S45; `../../daemon/agent-status.ts`): `failed` once its refresh failed for
 * good; `expired` when its access token is past or inside the serve margin (its accounts are not served); `expiring`
 * while still served but inside its refresh lead (`refreshDueAtSeconds` without the backoff) with a failed refresh
 * behind it; `ok` otherwise. `nextRefreshAtS` is when the refresher tries next, null for a failed login.
 */
export function loginAgentView(
  record: LoginRecord,
  nowSecs: number,
  settings: Pick<LoginSettings, "refreshLeadSeconds" | "serveMarginSeconds">,
): {
  readonly state: "ok" | "expiring" | "expired" | "failed";
  readonly failed: LoginFailure | null;
  readonly accessExpiresAtS: number;
  readonly refreshedAtS: number | null;
  readonly nextRefreshAtS: number | null;
  readonly failures: number;
} {
  const due = refreshDueAtSeconds({ ...record, nextAttemptAt: null }, settings.refreshLeadSeconds);
  const state =
    record.failed !== null
      ? "failed"
      : record.handedToVmAt !== undefined
        ? "ok" // egress refreshes it in the VM; this host's copy expiring says nothing about the account
      : !loginUsable(record, nowSecs, settings.serveMarginSeconds)
        ? "expired"
        : due !== null && nowSecs >= due && record.failures > 0
          ? "expiring"
          : "ok";
  return {
    state,
    failed: record.failed,
    accessExpiresAtS: record.accessExpiresAt,
    refreshedAtS: record.refreshedAt,
    nextRefreshAtS: refreshDueAtSeconds(record, settings.refreshLeadSeconds),
    failures: record.failures,
  };
}

/** The opaque mark the file source folds into an account's `changeMark`: new on every token change. */
export function loginMark(record: LoginRecord): string {
  return `${record.family}:${record.generation}:${record.failed ?? "ok"}`;
}
