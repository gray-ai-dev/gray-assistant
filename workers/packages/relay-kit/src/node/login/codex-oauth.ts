/**
 * The ChatGPT/Codex OAuth exchanges of the relay's own login (`gray-assistant login codex`, and the
 * agent's refresher): the device-code sign-in and the refresh-token grant. Nothing here reads or
 * writes a file; `./store.ts` owns the login record and `./refresher.ts` the schedule.
 *
 * The endpoints, the client id and the request shapes are the open-source Codex CLI's, read at
 * openai/codex tag `rust-v0.164.0` (2026-10-23) and cross-checked against CLIProxyAPI tag `v8.0.40`:
 *
 * - client id `app_EMoamEEZ73f0CkXaXp7hrann`: codex-rs/login/src/auth/manager.rs `CLIENT_ID`;
 *   CLIProxyAPI internal/auth/codex/openai_auth.go `ClientID`.
 * - issuer `https://auth.openai.com`: codex-rs/login/src/server.rs `DEFAULT_ISSUER`.
 * - device code: `POST {issuer}/api/accounts/deviceauth/usercode` with JSON `{client_id}` answers
 *   `{device_auth_id, user_code|usercode, interval}`; the operator opens `{issuer}/codex/device`;
 *   `POST {issuer}/api/accounts/deviceauth/token` with JSON `{device_auth_id, user_code}` answers
 *   403 or 404 while the code is not approved yet, and on approval `{authorization_code,
 *   code_challenge, code_verifier}`; the wait ends after 15 minutes
 *   (codex-rs/login/src/device_code_auth.rs; CLIProxyAPI sdk/auth/codex_device.go, whose poll
 *   interval is 5 s when the answer has none). Unlike the Codex CLI, a poll that gets no answer, a
 *   5xx or a 429 is repeated with a bounded backoff, and RFC 8628 §3.5's `authorization_pending`,
 *   `slow_down` (5 s more), `access_denied` and `expired_token` are read too (`pollCodexDeviceCode`).
 * - code exchange: form-encoded `POST {issuer}/oauth/token` with `grant_type=authorization_code`,
 *   `client_id`, `code`, `redirect_uri={issuer}/deviceauth/callback`, `code_verifier`
 *   (codex-rs/login/src/oauth/client.rs `exchange_code`, device_code_auth.rs).
 * - refresh: JSON `POST {issuer}/oauth/token` with `grant_type=refresh_token`, `client_id`,
 *   `refresh_token`; the answer's `access_token`, `refresh_token` and `id_token` are each optional,
 *   and a returned `refresh_token` replaces the stored one (rotation; manager.rs
 *   `request_chatgpt_token_refresh`, `persist_tokens`). CLIProxyAPI sends the same grant
 *   form-encoded with `scope=openid profile email`; this module follows the Codex CLI.
 * - a refresh failure is permanent when the status is 401, when the code is
 *   `refresh_token_expired`, `refresh_token_reused` or `refresh_token_invalidated`, or when a 400
 *   carries `invalid_grant`; every other failure is transient (manager.rs
 *   `classify_refresh_token_failure`). The code is the body's `error` string, `error.code` or
 *   top-level `code` (codex-rs/login/src/oauth/error.rs `TokenErrorDetail::parse`).
 * - beyond the Codex CLI: a 403 with the code `unsupported_country_region_territory` is OpenAI refusing the
 *   caller's country, region or territory (auth.openai.com from a Hong Kong host, 2026-10-31). It is
 *   `unsupported_region` at every step, a definitive refusal of this host: the same host asking again gets the same
 *   answer, and a device-code poll does not read it as "not approved yet".
 *
 * No error message, log field or return value carries a token, a device code, an authorization
 * code or a response body: an identity provider's body may echo a credential (Codex says the same
 * in `request_chatgpt_token_refresh`). Failures are one closed code.
 */
import { get, isObject, parsePlain } from "@gray/json";
import { RelayKitError } from "../../errors.ts";
import { fetchText } from "../source/http-client.ts";

/** openai/codex rust-v0.164.0 codex-rs/login/src/server.rs `DEFAULT_ISSUER`. */
export const CODEX_ISSUER = "https://auth.openai.com";
/** openai/codex rust-v0.164.0 codex-rs/login/src/auth/manager.rs `CLIENT_ID`. */
export const CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
/** device_code_auth.rs: "device auth timed out after 15 minutes". */
export const CODEX_DEVICE_CODE_TIMEOUT_MS = 15 * 60_000;
/** CLIProxyAPI v8.0.40 sdk/auth/codex_device.go `codexDeviceDefaultPollIntervalSeconds`. */
export const CODEX_DEVICE_DEFAULT_INTERVAL_SECONDS = 5;
/** CLIProxyAPI v8.0.40 internal/auth/codex/openai_auth.go `codexRefreshTimeout` (30 s). */
export const CODEX_REQUEST_TIMEOUT_MS = 30_000;
/** A token answer is a few kilobytes (three JWTs); anything near this is not one. */
export const CODEX_MAX_RESPONSE_BYTES = 256 * 1024;

/**
 * Where the exchanges go. Tests point `issuer` at a local fake; production keeps the defaults, with the `fetch` of
 * `./proxy.ts` (through `source.logins.proxy` when the config names one).
 */
export interface CodexOAuthEndpoint {
  readonly issuer: string;
  readonly clientId: string;
  readonly fetch: typeof fetch;
  readonly timeoutMs: number;
}

/** The closed failure codes of one exchange. */
export type CodexOAuthFailure =
  | "network"
  | "bad_response"
  | "server_error"
  | "rate_limited"
  | "rejected"
  | "access_denied"
  | "device_code_unavailable"
  | "device_code_expired"
  | "unauthorized"
  | "invalid_grant"
  | "refresh_token_expired"
  | "refresh_token_reused"
  | "refresh_token_invalidated"
  | "unsupported_region";

/** A refresh failure the next attempt cannot fix: the login needs a new sign-in. */
export const PERMANENT_REFRESH_FAILURES: ReadonlySet<CodexOAuthFailure> = new Set([
  "unauthorized",
  "invalid_grant",
  "refresh_token_expired",
  "refresh_token_reused",
  "refresh_token_invalidated",
  "unsupported_region",
]);

/** The code of OpenAI's 403 for a caller in a country, region or territory it does not serve. */
export const UNSUPPORTED_REGION_CODE = "unsupported_country_region_territory";

/** What the operator is told about `unsupported_region`: the sign-in and the agent's refreshes need another egress. */
export const UNSUPPORTED_REGION_TEXT =
  `OpenAI refuses this server's region (${UNSUPPORTED_REGION_CODE}). The sign-in and the agent's refreshes must ` +
  "reach auth.openai.com from a supported region: run gray-assistant on a host there, or set source.logins.proxy to an " +
  "http:// or https:// proxy there (user:password@ optional) with `gray-assistant config set source.logins.proxy " +
  "http://proxy.example:3128` and restart the agent (GUIDE section 7, \"Region\").";

/** One failed exchange: the closed code, and whether a retry can succeed. */
export class CodexOAuthError extends Error {
  override readonly name = "CodexOAuthError";
  readonly code: CodexOAuthFailure;
  readonly permanent: boolean;

  constructor(code: CodexOAuthFailure, permanent = false) {
    super(`codex-oauth/${code}`);
    this.code = code;
    this.permanent = permanent;
  }
}

/** The issuer's answer to a code exchange or a refresh; the id token is not kept. */
export interface CodexTokens {
  readonly accessToken: string;
  /** Present on a sign-in; on a refresh only when the issuer rotated it. */
  readonly refreshToken: string | null;
  /** `expires_in`, when the answer has it. */
  readonly expiresInSeconds: number | null;
}

/** What the operator is shown: where to go and which one-time code to enter. */
export interface CodexDeviceCode {
  readonly verificationUrl: string;
  readonly userCode: string;
  readonly intervalSeconds: number;
  /** Opaque to the operator; sent back with every poll. */
  readonly deviceAuthId: string;
}

/** The approved device code's PKCE pair and authorization code. */
export interface CodexDeviceGrant {
  readonly authorizationCode: string;
  readonly codeVerifier: string;
}

function issuerBase(endpoint: CodexOAuthEndpoint): string {
  return endpoint.issuer.replace(/\/+$/u, "");
}

async function post(
  endpoint: CodexOAuthEndpoint,
  path: string,
  body: string,
  contentType: string,
  signal: AbortSignal | undefined,
): Promise<{ readonly status: number; readonly text: string }> {
  try {
    return await fetchText(`${issuerBase(endpoint)}${path}`, {
      fetch: endpoint.fetch,
      signal,
      timeoutMs: endpoint.timeoutMs,
      maxBytes: CODEX_MAX_RESPONSE_BYTES,
      headers: { "content-type": contentType },
      label: "login",
      method: "POST",
      body,
    });
  } catch (error) {
    if (error instanceof RelayKitError && error.code === "source_bad_response") throw new CodexOAuthError("bad_response");
    throw new CodexOAuthError("network");
  }
}

function jsonObject(text: string): Record<string, unknown> | null {
  try {
    const value = parsePlain(text);
    return isObject(value as never) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function nonEmptyText(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

/** The issuer's error code, read the way codex-rs/login/src/oauth/error.rs reads it. */
export function oauthErrorCode(text: string): string | null {
  const body = jsonObject(text.trim());
  if (body === null) return null;
  const error = Object.hasOwn(body, "error") ? body["error"] : undefined;
  const nested = get(error as never, "code");
  return nonEmptyText(error) ?? nonEmptyText(nested) ?? nonEmptyText(body["code"]);
}

/** Classify a non-2xx refresh answer (manager.rs `classify_refresh_token_failure`). */
export function refreshFailure(status: number, text: string): CodexOAuthError {
  const code = oauthErrorCode(text)?.toLowerCase() ?? null;
  if (status === 403 && code === UNSUPPORTED_REGION_CODE) return new CodexOAuthError("unsupported_region", true);
  if (code === "refresh_token_expired" || code === "refresh_token_reused" || code === "refresh_token_invalidated") {
    return new CodexOAuthError(code, true);
  }
  if (status === 400 && code === "invalid_grant") return new CodexOAuthError("invalid_grant", true);
  if (status === 401) return new CodexOAuthError("unauthorized", true);
  if (status === 429) return new CodexOAuthError("rate_limited");
  if (status >= 500) return new CodexOAuthError("server_error");
  return new CodexOAuthError("rejected");
}

function tokensFrom(text: string, requireRefreshToken: boolean): CodexTokens {
  const body = jsonObject(text);
  if (body === null) throw new CodexOAuthError("bad_response");
  const accessToken = nonEmptyText(body["access_token"]);
  const refreshToken = nonEmptyText(body["refresh_token"]);
  const expiresIn = body["expires_in"];
  if (accessToken === null) throw new CodexOAuthError("bad_response");
  if (requireRefreshToken && refreshToken === null) throw new CodexOAuthError("bad_response");
  return {
    accessToken,
    refreshToken,
    expiresInSeconds: typeof expiresIn === "number" && Number.isSafeInteger(expiresIn) && expiresIn > 0 ? expiresIn : null,
  };
}

/** The poll interval the issuer asks for: a decimal string (Codex) or an integer (CLIProxyAPI). */
function intervalSeconds(value: unknown): number {
  const parsed = typeof value === "number" ? value : typeof value === "string" && /^\s*\d{1,4}\s*$/u.test(value) ? Number(value.trim()) : NaN;
  return Number.isSafeInteger(parsed) && parsed > 0 && parsed <= 60 ? parsed : CODEX_DEVICE_DEFAULT_INTERVAL_SECONDS;
}

/** Step 1 of the device sign-in: ask for a user code. */
export async function requestCodexDeviceCode(endpoint: CodexOAuthEndpoint, signal?: AbortSignal): Promise<CodexDeviceCode> {
  const response = await post(
    endpoint,
    "/api/accounts/deviceauth/usercode",
    JSON.stringify({ client_id: endpoint.clientId }),
    "application/json",
    signal,
  );
  if (response.status === 404) throw new CodexOAuthError("device_code_unavailable");
  if (response.status < 200 || response.status > 299) throw refreshFailure(response.status, response.text);
  const body = jsonObject(response.text);
  const deviceAuthId = nonEmptyText(body?.["device_auth_id"]);
  const userCode = nonEmptyText(body?.["user_code"]) ?? nonEmptyText(body?.["usercode"]);
  if (body === null || deviceAuthId === null || userCode === null) throw new CodexOAuthError("bad_response");
  return {
    verificationUrl: `${issuerBase(endpoint)}/codex/device`,
    userCode,
    intervalSeconds: intervalSeconds(body["interval"]),
    deviceAuthId,
  };
}

/** RFC 8628 §3.5: `slow_down` adds 5 seconds to the interval of this and every later poll. */
export const DEVICE_SLOW_DOWN_SECONDS = 5;
/** The longest wait after consecutive transient failures (RFC 8628 §3.5's backoff), the longest interval the issuer may ask for. */
export const DEVICE_MAX_BACKOFF_MS = 60_000;
/** A poll that failed for one of these reasons is repeated until the code expires; anything else ends the sign-in. */
const TRANSIENT_POLL_FAILURES: ReadonlySet<CodexOAuthFailure> = new Set(["network", "server_error", "rate_limited"]);

export interface DevicePollOptions {
  readonly nowMs: () => number;
  readonly sleep: (ms: number) => Promise<void>;
  readonly signal?: AbortSignal;
  /** Default `CODEX_DEVICE_CODE_TIMEOUT_MS`. */
  readonly timeoutMs?: number;
  /** Called once per poll that failed transiently (the closed code), with the wait before the next one. */
  readonly onTransient?: (failure: { readonly code: CodexOAuthFailure; readonly waitMs: number }) => void;
}

/**
 * What a non-2xx poll answer means (RFC 8628 §3.5): `access_denied` and `expired_token` end the sign-in,
 * `slow_down` and `authorization_pending` (the Codex issuer's 403 and 404) keep it waiting, and any other answer
 * is classified as a refresh failure is: transient for a 5xx or 429, else the end of the sign-in. A 403 that
 * refuses the host's region ends it too: it is not the issuer's "not approved yet".
 */
function pollAnswer(status: number, text: string): "pending" | "slow_down" | CodexOAuthError {
  const code = oauthErrorCode(text)?.toLowerCase() ?? null;
  if (status === 403 && code === UNSUPPORTED_REGION_CODE) return new CodexOAuthError("unsupported_region", true);
  if (code === "access_denied") return new CodexOAuthError("access_denied", true);
  if (code === "expired_token") return new CodexOAuthError("device_code_expired", true);
  if (code === "slow_down") return "slow_down";
  if (code === "authorization_pending" || status === 403 || status === 404) return "pending";
  return refreshFailure(status, text);
}

/**
 * Step 2: poll until the operator approves the code in a browser, the issuer denies it, or the code expires. A poll
 * that failed transiently (no answer, a timeout, a 5xx or 429) is repeated: the first after the interval, each
 * further one in a row after twice the last wait, at most `DEVICE_MAX_BACKOFF_MS`; an answer resets the wait. One
 * dropped connection during the operator's minutes in the browser must not cost them the code.
 */
export async function pollCodexDeviceCode(endpoint: CodexOAuthEndpoint, code: CodexDeviceCode, options: DevicePollOptions): Promise<CodexDeviceGrant> {
  const deadline = options.nowMs() + (options.timeoutMs ?? CODEX_DEVICE_CODE_TIMEOUT_MS);
  const body = JSON.stringify({ device_auth_id: code.deviceAuthId, user_code: code.userCode });
  // Read afresh each time: the signal may abort while a poll is in flight.
  const aborted = (): boolean => options.signal?.aborted === true;
  let intervalMs = code.intervalSeconds * 1000;
  let backoffMs = 0;
  for (;;) {
    if (aborted()) throw new CodexOAuthError("network");
    let failure: CodexOAuthError | null = null;
    let response: { readonly status: number; readonly text: string } | null = null;
    try {
      response = await post(endpoint, "/api/accounts/deviceauth/token", body, "application/json", options.signal);
    } catch (error) {
      if (!(error instanceof CodexOAuthError) || !TRANSIENT_POLL_FAILURES.has(error.code) || aborted()) throw error;
      failure = error;
    }
    if (response !== null && response.status >= 200 && response.status <= 299) {
      const answer = jsonObject(response.text);
      const authorizationCode = nonEmptyText(answer?.["authorization_code"]);
      const codeVerifier = nonEmptyText(answer?.["code_verifier"]);
      if (authorizationCode === null || codeVerifier === null) throw new CodexOAuthError("bad_response");
      return { authorizationCode, codeVerifier };
    }
    if (response !== null) {
      const answer = pollAnswer(response.status, response.text);
      if (answer instanceof CodexOAuthError) {
        if (!TRANSIENT_POLL_FAILURES.has(answer.code)) throw answer;
        failure = answer;
      } else if (answer === "slow_down") {
        intervalMs += DEVICE_SLOW_DOWN_SECONDS * 1000;
      }
    }
    backoffMs = failure === null ? 0 : backoffMs === 0 ? intervalMs : Math.min(backoffMs * 2, Math.max(DEVICE_MAX_BACKOFF_MS, intervalMs));
    const remaining = deadline - options.nowMs();
    if (remaining <= 0) throw new CodexOAuthError("device_code_expired");
    const waitMs = Math.min(failure === null ? intervalMs : backoffMs, remaining);
    if (failure !== null) options.onTransient?.({ code: failure.code, waitMs });
    await options.sleep(waitMs);
  }
}

/** Step 3: exchange the approved code for the token family. A sign-in without a refresh token is refused. */
export async function exchangeCodexDeviceCode(endpoint: CodexOAuthEndpoint, grant: CodexDeviceGrant, signal?: AbortSignal): Promise<CodexTokens> {
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: endpoint.clientId,
    code: grant.authorizationCode,
    redirect_uri: `${issuerBase(endpoint)}/deviceauth/callback`,
    code_verifier: grant.codeVerifier,
  });
  const response = await post(endpoint, "/oauth/token", form.toString(), "application/x-www-form-urlencoded", signal);
  if (response.status < 200 || response.status > 299) throw refreshFailure(response.status, response.text);
  return tokensFrom(response.text, true);
}

/** The refresh-token grant. The caller persists a returned refresh token before anything else. */
export async function refreshCodexTokens(endpoint: CodexOAuthEndpoint, refreshToken: string, signal?: AbortSignal): Promise<CodexTokens> {
  const body = JSON.stringify({ client_id: endpoint.clientId, grant_type: "refresh_token", refresh_token: refreshToken });
  const response = await post(endpoint, "/oauth/token", body, "application/json", signal);
  if (response.status < 200 || response.status > 299) throw refreshFailure(response.status, response.text);
  return tokensFrom(response.text, false);
}
