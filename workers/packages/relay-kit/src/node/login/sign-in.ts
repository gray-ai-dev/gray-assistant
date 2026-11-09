/**
 * `gray-assistant login codex`: the relay's one-time ChatGPT/Codex sign-in on the relay host, with the
 * device-code flow (`./codex-oauth.ts`). The operator runs it inside the agent's container, opens
 * the printed URL on any machine with a browser, signs in to the ChatGPT account this relay serves
 * and enters the printed one-time code. The token family is written only to the agent's state
 * volume (`<state dir>/logins/<name>.json`, 0600); stdout gets the URL, the one-time code and the
 * access token's expiry, never a token.
 *
 * This is a sign-in of its own, with its own refresh token. The agent never reads a Codex CLI's
 * `~/.codex/auth.json`: refresh tokens rotate on use (openai/codex rust-v0.164.0
 * codex-rs/login/src/auth/manager.rs `persist_tokens`), so a relay refreshing a copy of someone's
 * desktop login would spend the refresh token that desktop holds and sign it out.
 */
import { bytesToHex } from "@gray/relay-connector";
import { RelayKitError } from "../../errors.ts";
import {
  CODEX_DEVICE_CODE_TIMEOUT_MS,
  CodexOAuthError,
  exchangeCodexDeviceCode,
  pollCodexDeviceCode,
  requestCodexDeviceCode,
  UNSUPPORTED_REGION_TEXT,
  type CodexOAuthEndpoint,
} from "./codex-oauth.ts";
import type { LoginRecord } from "./record.ts";
import { accessExpiry } from "./refresher.ts";
import { assertLoginName, readLoginRecord, withLoginLock, writeLoginRecord } from "./store.ts";

export interface SignInOptions {
  readonly dir: string;
  readonly name: string;
  /** Replace an existing record (a failed login, or a move to another account). */
  readonly force: boolean;
  readonly endpoint: CodexOAuthEndpoint;
  readonly nowMs: () => number;
  readonly sleep: (ms: number) => Promise<void>;
  readonly random: (length: number) => Uint8Array;
  readonly print: (line: string) => void;
  /**
   * Where the device code goes instead of `print`: the local page (`../ui/logins.ts`) shows the link and the code in
   * the operator's browser and nothing reaches stdout. Called once, before the wait for the approval.
   */
  readonly onDeviceCode?: (code: { readonly verificationUrl: string; readonly userCode: string; readonly expiresAtMs: number }) => void;
  /** Called after the approval, while the code is exchanged for tokens. */
  readonly onApproved?: () => void;
  readonly signal?: AbortSignal;
}

/**
 * An absolute time as the operator reads it: UTC in ISO 8601 (seconds), and the process's local time beside it when
 * its time zone is not UTC (the agent's container is UTC unless compose gives it `TZ`).
 */
export function expiryText(ms: number, timeZone: string = Intl.DateTimeFormat().resolvedOptions().timeZone): string {
  const utc = new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");
  if (timeZone === "UTC" || timeZone === "Etc/UTC" || timeZone === "Etc/GMT" || timeZone === "GMT") return utc;
  const local = new Intl.DateTimeFormat("sv-SE", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).format(new Date(ms));
  return `${utc} (${local} ${timeZone})`;
}

/** One OAuth step; its failure is `login_failed` with `<step>: <code>`, which the local page reads the code back from. */
function oauthStep<T>(step: string, print: (line: string) => void, run: () => Promise<T>): Promise<T> {
  return run().catch((error: unknown) => {
    if (error instanceof CodexOAuthError) {
      // Another try from this host gets the same answer: say what has to change.
      if (error.code === "unsupported_region") print(`${UNSUPPORTED_REGION_TEXT}\n`);
      throw new RelayKitError("login_failed", `${step}: ${error.code}`);
    }
    throw error;
  });
}

/** Sign in once and write the login record; returns it (the caller prints only its metadata). */
export async function signInCodex(options: SignInOptions): Promise<LoginRecord> {
  const name = assertLoginName(options.name);
  const existing = readLoginRecord(options.dir, name);
  if (existing !== null && !options.force) {
    throw new RelayKitError("usage", `login ${name} already exists; pass --force to replace it with a new sign-in`);
  }
  const code = await oauthStep("device code", options.print, () => requestCodexDeviceCode(options.endpoint, options.signal));
  // The issuer's 15 minutes from now, as an absolute time the operator can hand to the person who approves.
  const expiresAtMs = options.nowMs() + CODEX_DEVICE_CODE_TIMEOUT_MS;
  if (options.onDeviceCode !== undefined) {
    options.onDeviceCode({ verificationUrl: code.verificationUrl, userCode: code.userCode, expiresAtMs });
  } else {
    const expiry = expiryText(expiresAtMs);
    options.print(
      [
        "",
        `Sign in the relay login ${name} (ChatGPT/Codex, device code):`,
        "",
        `1. On any machine with a browser, open ${code.verificationUrl}`,
        "   and sign in to the ChatGPT account this relay serves.",
        `2. Enter this one-time code: ${code.userCode}`,
        `   It expires in 15 minutes, at ${expiry}.`,
        "",
        "Continue only if you started this sign-in on the relay host yourself. If a website or another",
        "person gave you this code, stop here.",
        "",
        "Waiting for the approval...",
        "",
      ].join("\n"),
    );
    // The same, for an agent that hands the code to a person: one JSON line before the wait (the last line, after
    // the sign-in, is the result's).
    options.print(
      `${JSON.stringify({
        command: "login",
        state: "waiting_for_approval",
        login: name,
        verification_url: code.verificationUrl,
        user_code: code.userCode,
        code_expires_at: new Date(expiresAtMs).toISOString(),
        code_expires_at_unix: Math.floor(expiresAtMs / 1000),
      })}\n`,
    );
  }
  const grant = await oauthStep("approval", options.print, () =>
    pollCodexDeviceCode(options.endpoint, code, {
      nowMs: options.nowMs,
      sleep: options.sleep,
      // One line per poll that got no usable answer, so the operator sees the wait goes on.
      onTransient: ({ code: failure, waitMs }) => options.print(`Still waiting: the issuer did not answer (${failure}); asking again in ${Math.ceil(waitMs / 1000)} s.\n`),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    }),
  );
  options.onApproved?.();
  const tokens = await oauthStep("code exchange", options.print, () => exchangeCodexDeviceCode(options.endpoint, grant, options.signal));
  const nowSecs = Math.floor(options.nowMs() / 1000);
  const expiry = accessExpiry(tokens, nowSecs);
  if (expiry === null || expiry.expiresAt <= nowSecs) throw new RelayKitError("login_failed", "the issuer's access token has no usable chatgpt_account_id or expiry");
  if (tokens.refreshToken === null) throw new RelayKitError("login_failed", "the issuer returned no refresh token");
  const record: LoginRecord = {
    login: name,
    vendor: "chatgpt_codex",
    issuer: options.endpoint.issuer.replace(/\/+$/u, ""),
    clientId: options.endpoint.clientId,
    family: bytesToHex(options.random(16)),
    generation: 1,
    accountId: expiry.accountId,
    accessToken: tokens.accessToken,
    accessExpiresAt: expiry.expiresAt,
    refreshToken: tokens.refreshToken,
    signedInAt: nowSecs,
    refreshedAt: null,
    failures: 0,
    nextAttemptAt: null,
    failed: null,
    failedAt: null,
  };
  await withLoginLock(options.dir, name, () => {
    // A record that appeared while the operator was in the browser is replaced only with --force.
    const stored = readLoginRecord(options.dir, name);
    if (stored !== null && !options.force) throw new RelayKitError("usage", `login ${name} was created meanwhile; pass --force to replace it`);
    writeLoginRecord(options.dir, record);
  });
  return record;
}
