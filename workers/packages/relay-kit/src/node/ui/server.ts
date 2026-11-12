/**
 * `gray-assistant ui`: the relay's local page, where an operator adds accounts, accepts releases and runs
 * the checks on the relay's own machine, so a key never enters a page Gray serves. The page lives under `/ui/` and is
 * served in one of two modes:
 *
 * - **loopback** (`gray-assistant ui`, or `ui.listen` beside `gray-assistant run`): its own listener on 127.0.0.1 only. From
 *   another machine it is reached through the operator's own SSH tunnel (`ssh -L 7470:127.0.0.1:7470 <host>`) or a
 *   private network (Tailscale, Cloudflare Access). Sign-in is a one-time link (`./session.ts`) that `gray-assistant ui` or
 *   `gray-assistant ui link` prints to the operator's terminal.
 * - **public** (`ui.public: true`, served by `gray-assistant run`): the relay's own HTTPS origin, which is `ui.origin` when
 *   the config names one, else the relay tunnel's `https://<relay-id>.<relays zone>` while that tunnel is up (the
 *   `publicOrigin` seam; branch life/relay-tunnel mounts `handle` on it), else `stack.token_url`'s origin (the agent's
 *   listener behind the relay's TLS proxy or tunnel). Sign-in is a passkey (WebAuthn, `@simplewebauthn/server`) enrolled
 *   with `gray-assistant ui enroll`'s one-time link; there is no password and no link sign-in. The address bar shows the
 *   relay's domain, which is how the operator knows Gray's code is not on the page. A passkey belongs to the host it was
 *   made on: when the origin moves (the tunnel comes up), the operator enrols again there.
 *
 * Who may use it, in both modes:
 * - every request's Host must be the page's own (a loopback name in loopback mode, at any port, so a site that rebinds
 *   its DNS name to 127.0.0.1 is refused; the public origin's host in public mode): 421 otherwise, before anything else;
 * - every `/ui/api/` call needs the session cookie (HttpOnly, SameSite=Strict; `__Host-` and Secure in public mode); a
 *   session lives in this process's memory only and ends after its idle time, at its maximum age, on sign-out, when its
 *   passkey is revoked, or when the process stops;
 * - every write also needs the session's CSRF token in `x-gray-csrf`, an `Origin` equal to the page's own, no
 *   cross-site `Sec-Fetch-Site`, and a JSON body; there is no CORS (no `Access-Control-*` header, OPTIONS refused);
 * - passkey sign-in and enrolment are rate limited per client and in total;
 * - every answer carries a strict Content-Security-Policy (scripts from this origin only, `frame-ancestors 'none'`: the
 *   page is never framed, by Gray's page or any other), `nosniff`, `no-referrer`, and `no-store` for the API;
 * - the static files (the same bytes in every gray-assistant, no data) are served without a session, so the page itself can
 *   say it is signed out; everything it shows or changes goes through `/ui/api/`;
 * - a stored key is never sent back: the page sends a key once, in the write that stores it;
 * - every write and every sign-in is recorded in `ui-audit.jsonl` beside `state.json` (`./audit.ts`), without values.
 *
 * Nothing is logged with a secret: no request line, header, cookie, body, sign-in code, device code or key.
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parsePlain, toJsonString, type SerdeValue } from "@gray/json";
import { randomBytes, VENDORS, type Vendor } from "@gray/relay-connector";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { z } from "zod";
import { RelayKitError } from "../../errors.ts";
import { defaultConfigPath, loadRelayConfigFile, type LoadedRelayConfig } from "../config-file.ts";
import { panelIdLookup } from "../../daemon/account-aliases.ts";
import { accountAliasesPath, readAccountAliasesFile } from "../daemon/account-aliases-file.ts";
import { controlFileBeside } from "../daemon/control-file.ts";
import { readControlView } from "../control.ts";
import type { DoctorOptions, DoctorReport } from "../doctor.ts";
import { acceptReleaseId, vetoRelease } from "../release-control.ts";
import { addAccount, readAccountsView, removeAccount, replaceCredential, type UiAccount } from "./accounts-file.ts";
import { readAgentView, sealedState, type UiAgentView } from "./agent.ts";
import { appendUiAudit, uiAuditPath, type UiAuditEntry } from "./audit.ts";
import { UiHealth } from "./health.ts";
import { removeUiMarker, UI_MARKER_EVERY_MS, uiMarkerPath, writeUiMarker } from "./marker.ts";
import { PASSKEY_LABEL, PasskeyCache, passkeysPath, updatePasskeys, type StoredPasskey } from "./passkeys.ts";
import { UiRefusal } from "./refusal.ts";
import {
  csrfMatches,
  mintUiLink,
  peekUiLink,
  RateLimiter,
  redeemUiLink,
  UI_PUBLIC_SESSION_IDLE_MS,
  UI_PUBLIC_SESSION_MAX_MS,
  uiEnrollDirectory,
  uiLinksDirectory,
  UiSessions,
  type UiSession,
} from "./session.ts";

/** The page's port on 127.0.0.1 when neither `--port` nor `ui.listen.port` names one. */
export const DEFAULT_UI_PORT = 7470;
/** Where the page lives on either origin. */
export const UI_BASE = "/ui";
/** The largest JSON body the API reads; a key is at most 8 KiB, a passkey's attestation a few. */
export const MAX_UI_BODY_BYTES = 64 * 1024;
/** Where the built page lives in the package (`frontend/relay-ui` builds it there). */
export const DEFAULT_UI_BUNDLE_DIR = fileURLToPath(new URL("../../../assets/ui/", import.meta.url).toString());
/** How long a passkey ceremony may take between its options and its answer. */
export const UI_CEREMONY_MS = 5 * 60_000;

export type UiMode = "loopback" | "public";

export interface RelayUiIo {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
  readonly now: () => number;
}

interface UiCommonOptions {
  /** A private trust anchor for `doctor`'s lane, scheduler and release-list checks. */
  readonly ca?: string;
  /** Test-only quote verifier module for `doctor` (the same seam `doctor` has). */
  readonly verifierModule?: string;
  readonly io: RelayUiIo;
  readonly random?: (length: number) => Uint8Array;
  /** The built page; defaults to the package's `assets/ui`. */
  readonly bundleDir?: string;
  /** The doctor run, injectable for tests; defaults to `../doctor.ts`'s `runDoctor`. */
  readonly runDoctor?: (options: DoctorOptions) => Promise<DoctorReport>;
}

export interface UiHandlerOptions extends UiCommonOptions {
  readonly mode: UiMode;
  readonly config: LoadedRelayConfig;
  /**
   * Public mode: the origin the page answers on now (asked on every request, so it follows the tunnel coming up or
   * going), or null for none yet; `stack.token_url`'s origin when absent. `gray-assistant run` passes `ui.origin`, else the
   * tunnel's origin while it is up, else the token URL's. Tests give `http://localhost:<port>`, the one plain-HTTP origin
   * a browser runs WebAuthn on (the config refuses it).
   */
  readonly publicOrigin?: () => string | null;
}

export interface UiHandler {
  readonly mode: UiMode;
  /** The origin the page answers on now (public mode); null on 127.0.0.1, or while public mode has none. */
  origin(): string | null;
  /** Answer a request that is the page's (`/ui`, `/ui/…`; on 127.0.0.1 also `/`); false for any other path. */
  handle(request: IncomingMessage, response: ServerResponse): Promise<boolean>;
  /** Loopback: a one-time sign-in link for `base` (`http://127.0.0.1:<port>`). */
  mintLink(base: string): { readonly url: string; readonly code: string; readonly expiresAtMs: number };
  stop(): void;
}

export interface RelayUiOptions extends UiCommonOptions {
  readonly configPath: string;
  /** The port on 127.0.0.1; 0 picks a free one (tests). Defaults to `ui.listen.port`, then `DEFAULT_UI_PORT`. */
  readonly port?: number;
  /**
   * The address the listener binds, 127.0.0.1 by default. In the kit's container, `0.0.0.0` (`ui --host 0.0.0.0`) lets
   * the port compose.yaml publishes on the host's 127.0.0.1 only reach it; the page still answers only to a loopback
   * Host and a sign-in link, and its URL stays `http://127.0.0.1:<port>`.
   */
  readonly host?: string;
}

export interface RunningRelayUi {
  /** `http://127.0.0.1:<port>`. */
  readonly url: string;
  readonly port: number;
  readonly config: LoadedRelayConfig;
  /** Mint a one-time sign-in link for this page (what `gray-assistant ui link` does from another process). */
  mintLink(): { readonly url: string; readonly code: string; readonly expiresAtMs: number };
  stop(): Promise<void>;
}

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  // Base UI positions popups with inline styles, and Sonner adds its stylesheet at run time.
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const CONTENT_TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".ttf": "font/ttf",
  ".json": "application/json",
  ".txt": "text/plain; charset=utf-8",
};

interface StaticFile {
  readonly body: Buffer;
  readonly type: string;
  readonly etag: string;
}

/** Load every file of the built page into memory once: only these paths are ever served, so no path can escape. */
function loadBundle(dir: string): Map<string, StaticFile> {
  const files = new Map<string, StaticFile>();
  const root = resolve(dir);
  const walk = (current: string): void => {
    let names: string[];
    try {
      names = readdirSync(current);
    } catch {
      return;
    }
    for (const name of names) {
      const path = join(current, name);
      const stats = statSync(path);
      if (stats.isDirectory()) walk(path);
      else if (stats.isFile()) {
        const type = CONTENT_TYPES[extname(name).toLowerCase()];
        if (type === undefined) continue;
        const body = readFileSync(path);
        files.set(`/${relative(root, path).split(sep).join("/")}`, { body, type, etag: `"${createHash("sha256").update(body).digest("hex").slice(0, 32)}"` });
      }
    }
  };
  walk(root);
  return files;
}

/** A Host header that names this machine's loopback, at any port (an SSH tunnel may forward another port). */
export function isLoopbackHostHeader(host: string | undefined): boolean {
  const url = hostUrl(host);
  return url !== null && (url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "[::1]");
}

/** A Host header parsed as the platform parses it, or null when the header is more than a host and a port. */
function hostUrl(host: string | undefined): URL | null {
  if (host === undefined || host.length === 0 || host.length > 300) return null;
  let url: URL;
  try {
    url = new URL(`http://${host}`);
  } catch {
    return null;
  }
  // The whole header must have been the host and port: nothing the parser read as userinfo, path or query.
  if (url.host !== host.toLowerCase() || url.username !== "" || url.password !== "" || url.pathname !== "/" || url.search !== "" || url.hash !== "") return null;
  return url;
}

/** The `next` a sign-in link may send the browser to: a path of the page, never another origin. */
function safeNext(value: string | null): string {
  if (value === null || !value.startsWith(`${UI_BASE}/`) || value.startsWith("//") || value.includes("\\") || value.length > 2048 || /[\u0000-\u001f]/u.test(value)) return `${UI_BASE}/`;
  return value;
}

function cookieValue(request: IncomingMessage, name: string): string | null {
  const header = request.headers.cookie;
  if (header === undefined) return null;
  for (const pair of header.split(";")) {
    const index = pair.indexOf("=");
    if (index < 0) continue;
    if (pair.slice(0, index).trim() === name) return pair.slice(index + 1).trim();
  }
  return null;
}

function send(response: ServerResponse, status: number, headers: Record<string, string>, body: string | Buffer = ""): void {
  response.writeHead(status, {
    "content-security-policy": CSP,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    ...headers,
  });
  response.end(body);
}

function sendJson(response: ServerResponse, status: number, value: SerdeValue, headers: Record<string, string> = {}): void {
  send(response, status, { "content-type": "application/json", "cache-control": "no-store", ...headers }, `${toJsonString(value)}\n`);
}

function refusal(response: ServerResponse, error: UiRefusal): void {
  sendJson(response, error.status, { error: { code: error.code, field: error.field, detail: error.detail } });
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const type = request.headers["content-type"] ?? "";
  if (!/^application\/json(\s*;.*)?$/iu.test(type)) throw new UiRefusal(415, "json_only");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = chunk as Buffer;
    size += buffer.length;
    if (size > MAX_UI_BODY_BYTES) throw new UiRefusal(413, "body_too_large");
    chunks.push(buffer);
  }
  try {
    return parsePlain(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new UiRefusal(400, "bad_json");
  }
}

function parseBody<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const field = issue === undefined || issue.path.length === 0 ? null : String(issue.path[0]);
    throw new UiRefusal(422, "invalid", field);
  }
  return parsed.data;
}

const codeBody = z.object({ code: z.string().max(256) }).strict();
const credentialBody = z.object({ type: z.enum(["api_key", "oauth_access_token"]), value: z.string().min(1).max(16_384) }).strict();
const newAccountBody = z
  .object({
    account_id: z.string().max(256),
    vendor: z.enum(VENDORS),
    credential: credentialBody,
    models: z.array(z.string().max(512)).max(256).nullable(),
    proxy: z.string().max(4096).nullable(),
  })
  .strict();
const replaceBody = z.object({ credential: credentialBody }).strict();
const releaseIdBody = z.object({ id: z.string().min(1).max(256) }).strict();
const hashBody = z.object({ hash: z.string().max(128) }).strict();
// The browser's WebAuthn answers, checked whole by @simplewebauthn/server; here only their outline and size.
const webauthnAnswer = z.object({ id: z.string().min(1).max(2048), rawId: z.string().min(1).max(2048), type: z.literal("public-key"), response: z.record(z.string(), z.unknown()) }).passthrough();
const enrollOptionsBody = z.object({ code: z.string().max(256) }).strict();
const enrollVerifyBody = z.object({ code: z.string().max(256), ceremony: z.string().max(64), label: z.string().max(256), response: webauthnAnswer }).strict();
const loginVerifyBody = z.object({ ceremony: z.string().max(64), response: webauthnAnswer }).strict();

interface Ceremony {
  readonly kind: "register" | "login";
  readonly challenge: string;
  readonly expiresAtMs: number;
  readonly code: string | null;
  /** The origin it began on: an answer on another one (the tunnel came up meanwhile) is refused. */
  readonly origin: string;
}

/** The page's request handler, in one mode. */
export async function createRelayUiHandler(options: UiHandlerOptions): Promise<UiHandler> {
  const { config, mode } = options;
  const random = options.random ?? ((length: number) => randomBytes(length));
  const now = options.io.now;
  const bundle = loadBundle(options.bundleDir ?? DEFAULT_UI_BUNDLE_DIR);
  const linksDir = uiLinksDirectory(config.daemon.stateFile);
  const enrollDir = uiEnrollDirectory(config.daemon.stateFile);
  const auditPath = uiAuditPath(config.daemon.stateFile);
  const passkeys = new PasskeyCache(passkeysPath(config.daemon.stateFile), random);
  // Public mode: the relay's own origin, asked per request (it follows the tunnel); `stack.token_url`'s by default.
  const stackOrigin = config.daemon.stack === null ? null : new URL(config.daemon.stack.tokenUrl).origin;
  const originNow = (): string | null => (mode === "public" ? (options.publicOrigin === undefined ? stackOrigin : options.publicOrigin()) : null);
  const sessions = mode === "public" ? new UiSessions(random, { idleMs: UI_PUBLIC_SESSION_IDLE_MS, maxMs: UI_PUBLIC_SESSION_MAX_MS }) : new UiSessions(random);
  const ceremonies = new Map<string, Ceremony>();
  const loginOptionsLimit = new RateLimiter(30, 120, 60_000);
  const loginVerifyLimit = new RateLimiter(10, 30, 60_000);
  const enrollLimit = new RateLimiter(10, 30, 60_000);
  const health = new UiHealth({
    run: options.runDoctor ?? (async (doctorOptions) => (await import("../doctor.ts")).runDoctor(doctorOptions)),
    doctorOptions: () => ({
      configPath: config.path,
      ...(options.ca === undefined ? {} : { ca: options.ca }),
      ...(options.verifierModule === undefined ? {} : { verifierModule: options.verifierModule }),
    }),
    nowMs: now,
  });
  /** When this page last changed each account: until the agent's next seal, that account waits. */
  const editedAt = new Map<string, number>();
  // Two pages for two relays on one machine keep their own cookie; on the public origin the `__Host-` prefix binds it.
  const cookieName = mode === "public" ? "__Host-gray_assistant_ui" : `gray_assistant_ui_${createHash("sha256").update(`${config.daemon.relayId}\n${config.path}`).digest("hex").slice(0, 12)}`;
  const cookieAttributes = mode === "public" ? "HttpOnly; Secure; SameSite=Strict; Path=/" : `HttpOnly; SameSite=Strict; Path=${UI_BASE}`;
  // Commands the page shows name the config only when gray-assistant would not find it on its own.
  const configIsDefault = resolve(defaultConfigPath()) === config.path;

  const audit = (entry: UiAuditEntry): void => appendUiAudit(auditPath, mode, entry, now());
  const who = (session: UiSession | null): string | null => (session === null ? null : session.passkeyId === null ? "link" : `passkey:${session.passkeyId.slice(0, 12)}`);

  function sessionCookie(session: UiSession): string {
    return `${cookieName}=${session.id}; ${cookieAttributes}`;
  }

  function relayView(agent: UiAgentView): SerdeValue {
    return {
      relay_id: config.daemon.relayId,
      config_path: config.path,
      config_default: configIsDefault,
      mode,
      source: { kind: config.source.kind },
      agent: { state: agent.state, as_of_ms: agent.asOfMs, ready: agent.ready, paused: agent.paused },
      // The relay tunnel and its CT monitor (docs/relay-tunnel.md): the page warns on every page while CT shows a
      // certificate for the relay's name that gray-assistant did not obtain. Counts and words only.
      tunnel: agent.tunnel === null ? null : { state: agent.tunnel.state, name: agent.tunnel.name, ct: agent.tunnel.ct === null ? null : { state: agent.tunnel.ct.state, findings: agent.tunnel.ct.findings, checked_ms: agent.tunnel.ct.checkedMs } },
      // The image page arrives with `gray-assistant stack` (S53); until then the page shows no Image tab.
      features: { image: false },
    };
  }

  function accountValue(account: UiAccount, agent: UiAgentView, panelId: (vendor: Vendor, sourceId: string) => string | null): SerdeValue {
    const sealed = sealedState(agent, account.accountId, { editedAtMs: editedAt.get(account.accountId) ?? null, selected: account.selected, active: account.status === "active" || account.status === "limited" });
    return {
      account_id: account.accountId,
      // S59: the id Gray's panel knows it by; the alias when the source's id is none (an e-mail address), null until
      // the agent gives it one.
      panel_id: panelId(account.vendor, account.accountId),
      vendor: account.vendor,
      credential_type: account.credentialType,
      status: account.status,
      models: account.models === "*" ? "*" : [...account.models],
      proxy: account.proxy === null ? null : { type: account.proxy.type, host: account.proxy.host, port: account.proxy.port, username: account.proxy.username ?? null },
      credential_expires_at_ms: account.credentialExpiresAtMs,
      selected: account.selected,
      sealed: { state: sealed.state, version: sealed.version, at_ms: sealed.atMs, reason: sealed.reason },
    };
  }

  function accountsValue(nowMs: number): SerdeValue {
    const agent = readAgentView(config, nowMs);
    const view = readAccountsView(config.source);
    const panelId = panelIdLookup(readAccountAliasesFile(accountAliasesPath(config.daemon.stateFile)) ?? []);
    return {
      relay: relayView(agent),
      source: { kind: view.kind, path: view.path, url: view.url, exists: view.exists, writable: view.writable, problem: view.problem === null ? null : { code: view.problem.code, detail: view.problem.detail } },
      source_poll_ms: config.daemon.sourcePollMs,
      agent_last_poll_at_ms: agent.sourceLastPollAtMs,
      accounts: view.accounts.map((account) => accountValue(account, agent, panelId)),
    };
  }

  async function releasesValue(nowMs: number): Promise<SerdeValue> {
    const agent = readAgentView(config, nowMs);
    const control = await readControlView(config.daemon.stateFile, controlFileBeside(config.daemon.stateFile));
    // The operator's decisions are control.json's: a release accepted or rejected here shows so at once, before the
    // agent's next tick reads the file and its status says the same.
    const acceptedNow = new Set(control.control.acceptedReleases);
    const rejectedNow = new Set(control.control.rejectedReleases ?? []);
    const pairingNow = new Set(control.control.acceptedAtPairing ?? []);
    return {
      relay: relayView(agent),
      accept_mode: config.daemon.releases.accept,
      delay_days: config.daemon.releases.delayDays,
      release_list: agent.releaseList === null ? null : { current_until_ms: agent.releaseList.currentUntilMs, last_error: agent.releaseList.lastError },
      accepted: [...control.control.acceptedReleases],
      rejected: [...(control.control.rejectedReleases ?? [])],
      releases: agent.releases.map((row) => ({
        kind: row.kind,
        hash: row.hash,
        git_commit: row.gitCommit,
        version: row.version,
        first_seen_ms: row.firstSeenMs,
        acceptable_at_ms: row.acceptableAtMs,
        acceptable: row.acceptable && !rejectedNow.has(row.hash),
        accepted: !rejectedNow.has(row.hash) && (row.accepted || acceptedNow.has(row.hash)),
        // Pairing's acceptance, until the operator's own decision in control.json replaces it.
        accepted_at_pairing: row.acceptedAtPairing && !rejectedNow.has(row.hash) && pairingNow.has(row.hash),
        rejected: rejectedNow.has(row.hash),
        refusal: row.refusal,
      })),
      replicas: agent.replicas.map((replica) => ({ origin: replica.origin, phase: replica.phase, last_error: replica.lastError })),
    };
  }

  function healthValue(nowMs: number): SerdeValue {
    const view = health.view();
    return {
      relay: relayView(readAgentView(config, nowMs)),
      running: view.running,
      started_at_ms: view.startedAtMs,
      finished_at_ms: view.finishedAtMs,
      ok: view.ok,
      error: view.error,
      lines: view.lines === null ? null : view.lines.map((line) => ({ id: line.id, status: line.status, message: line.message, next_step: line.nextStep })),
    };
  }

  /** The request's own origin: the public one, or `http://<loopback host>`. */
  function pageOrigin(request: IncomingMessage): string {
    return originNow() ?? `http://${(request.headers.host ?? "").toLowerCase()}`;
  }

  /** A same-origin browser request: no cross-site `Sec-Fetch-Site`, and the page's own `Origin`. */
  function assertSameOrigin(request: IncomingMessage): void {
    const site = request.headers["sec-fetch-site"];
    if (site !== undefined && site !== "same-origin") throw new UiRefusal(403, "cross_site");
    if (request.headers.origin !== pageOrigin(request)) throw new UiRefusal(403, "cross_site");
  }

  /** The writes' extra checks: the session's CSRF token, and a same-origin browser request. */
  function assertWrite(request: IncomingMessage, session: UiSession): void {
    const header = request.headers["x-gray-csrf"];
    if (!csrfMatches(session, typeof header === "string" ? header : undefined)) throw new UiRefusal(403, "csrf");
    assertSameOrigin(request);
  }

  /** Who is asking, for the rate limits: the proxy's client address when it names one, else the socket's. */
  function clientKey(request: IncomingMessage): string {
    const cloudflare = request.headers["cf-connecting-ip"];
    if (typeof cloudflare === "string" && cloudflare.length <= 64) return cloudflare;
    const forwarded = request.headers["x-forwarded-for"];
    if (typeof forwarded === "string") return forwarded.split(",")[0]?.trim().slice(0, 64) ?? "unknown";
    return request.socket.remoteAddress ?? "unknown";
  }

  /** The session a request's cookie names; in public mode only while its passkey is still enrolled for this host. */
  function sessionOf(request: IncomingMessage, nowMs: number, origin: string | null): UiSession | null {
    const session = sessions.find(cookieValue(request, cookieName), nowMs);
    if (session === null) return null;
    if (mode === "public") {
      const rpId = origin === null ? null : new URL(origin).hostname;
      const enrolled = session.passkeyId !== null && passkeys.current().passkeys.some((passkey) => passkey.id === session.passkeyId && passkey.rp_id === rpId);
      if (!enrolled) {
        sessions.close(session.id);
        return null;
      }
    }
    return session;
  }

  function openCeremony(kind: Ceremony["kind"], challenge: string, code: string | null, origin: string, nowMs: number): string {
    for (const [id, ceremony] of ceremonies) if (ceremony.expiresAtMs <= nowMs) ceremonies.delete(id);
    while (ceremonies.size >= 256) {
      const oldest = ceremonies.keys().next().value;
      if (oldest === undefined) break;
      ceremonies.delete(oldest);
    }
    const id = Buffer.from(random(16)).toString("hex");
    ceremonies.set(id, { kind, challenge, expiresAtMs: nowMs + UI_CEREMONY_MS, code, origin });
    return id;
  }

  /** A ceremony is answered once: taken from the map whether or not its answer verifies. */
  function takeCeremony(id: string, kind: Ceremony["kind"], origin: string, nowMs: number): Ceremony {
    const ceremony = ceremonies.get(id);
    ceremonies.delete(id);
    if (ceremony === undefined || ceremony.kind !== kind || ceremony.expiresAtMs <= nowMs || ceremony.origin !== origin) throw new UiRefusal(400, "ceremony_expired");
    return ceremony;
  }

  /** Public mode: enrolment (one-time link → new passkey → a session) and passkey sign-in, on the origin of now. */
  async function passkeyApi(request: IncomingMessage, response: ServerResponse, route: string, nowMs: number, origin: string | null): Promise<boolean> {
    if (mode !== "public" || origin === null) return false;
    const rpId = new URL(origin).hostname;
    if (route === "POST passkeys/options") {
      assertSameOrigin(request);
      if (!enrollLimit.take(clientKey(request), nowMs)) throw new UiRefusal(429, "rate_limited");
      const body = parseBody(enrollOptionsBody, await readJsonBody(request));
      if (!peekUiLink(enrollDir, body.code.trim(), nowMs)) throw new UiRefusal(401, "enroll_link_invalid", "code");
      const store = passkeys.current();
      const optionsJson = await generateRegistrationOptions({
        rpName: `gray-assistant ${config.daemon.relayId}`,
        rpID: rpId,
        userName: `gray-assistant ${config.daemon.relayId}`,
        userID: new Uint8Array(Buffer.from(store.userId, "base64url")),
        userDisplayName: `gray-assistant ${config.daemon.relayId}`,
        attestationType: "none",
        excludeCredentials: store.passkeys.filter((passkey) => passkey.rp_id === rpId).map((passkey) => ({ id: passkey.id, transports: [...passkey.transports] })),
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
      });
      sendJson(response, 200, { ceremony: openCeremony("register", optionsJson.challenge, body.code.trim(), origin, nowMs), options: parsePlain(JSON.stringify(optionsJson)) as SerdeValue });
      return true;
    }
    if (route === "POST passkeys/verify") {
      assertSameOrigin(request);
      if (!enrollLimit.take(clientKey(request), nowMs)) throw new UiRefusal(429, "rate_limited");
      const body = parseBody(enrollVerifyBody, await readJsonBody(request));
      const label = body.label.trim();
      if (!PASSKEY_LABEL.test(label)) throw new UiRefusal(422, "invalid", "label");
      const ceremony = takeCeremony(body.ceremony, "register", origin, nowMs);
      if (ceremony.code !== body.code.trim()) throw new UiRefusal(400, "ceremony_expired");
      let verified;
      try {
        verified = await verifyRegistrationResponse({ response: body.response as unknown as RegistrationResponseJSON, expectedChallenge: ceremony.challenge, expectedOrigin: origin, expectedRPID: rpId, requireUserVerification: true });
      } catch {
        verified = { verified: false as const };
      }
      if (!verified.verified) {
        audit({ action: "passkey.enroll", who: null, outcome: "refused" });
        throw new UiRefusal(401, "passkey_refused");
      }
      // The link is spent only by an enrolment that verified, and only once.
      if (!redeemUiLink(enrollDir, body.code.trim(), nowMs)) throw new UiRefusal(401, "enroll_link_invalid", "code");
      const info = verified.registrationInfo;
      const stored: StoredPasskey = {
        id: info.credential.id,
        public_key: Buffer.from(info.credential.publicKey).toString("base64url"),
        counter: info.credential.counter,
        transports: (info.credential.transports ?? []).filter((transport) => /^[a-z-]{1,32}$/u.test(transport)).slice(0, 8),
        label,
        rp_id: rpId,
        created_at_ms: nowMs,
        last_used_at_ms: nowMs,
        device_type: info.credentialDeviceType,
        backed_up: info.credentialBackedUp,
      };
      await updatePasskeys(passkeysPath(config.daemon.stateFile), random, (store) => ({ store: { userId: store.userId, passkeys: [...store.passkeys.filter((passkey) => passkey.id !== stored.id), stored] }, result: null }));
      passkeys.invalidate();
      const session = sessions.open(nowMs, stored.id);
      audit({ action: "passkey.enroll", who: who(session), target: label, outcome: "ok" });
      sendJson(response, 200, { signed_in: true }, { "set-cookie": sessionCookie(session) });
      return true;
    }
    if (route === "POST login/options") {
      assertSameOrigin(request);
      if (!loginOptionsLimit.take(clientKey(request), nowMs)) throw new UiRefusal(429, "rate_limited");
      // Discoverable passkeys: the browser offers the ones it holds for this host; none is named here.
      const optionsJson = await generateAuthenticationOptions({ rpID: rpId, userVerification: "required", allowCredentials: [] });
      sendJson(response, 200, { ceremony: openCeremony("login", optionsJson.challenge, null, origin, nowMs), options: parsePlain(JSON.stringify(optionsJson)) as SerdeValue });
      return true;
    }
    if (route === "POST login/verify") {
      assertSameOrigin(request);
      if (!loginVerifyLimit.take(clientKey(request), nowMs)) {
        audit({ action: "session.open", who: null, outcome: "rate_limited" });
        throw new UiRefusal(429, "rate_limited");
      }
      const body = parseBody(loginVerifyBody, await readJsonBody(request));
      const ceremony = takeCeremony(body.ceremony, "login", origin, nowMs);
      const passkey = passkeys.current().passkeys.find((item) => item.id === body.response.id && item.rp_id === rpId);
      if (passkey === undefined) {
        audit({ action: "session.open", who: null, outcome: "unknown_passkey" });
        throw new UiRefusal(401, "passkey_refused");
      }
      let verified;
      try {
        verified = await verifyAuthenticationResponse({
          response: body.response as unknown as AuthenticationResponseJSON,
          expectedChallenge: ceremony.challenge,
          expectedOrigin: origin,
          expectedRPID: rpId,
          credential: { id: passkey.id, publicKey: new Uint8Array(Buffer.from(passkey.public_key, "base64url")), counter: passkey.counter, transports: [...passkey.transports] },
          requireUserVerification: true,
        });
      } catch {
        verified = null;
      }
      if (verified === null || !verified.verified) {
        audit({ action: "session.open", who: `passkey:${passkey.id.slice(0, 12)}`, outcome: "refused" });
        throw new UiRefusal(401, "passkey_refused");
      }
      const newCounter = verified.authenticationInfo.newCounter;
      await updatePasskeys(passkeysPath(config.daemon.stateFile), random, (store) => ({
        store: { userId: store.userId, passkeys: store.passkeys.map((item) => (item.id === passkey.id ? { ...item, counter: newCounter, last_used_at_ms: nowMs } : item)) },
        result: null,
      }));
      passkeys.invalidate();
      const session = sessions.open(nowMs, passkey.id);
      audit({ action: "session.open", who: who(session), target: passkey.label, outcome: "ok" });
      sendJson(response, 200, { signed_in: true }, { "set-cookie": sessionCookie(session) });
      return true;
    }
    return false;
  }

  async function api(request: IncomingMessage, response: ServerResponse, path: string, nowMs: number, origin: string | null): Promise<void> {
    const method = request.method ?? "GET";
    const segments = path.split("/").slice(1).map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        throw new UiRefusal(404, "not_found");
      }
    });
    const [area, id, sub] = segments;
    const route = `${method} ${area ?? ""}${id === undefined ? "" : `/${id}`}`;
    // Calls without a session: which sign-in this page takes, and the sign-ins themselves.
    if (route === "GET auth") {
      sendJson(response, 200, { mode });
      return;
    }
    if (await passkeyApi(request, response, route, nowMs, origin)) return;
    // Public mode signs in with passkeys only: no one-time link or code is taken there.
    if (route === "POST session" && mode === "public") throw new UiRefusal(404, "not_found");
    if (route === "POST session" && mode === "loopback") {
      assertSameOrigin(request);
      const body = parseBody(codeBody, await readJsonBody(request));
      if (!redeemUiLink(linksDir, body.code.trim(), nowMs)) throw new UiRefusal(401, "code_invalid", "code");
      const session = sessions.open(nowMs);
      audit({ action: "session.open", who: "link", outcome: "ok" });
      sendJson(response, 200, { signed_in: true }, { "set-cookie": sessionCookie(session) });
      return;
    }
    const session = sessionOf(request, nowMs, origin);
    if (session === null) throw new UiRefusal(401, "signed_out");
    if (method !== "GET") assertWrite(request, session);
    const act = <T>(action: string, target: string | null, run: () => Promise<T>): Promise<T> =>
      run().then(
        (value) => {
          audit({ action, who: who(session), target, outcome: "ok" });
          return value;
        },
        (error: unknown) => {
          audit({ action, who: who(session), target, outcome: error instanceof UiRefusal ? error.code : error instanceof RelayKitError ? error.code : "internal" });
          throw error;
        },
      );
    switch (`${method} ${area ?? ""}${id === undefined ? "" : "/:id"}${sub === undefined ? "" : `/${sub}`}`) {
      case "GET session":
        sendJson(response, 200, { signed_in: true, csrf_token: session.csrf, ...(relayView(readAgentView(config, nowMs)) as Record<string, SerdeValue>) });
        return;
      case "POST session/:id":
        if (id !== "end") break;
        sessions.close(session.id);
        audit({ action: "session.end", who: who(session), outcome: "ok" });
        sendJson(response, 200, { signed_in: false }, { "set-cookie": `${cookieName}=; ${cookieAttributes}; Max-Age=0` });
        return;
      case "GET accounts":
        sendJson(response, 200, accountsValue(nowMs));
        return;
      case "POST accounts": {
        const body = parseBody(newAccountBody, await readJsonBody(request));
        const accountId = body.account_id.trim();
        await act("account.add", accountId, () =>
          addAccount(config.source, config.daemon.relayId, {
            accountId,
            vendor: body.vendor,
            credential: body.credential,
            models: body.models === null ? null : body.models.map((model) => model.trim()).filter((model) => model.length > 0),
            proxy: body.proxy === null || body.proxy.trim() === "" ? null : body.proxy.trim(),
          }),
        );
        editedAt.set(accountId, nowMs);
        sendJson(response, 201, accountsValue(nowMs));
        return;
      }
      case "PUT accounts/:id/credential": {
        const body = parseBody(replaceBody, await readJsonBody(request));
        await act("account.replace_key", id as string, () => replaceCredential(config.source, config.daemon.relayId, id as string, body.credential));
        editedAt.set(id as string, nowMs);
        sendJson(response, 200, accountsValue(nowMs));
        return;
      }
      case "DELETE accounts/:id":
        await act("account.remove", id as string, () => removeAccount(config.source, config.daemon.relayId, id as string));
        editedAt.delete(id as string);
        sendJson(response, 200, accountsValue(nowMs));
        return;
      case "GET releases":
        sendJson(response, 200, await releasesValue(nowMs));
        return;
      case "POST releases/:id": {
        const controlFile = controlFileBeside(config.daemon.stateFile);
        if (id === "accept") {
          const body = parseBody(releaseIdBody, await readJsonBody(request));
          const outcome = await act("release.accept", body.id.trim(), async () => {
            // The page lists what the agent has seen; an id it has not seen yet is refused (`not_seen`) rather than
            // recorded as an acceptance that would not count (R27). Its Accept button only shows for listed releases.
            const result = await acceptReleaseId(config, controlFile, body.id.trim(), () => nowMs, { waitMs: 0, agentRunning: true, sleep: async () => undefined });
            if (!result.ok) throw new UiRefusal(409, result.code);
            return result;
          });
          sendJson(response, 200, { ok: true, kind: outcome.kind, provenance: outcome.kind === "os_image" ? outcome.provenance : "ok", releases: await releasesValue(nowMs) });
          return;
        }
        if (id === "reject" || id === "unreject") {
          const body = parseBody(hashBody, await readJsonBody(request));
          const hash = body.hash.trim();
          if (!/^[0-9a-f]{64}$/u.test(hash)) throw new UiRefusal(422, "invalid", "hash");
          await act(`release.${id}`, hash, async () => {
            const result = await vetoRelease(config, controlFile, id, hash, nowMs);
            if (!result.ok) throw new UiRefusal(409, result.code);
            return result;
          });
          sendJson(response, 200, { ok: true, releases: await releasesValue(nowMs) });
          return;
        }
        break;
      }
      case "GET health":
        sendJson(response, 200, healthValue(nowMs));
        return;
      case "POST health/:id":
        if (id !== "run") break;
        health.start();
        audit({ action: "health.run", who: who(session), outcome: "ok" });
        sendJson(response, 202, healthValue(nowMs));
        return;
    }
    throw new UiRefusal(404, "not_found");
  }

  function serveStatic(request: IncomingMessage, response: ServerResponse, path: string): void {
    const file = bundle.get(path) ?? (path.startsWith("/assets/") || extname(path) !== "" ? undefined : bundle.get("/index.html"));
    if (file === undefined) {
      if (!bundle.has("/index.html")) {
        send(response, 503, { "content-type": "text/plain; charset=utf-8" }, "This gray-assistant was built without its page (assets/ui is empty).\n");
        return;
      }
      send(response, 404, { "content-type": "text/plain; charset=utf-8" }, "Not found.\n");
      return;
    }
    const hashed = path.startsWith("/assets/");
    if (request.headers["if-none-match"] === file.etag) {
      send(response, 304, { etag: file.etag });
      return;
    }
    send(response, 200, { "content-type": file.type, etag: file.etag, "cache-control": hashed ? "public, max-age=31536000, immutable" : "no-cache" }, request.method === "HEAD" ? "" : file.body);
  }

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<boolean> {
    let url: URL;
    try {
      url = new URL(request.url ?? "/", "http://ui");
    } catch {
      if (mode === "public") return false;
      send(response, 400, { "content-type": "text/plain; charset=utf-8" }, "Bad request.\n");
      return true;
    }
    const path = url.pathname;
    const ours = path === UI_BASE || path.startsWith(`${UI_BASE}/`) || (mode === "loopback" && path === "/");
    if (!ours) return false;
    const nowMs = now();
    const origin = originNow();
    if (mode === "public" && origin === null) {
      send(response, 503, { "content-type": "text/plain; charset=utf-8", "retry-after": "60" }, "gray-assistant's page has no public address yet.\n");
      return true;
    }
    const hostOk = origin !== null ? hostUrl(request.headers.host)?.host === new URL(origin).host : isLoopbackHostHeader(request.headers.host);
    if (!hostOk) {
      send(response, 421, { "content-type": "text/plain; charset=utf-8" }, mode === "public" ? "gray-assistant's page answers on the relay's own origin only.\n" : "gray-assistant's page answers on 127.0.0.1 only.\n");
      return true;
    }
    const method = request.method ?? "GET";
    try {
      if (path === "/" || path === UI_BASE) {
        send(response, 303, { location: `${UI_BASE}/`, "cache-control": "no-store" });
        return true;
      }
      const sub = path.slice(UI_BASE.length);
      if (sub.startsWith("/api/")) {
        await api(request, response, sub.slice("/api".length), nowMs, origin);
        return true;
      }
      if (method === "GET" && sub.startsWith("/session/") && mode === "loopback") {
        // A sign-in link: one code, one session, then the page (and the code is gone from the address bar).
        const code = sub.slice("/session/".length);
        const next = safeNext(url.searchParams.get("next"));
        if (!redeemUiLink(linksDir, code, nowMs)) {
          send(response, 303, { location: `${UI_BASE}/?link=expired`, "cache-control": "no-store" });
          return true;
        }
        const session = sessions.open(nowMs);
        audit({ action: "session.open", who: "link", outcome: "ok" });
        send(response, 303, { location: next, "set-cookie": sessionCookie(session), "cache-control": "no-store" });
        return true;
      }
      if (method !== "GET" && method !== "HEAD") {
        send(response, 405, { allow: "GET, HEAD", "content-type": "text/plain; charset=utf-8" }, "Method not allowed.\n");
        return true;
      }
      serveStatic(request, response, sub);
    } catch (error) {
      if (error instanceof UiRefusal) {
        refusal(response, error);
        return true;
      }
      if (error instanceof RelayKitError) {
        // A busy lock, an unreadable file, a release list that does not verify: the closed code and its member only.
        const busy = error.message.includes("holds");
        refusal(response, new UiRefusal(busy ? 409 : 500, busy ? "busy" : error.code, null, busy ? null : error.detail));
        return true;
      }
      options.io.stderr("gray-assistant ui: internal error\n");
      refusal(response, new UiRefusal(500, "internal"));
    }
    return true;
  }

  return {
    mode,
    origin: originNow,
    handle,
    mintLink(base: string) {
      const link = mintUiLink(linksDir, now(), random);
      return { url: `${base}${UI_BASE}/session/${link.code}`, code: link.code, expiresAtMs: link.expiresAtMs };
    },
    stop() {
      sessions.clear();
      ceremonies.clear();
    },
  };
}

/** Start the page in loopback mode on its own 127.0.0.1 listener. */
export async function startRelayUi(options: RelayUiOptions): Promise<RunningRelayUi> {
  const config = loadRelayConfigFile(options.configPath);
  const port = options.port ?? config.daemon.ui?.port ?? DEFAULT_UI_PORT;
  if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new RelayKitError("usage", "--port must be a TCP port");
  const handler = await createRelayUiHandler({ ...options, mode: "loopback", config });
  const server: Server = createServer((request, response) => {
    void handler.handle(request, response).then((handled) => {
      if (!handled) send(response, 404, { "content-type": "text/plain; charset=utf-8" }, "Not found.\n");
    });
  });
  server.headersTimeout = 20_000;
  server.requestTimeout = 60_000;
  const actualPort = await new Promise<number>((resolvePort, reject) => {
    server.once("error", (error: NodeJS.ErrnoException) => reject(new RelayKitError("io", error.code === "EADDRINUSE" ? `port ${port} on ${options.host ?? "127.0.0.1"} is in use; pick another with --port` : `cannot listen on 127.0.0.1:${port}`)));
    server.listen(port, options.host ?? "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") reject(new RelayKitError("io", "no port"));
      else resolvePort(address.port);
    });
  });
  const base = `http://127.0.0.1:${actualPort}`;
  // The agent's status (S45) carries the page's port while this marker is fresh, so Gray's panel can link here.
  const marker = uiMarkerPath(config.daemon.stateFile);
  const touchMarker = (): void => {
    try {
      writeUiMarker(marker, actualPort, options.io.now());
    } catch {
      // The panel then has no link; the page itself works.
    }
  };
  touchMarker();
  const markerTimer = setInterval(touchMarker, UI_MARKER_EVERY_MS);
  markerTimer.unref();
  return {
    url: base,
    port: actualPort,
    config,
    mintLink: () => handler.mintLink(base),
    async stop() {
      clearInterval(markerTimer);
      removeUiMarker(marker);
      handler.stop();
      await new Promise<void>((resolveClose) => {
        server.close(() => resolveClose());
        server.closeAllConnections();
      });
    },
  };
}
