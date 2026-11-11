// The local page's API, served by `gray-assistant ui` under /ui/api/ (workers/packages/relay-kit/src/node/ui/server.ts), on
// 127.0.0.1 or on the relay's public origin.
// Every read needs the session cookie; every write also sends the session's CSRF token and a JSON body. No answer
// carries a key: the page sends a key once, in the write that stores it, and never reads one back.
import type { CompatibleVendor } from '../runtime/lane-vendors.ts';

export type Vendor = 'anthropic' | 'openai' | 'chatgpt_codex' | CompatibleVendor;
/** What accounts.json may name; `sign_in` and `password` accounts sign in inside the VM (`gray-assistant login <account>`). */
export type CredentialType = 'api_key' | 'oauth_access_token' | 'sign_in' | 'password';
/** What the add-account form and a key replacement take: a pasted secret. */
export type PastedCredentialType = 'api_key' | 'oauth_access_token';
export type AgentState = 'running' | 'stopped' | 'stale' | 'not_running';

/** Where this page is served: 127.0.0.1 (one-time sign-in links) or the relay's public origin (passkeys only). */
export type UiMode = 'loopback' | 'public';

export type RelayInfo = {
  relay_id: string;
  mode: UiMode;
  config_path: string;
  /** gray-assistant finds this config without `--config` ($GRAY_ASSISTANT_CONFIG, /etc/gray-assistant, ./gray-assistant.jsonc). */
  config_default: boolean;
  source: { kind: 'file' | 'http' | 'cliproxyapi' };
  agent: { state: AgentState; as_of_ms: number | null; ready: boolean; paused: boolean };
  features: { image: boolean };
  /** The relay tunnel and its CT monitor's verdict (docs/relay-tunnel.md); null without a tunnel section. */
  tunnel: { state: 'connected' | 'down'; name: string; ct: { state: 'ok' | 'alert' | 'unknown'; findings: number; checked_ms: number | null } | null } | null;
};

export type Session = RelayInfo & { signed_in: true; csrf_token: string };

export type SealedState = 'sealed' | 'partly' | 'waiting' | 'parked' | 'unknown';

export type Account = {
  account_id: string;
  /**
   * The account's id on Gray's panel when it is not `account_id` (S59): a source id that is no panel id, an e-mail
   * address, gets a plain one on this host (`codex-1`). Absent from gray-assistant before it.
   */
  panel_id?: string;
  vendor: Vendor;
  credential_type: CredentialType;
  status: string;
  models: string[] | '*';
  proxy: { type: string; host: string; port: number; username: string | null } | null;
  credential_expires_at_ms: number | null;
  selected: boolean;
  sealed: { state: SealedState; version: string | null; at_ms: number | null; reason: string | null };
};

export type AccountsView = {
  relay: RelayInfo;
  source: {
    kind: 'file' | 'http' | 'cliproxyapi';
    path: string | null;
    url: string | null;
    exists: boolean;
    writable: boolean;
    problem: { code: string; detail: string } | null;
  };
  source_poll_ms: number;
  agent_last_poll_at_ms: number | null;
  accounts: Account[];
};

export type Release = {
  kind: 'release' | 'os_image';
  hash: string;
  git_commit: string | null;
  version: string | null;
  first_seen_ms: number | null;
  acceptable_at_ms: number | null;
  acceptable: boolean;
  accepted: boolean;
  /** Accepted because it was in Gray’s list when this relay paired (gray-assistant init --pair). */
  accepted_at_pairing: boolean;
  rejected: boolean;
  refusal: string | null;
};

export type ReleasesView = {
  relay: RelayInfo;
  accept_mode: 'auto-after-delay' | 'manual';
  delay_days: number;
  release_list: { current_until_ms: number | null; last_error: string | null } | null;
  accepted: string[];
  rejected: string[];
  releases: Release[];
  replicas: { origin: string; phase: string; last_error: string | null }[];
};

export type HealthStatus = 'ok' | 'warn' | 'fail' | 'skip';

export type HealthView = {
  relay: RelayInfo;
  running: boolean;
  started_at_ms: number | null;
  finished_at_ms: number | null;
  ok: boolean | null;
  error: string | null;
  lines: { id: string; status: HealthStatus; message: string; next_step: string | null }[] | null;
};

/** A refusal from the page's server: its closed code, the form field it belongs to, a member path at most. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly field: string | null;
  readonly detail: string | null;
  constructor(status: number, code: string, field: string | null, detail: string | null) {
    super(code);
    this.status = status;
    this.code = code;
    this.field = field;
    this.detail = detail;
  }
}

/** Set by the session read; every write sends it back. */
let csrfToken = '';
export function setCsrfToken(token: string) {
  csrfToken = token;
}

async function errorOf(response: Response): Promise<ApiError> {
  try {
    const body = await response.json() as { error?: { code?: string; field?: string | null; detail?: string | null } };
    return new ApiError(response.status, body.error?.code ?? 'unknown', body.error?.field ?? null, body.error?.detail ?? null);
  } catch {
    return new ApiError(response.status, response.status === 421 ? 'not_loopback' : 'unknown', null, null);
  }
}

export async function read<T>(path: string, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/ui/api/${path}`, { credentials: 'same-origin', signal, headers: { accept: 'application/json' } });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new ApiError(0, 'unreachable', null, null);
  }
  if (!response.ok) throw await errorOf(response);
  return await response.json() as T;
}

export async function write<T>(method: 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/ui/api/${path}`, {
      method,
      credentials: 'same-origin',
      headers: { accept: 'application/json', 'x-gray-csrf': csrfToken, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'unreachable', null, null);
  }
  if (!response.ok) throw await errorOf(response);
  return await response.json() as T;
}
