// The local page's API, served by `gray-assistant ui` under /ui/api/ (workers/packages/relay-kit/src/node/ui/server.ts), on
// 127.0.0.1 or on the relay's public origin.
// Every read needs the session cookie; every write also sends the session's CSRF token and a JSON body. No answer
// carries a key: the page sends a key once, in the write that stores it, and never reads one back.
import type { CompatibleVendor } from '../runtime/lane-vendors.ts';
import type { StackAccount } from '../runtime/relay-stack.ts';
import type { StackHealth } from '../runtime/relay-stack-health.ts';

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
  source: { kind: 'file' | 'http' };
  agent: { state: AgentState; as_of_ms: number | null; ready: boolean; paused: boolean };
  features: { image: boolean; sign_in?: boolean; push?: boolean; panel?: boolean };
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
  /** The entry of the file's proxy list the account names; null for none or for a proxy written inline in the account. */
  proxy_id?: string | null;
  credential_expires_at_ms: number | null;
  selected: boolean;
  sealed: { state: SealedState; version: string | null; at_ms: number | null; reason: string | null };
};

export type AccountsView = {
  relay: RelayInfo;
  source: {
    kind: 'file' | 'http';
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

/** One entry of the account file's proxy list. Its password is never in an answer: `has_password` says there is one. */
export type Proxy = { id: string; type: string; host: string; port: number; username: string | null; has_password: boolean; used_by: string[] };
export type ProxiesView = { proxies: Proxy[] };

/**
 * The last send of the account file to the VM (what `accounts push` does): a write of this page starts one by itself.
 * `refused` and `failed` carry the command's own words in `message`.
 */
export type PushState = 'idle' | 'running' | 'ok' | 'refused' | 'failed';
export type PushView = {
  state: PushState; at_ms: number | null;
  /** `ok`: the accounts the VM holds now, and how many of the source's were left out. */
  accounts?: number; accounts_left_out?: number;
  /** `refused`: the command's closed code; `refused` and `failed`: why, in the command's words. */
  code?: string; message?: string;
};

/** A subscription account's sign-in inside the VM, as the page's server follows it (ui/sign-in.ts). */
export type SignInState = 'starting' | 'prompt' | 'working' | 'done' | 'failed';
/** What the operator acts on. `paste` says what the field takes back: a code, the address the browser ended on, or nothing (a device code). */
export type SignInPrompt = { kind: 'url' | 'device_code'; url: string; code?: string; paste: 'code' | 'address' | null; expires_at_ms: number };
export type SignInView = {
  session: string; account_id: string; state: SignInState; vendor?: string; prompt?: SignInPrompt;
  /** Where the sign-in stands, or why the last paste was not it, in a sentence. */
  message?: string;
  /** `failed` only: the closed code (`cancelled`, `expired`, a refusal of the VM's). */
  code?: string;
};

/**
 * What Gray's panel knows of the relay's accounts (docs/design/relay-operator-page.md section 5): the bodies of the
 * console's `GET …/accounts` (with `group`) and `GET …/health`. `null` while Gray does not answer.
 */
export type PanelAccount = StackAccount & { group: string | null };
export type PanelView = { accounts: PanelAccount[]; health: StackHealth } | null;

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
  // A write whose answer has no body (a removal) is still done.
  return await response.json().catch(() => null) as T;
}
