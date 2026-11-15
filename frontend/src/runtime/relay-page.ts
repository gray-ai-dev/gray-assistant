// Links from Gray's panel to the relay's own page (gray-assistant ui), where a key is typed on the relay's side and Gray's
// pages never see it. Where that page answers comes from the relay's signed agent status (S45 `ui_mode`, `ui_port`) and
// from what Gray already stores, never from free text the relay sends:
// - `loopback`: http://127.0.0.1:<ui_port> on the operator's machine (they reach the relay's 127.0.0.1 through their own
//   SSH tunnel or private network);
// - `public`: the relay's own HTTPS origin, the one its status names (`ui_origin`, gray-assistant's `ui.origin`:
//   docs/design/relay-operator-page.md section 3), or for an older status without it its token service's (`token_url`,
//   an https origin the console keeps);
// - `tunnel`: the relay tunnel's https://<relay-id>.<relays zone>, which the caller passes in.
// The page lives under /ui/ in every mode. Each link opens in a new tab, so the address bar shows the relay's address.

export type RelayPageMode = 'loopback' | 'public' | 'tunnel';

/** The part of the agent status (`GET …/lane-stacks/{relay}/agent-status` → `status`) that says where the page runs. */
export type RelayPageStatus = { ui_mode?: string; ui_port?: number; ui_origin?: string } | null | undefined;

/** The relay's page origin now, or null while it runs nowhere Gray can link to. */
export function relayPageOrigin(relay: { token_url: string | null }, status: RelayPageStatus, tunnelOrigin: string | null = null): string | null {
  if (!status) return null;
  if (status.ui_mode === 'loopback') {
    const port = status.ui_port;
    return typeof port === 'number' && Number.isInteger(port) && port >= 1024 && port <= 65_535 ? `http://127.0.0.1:${port}` : null;
  }
  if (status.ui_mode === 'public') return status.ui_origin === undefined ? httpsOrigin(relay.token_url) : pageOrigin(status.ui_origin);
  if (status.ui_mode === 'tunnel') return httpsOrigin(tunnelOrigin);
  return null;
}

function httpsOrigin(value: string | null): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.origin : null;
  } catch {
    return null;
  }
}

/** The origin a status names for the page: https, at most 255 characters, and nothing but the origin (no path, query or user info). */
function pageOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 255) return null;
  const origin = httpsOrigin(value);
  return origin === value ? origin : null;
}

/** The page's "Add account" form, filled with the account the panel knows: the operator only pastes the key there. */
export function addAccountUrl(origin: string, account: { account_id?: string; vendor?: string; models?: readonly string[]; credential_type?: string; group?: string | null }): string {
  const query = new URLSearchParams();
  if (account.account_id) query.set('id', account.account_id);
  if (account.vendor) query.set('vendor', account.vendor);
  if (account.models?.length) query.set('models', account.models.join(','));
  if (account.credential_type) query.set('type', account.credential_type);
  // The group chosen in the panel: the page offers it for the new account and sets it on Gray once Gray has the account.
  if (account.group) query.set('group', account.group);
  const text = query.toString();
  return `${origin}/ui/accounts/new${text ? `?${text}` : ''}`;
}

/** The parts of an account's own screen a jump opens: its sign-in, its key, its proxy. */
export type AccountPart = 'sign-in' | 'key' | 'proxy';

/** One account's screen on the page, or the part of it a jump is for (`/ui/accounts/{id}/sign-in`, `/key`, `/proxy`). */
export function accountUrl(origin: string, accountId: string, part?: AccountPart): string {
  return `${origin}/ui/accounts/${encodeURIComponent(accountId)}${part ? `/${part}` : ''}`;
}

/** One proxy for several accounts (`/ui/accounts/proxy?ids=a,b`). */
export function bulkProxyUrl(origin: string, accountIds: readonly string[]): string {
  return `${origin}/ui/accounts/proxy?ids=${accountIds.map(encodeURIComponent).join(',')}`;
}
