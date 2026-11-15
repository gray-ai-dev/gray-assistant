// Which screen a path of the page is (docs/design/relay-operator-page.md section 7, Screens). Gray's panel links to
// these addresses, so they are a contract: `/accounts/{id}/sign-in`, `/key` and `/proxy` open one account at that part.
// Pure, so `words.test.mjs` reads it in Node.

/** The parts of one account's screen a link can open. */
export type AccountPart = 'sign-in' | 'key' | 'proxy';

export type Screen =
  | { page: 'accounts' }
  | { page: 'add-account' }
  | { page: 'bulk-proxy' }
  | { page: 'account'; id: string; part: AccountPart | null }
  | { page: 'proxies' }
  | { page: 'health' }
  | { page: 'enroll'; code: string };

/** The screen of a path without the `/ui` base (`/accounts/claude-max-01/sign-in`); null for none. */
export function screenOf(path: string): Screen | null {
  if (path === '/' || path === '/accounts') return { page: 'accounts' };
  if (path === '/accounts/new') return { page: 'add-account' };
  if (path === '/accounts/proxy') return { page: 'bulk-proxy' };
  if (path === '/proxies') return { page: 'proxies' };
  if (path === '/health') return { page: 'health' };
  // `gray-assistant ui enroll`'s one-time link (public mode).
  const enroll = /^\/enroll\/([A-Za-z0-9_-]{43})$/.exec(path);
  if (enroll) return { page: 'enroll', code: enroll[1]! };
  const account = /^\/accounts\/([^/]+)(?:\/(sign-in|key|proxy))?$/.exec(path);
  if (!account) return null;
  try {
    return { page: 'account', id: decodeURIComponent(account[1]!), part: (account[2] as AccountPart | undefined) ?? null };
  } catch {
    return null;
  }
}

/** One account's address, at a part or at its top. */
export function accountPath(id: string, part?: AccountPart): string {
  return `/accounts/${encodeURIComponent(id)}${part ? `/${part}` : ''}`;
}

/** The address that sets one proxy for several accounts. */
export function bulkProxyPath(ids: readonly string[]): string {
  return `/accounts/proxy?ids=${ids.map(id => encodeURIComponent(id)).join(',')}`;
}
