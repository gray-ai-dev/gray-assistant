// The local page's addresses are real paths under /ui/ (`/ui/accounts/new?id=…`), the same on 127.0.0.1 and on the
// relay's public origin, so Gray's panel can link to one and the operator can bookmark it; gray-assistant answers every page
// path with the same index.html. Links stay plain `<a href>`: one click handler on the document turns a same-origin
// click into a history entry instead of a reload. Pages name paths without the base (`/accounts`); `href` adds it.
import { useSyncExternalStore } from 'react';

/** Where the page lives on either origin (workers/packages/relay-kit/src/node/ui/server.ts `UI_BASE`). */
export const BASE = '/ui';

export type Route = { readonly path: string; readonly query: URLSearchParams };

/** A page's address: `/accounts` → `/ui/accounts`. */
export function href(path: string): string {
  return `${BASE}${path.startsWith('/') ? path : `/${path}`}`;
}

const listeners = new Set<() => void>();
let snapshot: Route = current();

function current(): Route {
  const inside = window.location.pathname.startsWith(`${BASE}/`) ? window.location.pathname.slice(BASE.length) : '/';
  return { path: inside.replace(/\/+$/, '') || '/', query: new URLSearchParams(window.location.search) };
}

function changed() {
  snapshot = current();
  for (const listener of listeners) listener();
}

/** Go to a page (`/accounts/new?…`); `replace` keeps the history entry (a redirect, a form that finished). */
export function navigate(to: string, { replace = false }: { replace?: boolean } = {}) {
  if (replace) window.history.replaceState(null, '', href(to));
  else window.history.pushState(null, '', href(to));
  window.scrollTo(0, 0);
  changed();
}

/** Same-origin clicks on the page's own links become history entries; anything else keeps the browser's behaviour. */
export function interceptLinks(): () => void {
  const onClick = (event: MouseEvent) => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const anchor = (event.target as Element | null)?.closest?.('a[href]');
    if (!(anchor instanceof HTMLAnchorElement) || anchor.target || anchor.hasAttribute('download')) return;
    const url = new URL(anchor.href);
    if (url.origin !== window.location.origin || !(url.pathname === BASE || url.pathname.startsWith(`${BASE}/`))) return;
    event.preventDefault();
    if (url.pathname + url.search !== window.location.pathname + window.location.search) navigate(`${url.pathname.slice(BASE.length) || '/'}${url.search}`);
  };
  const onPop = () => changed();
  document.addEventListener('click', onClick);
  window.addEventListener('popstate', onPop);
  return () => {
    document.removeEventListener('click', onClick);
    window.removeEventListener('popstate', onPop);
  };
}

export function useRoute(): Route {
  return useSyncExternalStore(listener => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }, () => snapshot);
}
