// The relay's local page (`gray-assistant ui`): Gray's app bar and design system around five pages that gray-assistant serves on
// the relay's own machine. The bar says where the page runs, so it is never mistaken for Gray's website: keys typed
// here go to gray-assistant on the relay's machine and nowhere else.
import { useEffect, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { BrandMark, BrandWordmark } from '../components/Brand';
import { Menu as MenuIcon, Moon, ShieldCheck, Sun } from '../components/icons';
import { Badge, Button, CodeBlock, Drawer, FixedLayer, IconButton, LinkButton, Notice, OverflowNav, Page, PageHeader, Skeleton, Stack, Text } from '../ui';
import { ApiError, read, setCsrfToken, write, type Session, type UiMode } from './api';
import { href, interceptLinks, useRoute } from './router';
import { AGENT_WORDS, clockText, ctAlertText, refusalText } from './words';
import { AccountsPage } from './pages/Accounts';
import { EnrollPage, SignInPage } from './pages/SignIn';
import { AddAccountPage } from './pages/AddAccount';
import { HealthPage } from './pages/Health';
import { LoginsPage } from './pages/Logins';
import { ReleasesPage } from './pages/Releases';

type PageKey = 'accounts' | 'logins' | 'releases' | 'image' | 'health';

const PAGES: readonly { key: PageKey; label: string; href: string }[] = [
  { key: 'accounts', label: 'Accounts', href: href('/accounts') },
  { key: 'logins', label: 'Logins', href: href('/logins') },
  { key: 'releases', label: 'Releases', href: href('/releases') },
  // The image page arrives with `gray-assistant stack` (rollout, rollback); the server says when it is there.
  { key: 'image', label: 'Image', href: href('/image') },
  { key: 'health', label: 'Health', href: href('/health') },
];

function pageOf(path: string): PageKey | 'add-account' | 'enroll' | null {
  if (path === '/' || path === '/accounts') return 'accounts';
  // `gray-assistant ui enroll`'s one-time link (public mode).
  if (/^\/enroll\/[A-Za-z0-9_-]{43}$/.test(path)) return 'enroll';
  if (path === '/accounts/new') return 'add-account';
  // Gray's panel links a login's re-login to /logins/<login>.
  if (/^\/logins\/[^/]+$/.test(path)) return 'logins';
  const key = path.slice(1) as PageKey;
  return PAGES.some(page => page.key === key) ? key : null;
}

/** The login a `/logins/<login>` address names. */
function loginOf(path: string): string | null {
  const match = /^\/logins\/([^/]+)$/.exec(path);
  if (!match) return null;
  try { return decodeURIComponent(match[1]!); } catch { return null; }
}

function useTheme(): [boolean, (dark: boolean) => void] {
  const [dark, setDark] = useState(() => localStorage.getItem('gray-theme') === 'dark');
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    localStorage.setItem('gray-theme', dark ? 'dark' : 'light');
    const bg = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim();
    if (bg) document.querySelector('meta[name="theme-color"]')?.setAttribute('content', bg);
  }, [dark]);
  return [dark, setDark];
}

export function App() {
  const route = useRoute();
  const client = useQueryClient();
  const [dark, setDark] = useTheme();
  const [menu, setMenu] = useState(false);
  useEffect(() => interceptLinks(), []);
  const session = useQuery<Session, ApiError>({ queryKey: ['session'], queryFn: ({ signal }) => read<Session>('session', signal), refetchInterval: 15_000, refetchOnWindowFocus: true });
  // Which sign-in this page takes (a code on 127.0.0.1, a passkey on the relay's public origin); asked without a session.
  const auth = useQuery<{ mode: UiMode }, ApiError>({ queryKey: ['auth'], queryFn: ({ signal }) => read<{ mode: UiMode }>('auth', signal), staleTime: Infinity });
  const mode: UiMode = session.data?.mode ?? auth.data?.mode ?? 'loopback';
  useEffect(() => { if (session.data) setCsrfToken(session.data.csrf_token); }, [session.data]);
  const signedOut = session.error?.code === 'signed_out';
  const info = signedOut ? null : session.data ?? null;
  const page = pageOf(route.path);
  const current = page === 'add-account' ? 'accounts' : page;
  const links = info ? PAGES.filter(item => item.key !== 'image' || info.features.image).map(item => ({ ...item, current: item.key === current })) : [];
  useEffect(() => {
    setMenu(false);
    const label = page === 'add-account' ? 'Add account' : page === 'enroll' ? 'Add a passkey' : PAGES.find(item => item.key === page)?.label;
    document.title = signedOut && page !== 'enroll' ? 'Sign in · gray-assistant' : `${label ?? 'Not found'} · gray-assistant${info ? ` · ${info.relay_id}` : ''}`;
  }, [route.path, signedOut, info?.relay_id]);

  async function signOut() {
    try { await write('POST', 'session/end'); } catch { /* signed out either way */ }
    // Every read starts over (no data of the session stays on screen); the session read then says signed out.
    await client.resetQueries();
  }

  let content: ReactNode;
  if (page === 'enroll' && mode === 'public' && !auth.isLoading) content = <EnrollPage code={route.path.slice('/enroll/'.length)} />;
  else if (session.isLoading || (signedOut && auth.isLoading)) content = <Page><Skeleton lines={4} label="Loading gray-assistant’s page" /></Page>;
  else if (signedOut) content = <SignInPage mode={mode} expired={route.query.get('link') === 'expired'} />;
  else if (session.error || !info) content = <Unreachable error={session.error} onRetry={() => void session.refetch()} />;
  else if (page === 'accounts') content = <AccountsPage relay={info} />;
  else if (page === 'add-account') content = <AddAccountPage relay={info} query={route.query} />;
  else if (page === 'logins') content = <LoginsPage relay={info} login={loginOf(route.path) ?? route.query.get('login')} />;
  else if (page === 'releases') content = <ReleasesPage relay={info} />;
  else if (page === 'health') content = <HealthPage relay={info} />;
  else content = <Page size="narrow"><Stack gap={6}>
    <PageHeader title="No page here" description="gray-assistant’s page has Accounts, Logins, Releases and Health." />
    <div><LinkButton variant="primary" href={href('/accounts')}>Go to Accounts</LinkButton></div>
  </Stack></Page>;

  const agent = info ? AGENT_WORDS[info.agent.state] : null;
  // On every page while the tunnel's CT monitor has a finding (docs/relay-tunnel.md).
  const ctAlert = info ? ctAlertText(info.tunnel) : null;
  return <>
    <a className="skip-link" href="#main" onClick={event => { event.preventDefault(); document.getElementById('main')?.focus(); }}>Skip to content</a>
    <FixedLayer><header className="appbar relay-ui-appbar">
      <a href={href('/accounts')} className="brand" aria-label="gray-assistant, accounts">
        <BrandMark />
        <BrandWordmark />
      </a>
      <span className="relay-ui-where">
        {mode === 'public'
          ? <Badge icon={<ShieldCheck size={14} aria-hidden="true" />} title={`gray-assistant serves this page from your relay at ${window.location.host}. Keys you enter here go to gray-assistant and nowhere else: Gray’s website never sees them.`}>gray-assistant page</Badge>
          : <Badge icon={<ShieldCheck size={14} aria-hidden="true" />} title="gray-assistant serves this page on 127.0.0.1 of your relay’s machine, reached directly or through ssh -L. Keys you enter here go to gray-assistant there and nowhere else: Gray’s website never sees them.">gray-assistant page</Badge>}
      </span>
      {links.length > 0 && <OverflowNav className="desktop-nav" label="Pages" links={links} />}
      <div className="account-nav">
        {info && agent && <span className="relay-ui-relay">
          <Text as="span" weight="medium" truncate className="relay-ui-relay__id">{info.relay_id}</Text>
          <Badge tone={agent.tone} dot title={info.agent.as_of_ms ? `Last report ${clockText(info.agent.as_of_ms, Date.now())}` : undefined}>{info.agent.paused ? 'Paused' : agent.label}</Badge>
        </span>}
        <div className="account-controls">
          <IconButton size="sm" label={dark ? 'Use light theme' : 'Use dark theme'} icon={dark ? <Sun size={18} aria-hidden="true" /> : <Moon size={18} aria-hidden="true" />} onClick={() => setDark(!dark)} />
          {info && <Button size="sm" variant="ghost" className="relay-ui-sign-out" onClick={() => void signOut()}>Sign out</Button>}
        </div>
        {links.length > 0 && <IconButton size="sm" className="mobile-menu" label="Pages" icon={<MenuIcon size={20} aria-hidden="true" />} aria-haspopup="dialog" aria-expanded={menu} onClick={() => setMenu(true)} />}
      </div>
    </header></FixedLayer>
    {links.length > 0 && <Drawer open={menu} onOpenChange={setMenu} title="Pages"
      description={info && agent ? `${info.relay_id} · gray-assistant ${info.agent.paused ? 'paused' : agent.label.toLowerCase()}` : undefined}>
      <nav className="mobile-navigation" aria-label="Pages">
        <div className="mobile-navigation-primary">
          {links.map(link => <a key={link.key} href={link.href} aria-current={link.current ? 'page' : undefined}>{link.label}</a>)}
        </div>
        <div className="relay-ui-mobile-footer">
          <Button variant="ghost" onClick={() => { setMenu(false); void signOut(); }}>Sign out</Button>
        </div>
      </nav>
    </Drawer>}
    <main id="main" tabIndex={-1}>
      {ctAlert && <Page className="relay-ui-banner"><Notice tone="danger" role="alert" title={ctAlert.title}>{ctAlert.detail}</Notice></Page>}
      {content}
    </main>
  </>;
}

function Unreachable({ error, onRetry }: { error: ApiError | null; onRetry: () => void }) {
  return <Page size="narrow">
    <Stack gap={6}>
      <PageHeader title="gray-assistant doesn’t answer" />
      <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={onRetry}>Try again</Button>}>
        {refusalText(error?.code ?? 'unreachable')}
      </Notice>
      <CodeBlock language="bash" copyLabel="Copy command" description="Start it again on the relay’s machine (or gray-assistant run with ui.listen in its config):"
        code="gray-assistant ui" />
    </Stack>
  </Page>;
}
