// The relay's local page (`gray-assistant ui`): Gray's app bar and design system around the screens gray-assistant
// serves on the relay's own machine (docs/design/relay-operator-page.md section 7): the accounts, one account, the
// proxies, and gray-assistant's checks. The bar says where the page runs, so it is never mistaken for Gray's website:
// keys typed here go to gray-assistant on the relay's machine and nowhere else. Under the bar the shell says, quietly,
// whether the last change has reached the VM.
import { useEffect, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { BrandMark, BrandWordmark } from '../components/Brand';
import { Menu as MenuIcon, Moon, ShieldCheck, Sun } from '../components/icons';
import { Badge, Button, CodeBlock, Drawer, FixedLayer, IconButton, LinkButton, Notice, OverflowNav, Page, PageHeader, Skeleton, Spinner, Stack, Text, toast } from '../ui';
import { ApiError, read, setCsrfToken, write, type PushView, type Session, type UiMode } from './api';
import { BUSY_MS, LIVE_MS, useLocal, useNow } from './data';
import { href, interceptLinks, useRoute } from './router';
import { screenOf, type Screen } from './screens';
import { AGENT_WORDS, clockText, ctAlertText, pushWords, refusalText } from './words';
import { AccountsPage } from './pages/Accounts';
import { EnrollPage, SignInPage } from './pages/SignIn';
import { AddAccountPage } from './pages/AddAccount';
import { HealthPage } from './pages/Health';
import { AccountPage } from './pages/Account';
import { BulkProxyPage } from './pages/BulkProxy';
import { ProxiesPage } from './pages/Proxies';

type PageKey = 'accounts' | 'proxies' | 'health';

const PAGES: readonly { key: PageKey; label: string; href: string }[] = [
  { key: 'accounts', label: 'Accounts', href: href('/accounts') },
  { key: 'proxies', label: 'Proxies', href: href('/proxies') },
  { key: 'health', label: 'Health', href: href('/health') },
];

/** The navigation entry a screen belongs to, and its name in the tab's title. */
function placeOf(screen: Screen | null): { nav: PageKey | null; title: string } {
  if (!screen) return { nav: null, title: 'Not found' };
  if (screen.page === 'accounts') return { nav: 'accounts', title: 'Accounts' };
  if (screen.page === 'add-account') return { nav: 'accounts', title: 'Add account' };
  if (screen.page === 'bulk-proxy') return { nav: 'accounts', title: 'Change proxy' };
  if (screen.page === 'account') return { nav: 'accounts', title: screen.id };
  if (screen.page === 'proxies') return { nav: 'proxies', title: 'Proxies' };
  if (screen.page === 'health') return { nav: 'health', title: 'Health' };
  return { nav: null, title: 'Add a passkey' };
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
  const screen = screenOf(route.path);
  const page = screen?.page ?? null;
  const place = placeOf(screen);
  const links = info ? PAGES.map(item => ({ ...item, current: item.key === place.nav })) : [];
  useEffect(() => {
    setMenu(false);
    document.title = signedOut && page !== 'enroll' ? 'Sign in · gray-assistant' : `${place.title} · gray-assistant${info ? ` · ${info.relay_id}` : ''}`;
  }, [route.path, signedOut, info?.relay_id]);

  async function signOut() {
    try { await write('POST', 'session/end'); } catch { /* signed out either way */ }
    // Every read starts over (no data of the session stays on screen); the session read then says signed out.
    await client.resetQueries();
  }

  let content: ReactNode;
  if (screen?.page === 'enroll' && mode === 'public' && !auth.isLoading) content = <EnrollPage code={screen.code} />;
  else if (session.isLoading || (signedOut && auth.isLoading)) content = <Page><Skeleton lines={4} label="Loading gray-assistant’s page" /></Page>;
  else if (signedOut) content = <SignInPage mode={mode} expired={route.query.get('link') === 'expired'} />;
  else if (session.error || !info) content = <Unreachable error={session.error} onRetry={() => void session.refetch()} />;
  else if (screen?.page === 'accounts') content = <AccountsPage />;
  else if (screen?.page === 'add-account') content = <AddAccountPage query={route.query} />;
  else if (screen?.page === 'bulk-proxy') content = <BulkProxyPage query={route.query} />;
  // A new account, a new screen: nothing typed for one account stays for the next.
  else if (screen?.page === 'account') content = <AccountPage key={screen.id} id={screen.id} part={screen.part} />;
  else if (screen?.page === 'proxies') content = <ProxiesPage />;
  else if (screen?.page === 'health') content = <HealthPage relay={info} />;
  else content = <Page size="narrow"><Stack gap={6}>
    <PageHeader title="No page here" description="gray-assistant’s page has Accounts, Proxies and Health." />
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
          : <Badge icon={<ShieldCheck size={14} aria-hidden="true" />} title="Served by gray-assistant on your relay’s machine. What you type here never reaches Gray’s website.">gray-assistant page</Badge>}
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
      {info && page !== null && page !== 'enroll' && <PushStatus />}
      {content}
    </main>
  </>;
}

/**
 * Whether the account file has reached the VM. A write of this page starts the push by itself; this line follows it:
 * one quiet line while it runs and once it is sent, a notice with the command's own words and `Send again` when the VM
 * refused it or it did not get there. Nothing before the first push.
 */
function PushStatus() {
  const push = useLocal<PushView>('push', { live: data => data?.state === 'running' ? BUSY_MS : LIVE_MS });
  const now = useNow(30_000);
  const [sending, setSending] = useState(false);
  const words = pushWords(push.data, now);
  if (!words) return null;
  async function again() {
    setSending(true);
    try {
      await write('POST', 'push');
      await push.reload();
    } catch (error) {
      const refusal = error instanceof ApiError ? error : null;
      // A page started without the push (501): say what does it instead.
      toast.error('Couldn’t send the accounts.', { description: refusal?.code === 'not_available' ? 'This page can’t send them. Run gray-assistant accounts push on the relay’s machine.' : refusalText(refusal?.code ?? 'internal', refusal?.detail) });
    } finally {
      setSending(false);
    }
  }
  if (words.again) return <Page className="relay-ui-banner">
    <Notice tone="danger" role="alert" title={words.text} actions={<Button size="sm" loading={sending} onClick={() => void again()}>Send again</Button>}>
      {words.detail ?? 'gray-assistant gave no reason. gray-assistant accounts push on the relay’s machine prints it.'}
    </Notice>
  </Page>;
  return <Page className="relay-ui-banner relay-ui-banner--quiet">
    <span className="relay-ui-push" role="status">
      {push.data?.state === 'running' && <Spinner />}
      <Text as="span" size="meta" tone="muted">{words.text}</Text>
    </span>
  </Page>;
}

function Unreachable({ error, onRetry }: { error: ApiError | null; onRetry: () => void }) {
  return <Page size="narrow">
    <Stack gap={6}>
      <PageHeader title="gray-assistant doesn’t answer" />
      <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={onRetry}>Try again</Button>}>
        {refusalText(error?.code ?? 'unreachable')}
      </Notice>
      <CodeBlock language="bash" copyLabel="Copy command" description="Start it again on the relay’s machine:"
        code="gray-assistant ui" />
    </Stack>
  </Page>;
}
