// One account: its sign-in (a subscription), its key (a key account), its proxy, and removing it. Gray's panel links to
// each part (`/accounts/{id}/sign-in`, `/key`, `/proxy`); the screen opens scrolled to it. A key is typed here once and
// never shown again; the proxy is one of the relay's list (the Proxies screen holds addresses and passwords). When the
// accounts come from the relay's own software this screen changes nothing and still signs a subscription in.
import { useEffect, useRef, useState, type RefObject } from 'react';
import {
  Badge, Button, EmptyState, Field, Inline, LinkButton, Notice, Page, PageHeader, Panel, SegmentedControl, Skeleton, Stack, Text, TextInput, TextLink, toast, useConfirm,
} from '../../ui';
import { ApiError, write, type Account, type AccountsView, type PanelView, type PastedCredentialType, type ProxiesView } from '../api';
import { useChanged, useLocal, useNow } from '../data';
import { href, navigate } from '../router';
import type { AccountPart } from '../screens';
import {
  clockText, credentialLabel, keyFits, keyHint, kindPhrase, panelAccount, panelState, parkReason, proxyAddress, recognizeKey, refusalText, refusalWords, signsIn, VENDOR_LABEL,
} from '../words';
import { AccountSignIn } from './AccountSignIn';
import { editable, ProxyPicker, SourceNotice } from './parts';

const refusal = (error: unknown): string => refusalWords(error instanceof ApiError ? error : null);

export function AccountPage({ id, part }: { id: string; part: AccountPart | null }) {
  const accounts = useLocal<AccountsView>('accounts');
  const panel = useLocal<PanelView>('panel', { live: 30_000 });
  const now = useNow(30_000);
  const view = accounts.data;
  const source = view?.source;
  const canEdit = editable(source);
  // Gray's panel names an account by its panel id, which is the file's id unless the file's is no panel id.
  const account = view?.accounts.find(item => item.account_id === id) ?? view?.accounts.find(item => item.panel_id === id) ?? null;
  const proxies = useLocal<ProxiesView>('proxies', { enabled: canEdit });
  const headings: Record<AccountPart, RefObject<HTMLHeadingElement | null>> = { 'sign-in': useRef(null), key: useRef(null), proxy: useRef(null) };
  const found = account !== null;
  // A link to one part opens the screen at it, once the account is on screen.
  useEffect(() => {
    if (!part || !found) return;
    const heading = headings[part].current;
    if (!heading) return;
    // The part's panel, under the page's sticky bar (`relay-ui-part` keeps the bar's height free above it).
    (heading.closest('.relay-ui-part') ?? heading).scrollIntoView({ block: 'start' });
    heading.focus({ preventScroll: true });
  }, [part, found]);

  if (accounts.loading) return <Page size="narrow"><Skeleton lines={6} label="Loading the account" /></Page>;
  if (!account) return <Page size="narrow">
    <Stack gap={6}>
      <PageHeader back={{ href: href('/accounts'), label: 'Accounts' }} title={id} />
      {accounts.error
        ? <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void accounts.reload()}>Try again</Button>}>Couldn’t read the accounts: {refusalText(accounts.error.code)}</Notice>
        : <EmptyState title="No account with this ID here"
          description={source && source.kind !== 'file' ? 'Your software doesn’t list it. Add it there.' : 'accounts.json on your machine doesn’t name it.'}
          actions={<Inline gap={2}>
            {canEdit && <LinkButton variant="primary" href={href(`/accounts/new?id=${encodeURIComponent(id)}`)}>Add it</LinkButton>}
            <LinkButton href={href('/accounts')}>All accounts</LinkButton>
          </Inline>} />}
    </Stack>
  </Page>;

  const gray = panel.data ?? undefined;
  const state = panelState(gray, account, now);
  const group = panelAccount(gray, account)?.group ?? null;
  const subscription = signsIn(account.credential_type);
  return <Page size="narrow">
    <Stack gap={6}>
      <PageHeader back={{ href: href('/accounts'), label: 'Accounts' }} title={account.account_id}>
        <Inline gap={2}>
          <Badge>{VENDOR_LABEL[account.vendor]}</Badge>
          <Badge>{kindPhrase(account)}</Badge>
          {group !== null && <Badge title="Its group on Gray’s panel">{group}</Badge>}
          {state.known ? <Badge tone={state.tone} dot>{state.label}</Badge> : <Badge>{`State on Gray: ${state.label.toLowerCase()}`}</Badge>}
        </Inline>
      </PageHeader>
      {/* A badge that says Serving or Paused needs no sentence under it, and one that waits for its sign-in has the
          sign-in itself right below. */}
      {(!state.known || state.tone === 'warning' || state.tone === 'danger') && account.sealed.state !== 'parked' && !(subscription && /sign-in/i.test(state.label))
        && <Text size="support" tone="muted">{state.reason}</Text>}
      {account.panel_id && account.panel_id !== account.account_id && <Text size="support" tone="muted">On Gray’s panel it is {account.panel_id}.</Text>}
      {account.sealed.state === 'parked' && <Notice tone="warning" title="Left out of the VM">{parkReason(account.sealed.reason)}</Notice>}
      <SourceNotice source={source} signIn={subscription} />

      {subscription && <Panel title="Sign-in" headingRef={headings['sign-in']} className="relay-ui-part">
        <AccountSignIn account={account} />
      </Panel>}
      {!subscription && canEdit && <Panel title="Key" headingRef={headings.key} className="relay-ui-part">
        <KeyPart account={account} />
      </Panel>}
      {canEdit && <Panel title="Proxy" headingRef={headings.proxy} className="relay-ui-part">
        <ProxyPart account={account} proxies={proxies} />
      </Panel>}
      {canEdit && <Panel title="Remove" className="relay-ui-part">
        <RemovePart account={account} />
      </Panel>}
      {!subscription && account.credential_expires_at_ms !== null && <Text size="meta" tone="muted">Its key expires {clockText(account.credential_expires_at_ms, now)}.</Text>}
    </Stack>
  </Page>;
}

/** Replace the account's key. The field is write-only: it starts empty, is cleared once saved, and no answer holds a key. */
function KeyPart({ account }: { account: Account }) {
  const changed = useChanged();
  const types: readonly PastedCredentialType[] = account.vendor === 'anthropic' ? ['api_key', 'oauth_access_token'] : account.vendor === 'chatgpt_codex' ? ['oauth_access_token'] : ['api_key'];
  const [type, setType] = useState<PastedCredentialType>(account.credential_type === 'oauth_access_token' ? 'oauth_access_token' : account.credential_type === 'api_key' ? 'api_key' : types[0]!);
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ field: boolean; text: string } | null>(null);
  const seen = recognizeKey(value);
  const fits = keyFits(account.vendor, type, seen);
  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await write('PUT', `accounts/${encodeURIComponent(account.account_id)}/credential`, { credential: { type, value: value.trim() } });
      setValue('');
      await changed();
      toast.success(`Replaced ${account.account_id}’s key.`);
    } catch (failure) {
      setError({ field: failure instanceof ApiError && failure.field === 'credential', text: refusal(failure) });
    } finally {
      setBusy(false);
    }
  }
  return <form onSubmit={event => { event.preventDefault(); void submit(); }}>
    <Stack gap={4}>
      {error && !error.field && <Notice tone="danger" role="alert">{error.text}</Notice>}
      {types.length > 1 && <Field label="Kind of key"><div><SegmentedControl aria-label="Kind of key" value={type} onValueChange={next => setType(next)} options={types.map(item => ({ value: item, label: credentialLabel(account.vendor, item) }))} /></div></Field>}
      <Field label="New key" hint={seen ? `${seen.label}.${fits ? '' : ` This account needs: ${keyHint(account.vendor, type)}`}` : keyHint(account.vendor, type)} error={error?.field ? error.text : undefined}>
        <TextInput type="password" mono autoComplete="off" spellCheck={false} data-1p-ignore="" data-lpignore="true" value={value} onChange={event => setValue(event.target.value)} />
      </Field>
      <div><Button type="submit" variant="primary" loading={busy} disabled={value.trim() === ''}>Replace key</Button></div>
    </Stack>
  </form>;
}

/** Which proxy of the list the account leaves through, or none. Addresses and passwords are on the Proxies screen. */
function ProxyPart({ account, proxies }: { account: Account; proxies: ReturnType<typeof useLocal<ProxiesView>> }) {
  const changed = useChanged();
  const current = account.proxy_id ?? null;
  // A proxy written inside the account, not in the list: any choice made here replaces it.
  const own = account.proxy !== null && current === null;
  const [choice, setChoice] = useState<string | null>(current);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { setChoice(current); }, [current]);
  const list = proxies.data?.proxies ?? [];
  async function save() {
    setBusy(true);
    setError(null);
    try {
      await write('PUT', 'accounts/proxy', { account_ids: [account.account_id], proxy_id: choice });
      await changed();
      toast.success(choice === null ? `${account.account_id} uses no proxy.` : `${account.account_id} leaves through ${choice}.`);
    } catch (failure) {
      setError(refusal(failure));
    } finally {
      setBusy(false);
    }
  }
  if (proxies.loading) return <Skeleton lines={2} label="Loading the proxies" />;
  return <Stack gap={4}>
    {proxies.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void proxies.reload()}>Try again</Button>}>Couldn’t read the proxies: {refusalText(proxies.error.code)}</Notice>}
    {error && <Notice tone="danger" role="alert">{error}</Notice>}
    {own && <Text size="support" tone="muted">Its proxy now ({proxyAddress(account.proxy!)}) isn’t from the list. A choice here replaces it.</Text>}
    <Field label="Leaves through" hint={list.length === 0 ? 'The list has no proxy yet.' : undefined}>
      <ProxyPicker proxies={list} value={choice} onChange={setChoice} disabled={busy} />
    </Field>
    <Inline gap={3}>
      <Button variant="primary" loading={busy} disabled={choice === current && !own} onClick={() => void save()}>Save proxy</Button>
      <TextLink href={href('/proxies')}>Add a proxy</TextLink>
    </Inline>
  </Stack>;
}

function RemovePart({ account }: { account: Account }) {
  const changed = useChanged();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function remove() {
    if (!await confirm({
      title: `Remove ${account.account_id}?`,
      description: 'It stops serving, and its key or sign-in is deleted from your machine. Gray’s panel keeps its record until you delete it there.',
      confirmLabel: 'Remove account',
      tone: 'danger',
    })) return;
    setBusy(true);
    setError(null);
    try {
      await write('DELETE', `accounts/${encodeURIComponent(account.account_id)}`);
      await changed();
      toast.success(`Removed ${account.account_id}.`);
      navigate('/accounts', { replace: true });
    } catch (failure) {
      setError(refusal(failure));
      setBusy(false);
    }
  }
  return <Stack gap={4}>
    {error && <Notice tone="danger" role="alert">{error}</Notice>}
    <div><Button variant="danger" loading={busy} onClick={() => void remove()}>Remove account</Button></div>
  </Stack>;
}
