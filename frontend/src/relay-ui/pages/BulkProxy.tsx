// One proxy for several accounts (`/accounts/proxy?ids=a,b`): the accounts named, one picker, save. Gray's panel's bulk
// bar and this page's own accounts list both link here.
import { useState } from 'react';
import { Button, EmptyState, Field, Inline, LinkButton, List, Notice, Page, PageHeader, Panel, Skeleton, Stack, Text, TextLink, toast } from '../../ui';
import { ApiError, write, type AccountsView, type ProxiesView } from '../api';
import { useChanged, useLocal } from '../data';
import { href, navigate } from '../router';
import { idsOf, kindPhrase, proxyAddress, refusalText, refusalWords, VENDOR_LABEL } from '../words';
import { editable, ProxyPicker, SourceNotice } from './parts';

export function BulkProxyPage({ query }: { query: URLSearchParams }) {
  const accounts = useLocal<AccountsView>('accounts');
  const source = accounts.data?.source;
  const canEdit = editable(source);
  const proxies = useLocal<ProxiesView>('proxies', { enabled: canEdit });
  const changed = useChanged();
  const [choice, setChoice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const asked = idsOf(query.get('ids'));
  const all = accounts.data?.accounts ?? [];
  // Gray's panel names accounts by their panel ids; the file's own ids are what the change is sent with.
  const named = asked.map(id => ({ id, account: all.find(item => item.account_id === id) ?? all.find(item => item.panel_id === id) ?? null }));
  const found = named.flatMap(item => item.account ? [item.account] : []);
  const missing = named.filter(item => !item.account).map(item => item.id);
  const list = proxies.data?.proxies ?? [];

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await write('PUT', 'accounts/proxy', { account_ids: found.map(account => account.account_id), proxy_id: choice });
      await changed();
      toast.success(`${found.length === 1 ? found[0]!.account_id : `${found.length} accounts`} ${choice === null ? 'use no proxy' : `leave through ${choice}`}.`);
      navigate('/accounts', { replace: true });
    } catch (failure) {
      setError(refusalWords(failure instanceof ApiError ? failure : null));
      setBusy(false);
    }
  }

  return <Page size="narrow">
    <Stack gap={6}>
      <PageHeader back={{ href: href('/accounts'), label: 'Accounts' }} title="Change proxy" />
      {accounts.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void accounts.reload()}>Try again</Button>}>Couldn’t read the accounts: {refusalText(accounts.error.code)}</Notice>}
      <SourceNotice source={source} signIn={false} />
      {error && <Notice tone="danger" role="alert">{error}</Notice>}
      {(accounts.loading || proxies.loading) && <Skeleton lines={5} label="Loading the accounts" />}
      {accounts.data && asked.length === 0 && <EmptyState title="No account chosen" description="Select accounts in the list, then Change proxy." actions={<LinkButton variant="primary" href={href('/accounts')}>Go to Accounts</LinkButton>} />}
      {accounts.data && missing.length > 0 && <Notice tone="warning" title={missing.length === 1 ? `No account ${missing[0]} here` : `${missing.length} of these accounts are not here`}>
        {missing.length === 1 ? 'It is left out of the change.' : `${missing.join(', ')}: left out of the change.`}
      </Notice>}
      {canEdit && !proxies.loading && found.length > 0 && <Panel>
        <Stack gap={5}>
          <Stack gap={2}>
            <Text weight="medium">{found.length === 1 ? '1 account' : `${found.length} accounts`}</Text>
            <List aria-label="Accounts to change">{found.map(account => <li key={account.account_id} className="relay-ui-pair">
              <Text as="span" weight="medium" truncate className="relay-ui-name">{account.account_id}</Text>
              <Text as="span" size="meta" tone="muted">{VENDOR_LABEL[account.vendor]} · {kindPhrase(account)} · {account.proxy ? `now ${account.proxy_id ?? proxyAddress(account.proxy)}` : 'no proxy now'}</Text>
            </li>)}</List>
          </Stack>
          {proxies.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void proxies.reload()}>Try again</Button>}>Couldn’t read the proxies: {refusalText(proxies.error.code)}</Notice>}
          <Field label="Leave through" hint={list.length === 0 ? 'The list has no proxy yet: add one first, or choose No proxy.' : undefined}>
            <ProxyPicker proxies={list} value={choice} onChange={setChoice} disabled={busy} />
          </Field>
          <Inline gap={3}>
            <Button variant="primary" loading={busy} onClick={() => void save()}>{choice === null ? 'Use no proxy' : 'Save proxy'}</Button>
            <LinkButton href={href('/accounts')}>Cancel</LinkButton>
            <TextLink href={href('/proxies')}>Add a proxy</TextLink>
          </Inline>
        </Stack>
      </Panel>}
    </Stack>
  </Page>;
}
