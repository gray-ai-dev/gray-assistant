// Accounts: every account of the relay's source as an operator recognises it from Gray's panel: its id, what kind it is
// (a subscription signed in inside the VM, or a key), the proxy it leaves through, and its group and state on Gray
// (`GET panel`; while Gray does not answer the state says so and the page works the same). A row opens the account;
// several selected rows take one proxy. Keys are never shown: this list holds none.
import { useMemo, useState } from 'react';
import {
  Badge, Button, Checkbox, EmptyState, Facts, Grow, Inline, LinkButton, Notice, Page, PageHeader, SelectField, Skeleton, Stack, StackedTable, TableBody, TableCell, TableHead, TableHeaderCell, TableRow,
  Text, VisuallyHidden,
} from '../../ui';
import type { Account, AccountsView, PanelView } from '../api';
import { BUSY_MS, LIVE_MS, useLocal, useNow } from '../data';
import { href } from '../router';
import { accountPath, bulkProxyPath } from '../screens';
import { kindPhrase, panelAccount, panelState, parkReason, proxyAddress, refusalText, VENDOR_LABEL } from '../words';
import { editable, SourceNotice, StateCell } from './parts';

/** How often the panel view is asked again: gray-assistant keeps Gray's answer for 30 seconds. */
const PANEL_MS = 30_000;
const ALL = '(all)', UNGROUPED = '(none)';

export function AccountsPage() {
  const accounts = useLocal<AccountsView>('accounts', { live: data => data?.accounts.some(account => account.sealed.state === 'waiting') ? BUSY_MS : LIVE_MS });
  const panel = useLocal<PanelView>('panel', { live: PANEL_MS });
  const now = useNow(30_000);
  const [group, setGroup] = useState(ALL);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const view = accounts.data;
  const source = view?.source;
  const canEdit = editable(source);
  const list = view?.accounts ?? [];
  // `undefined` while the panel view is not read yet or Gray does not answer: the state column then says so.
  const gray = panel.data ?? undefined;
  const groupOf = (account: Account) => panelAccount(gray, account)?.group ?? null;
  const groups = useMemo(() => [...new Set(list.map(groupOf).filter((name): name is string => name !== null))].sort((a, b) => a.localeCompare(b)), [list, gray]);
  // A group that no account names any more (it was renamed on Gray) falls back to every account.
  const active = group === ALL || group === UNGROUPED || groups.includes(group.slice(2)) ? group : ALL;
  const shown = list.filter(account => active === ALL || (active === UNGROUPED ? groupOf(account) === null : groupOf(account) === active.slice(2)));
  const picked = shown.filter(account => selected.has(account.account_id));
  const allShown = shown.length > 0 && picked.length === shown.length;

  function toggle(id: string, on: boolean) {
    const next = new Set(selected);
    if (on) next.add(id); else next.delete(id);
    setSelected(next);
  }

  return <Page>
    <Stack gap={6}>
      <PageHeader title="Accounts"
        actions={source?.kind === 'file' && (canEdit
          ? <LinkButton variant="primary" href={href('/accounts/new')}>Add account</LinkButton>
          : <Button variant="primary" disabled title={source.problem ? 'Fix accounts.json first.' : 'accounts.json is read-only here.'}>Add account</Button>)} />
      {accounts.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void accounts.reload()}>Try again</Button>}>Couldn’t read the accounts: {refusalText(accounts.error.code)}</Notice>}
      <SourceNotice source={source} />
      {accounts.loading && <Skeleton rows={4} label="Loading the accounts" />}
      {view && source?.kind === 'file' && !source.problem && list.length === 0 && <EmptyState title="No accounts yet"
        description="Add an account and sign it in, or paste API keys."
        actions={canEdit && <LinkButton variant="primary" href={href('/accounts/new')}>Add account</LinkButton>} />}
      {view && source && source.kind !== 'file' && list.length === 0 && <EmptyState title="Your software lists no account" />}

      {list.length > 0 && <Stack gap={3}>
        {(groups.length > 0 || picked.length > 0) && <Inline gap={3}>
          {groups.length > 0 && <SelectField aria-label="Group" className="relay-ui-group" value={active} onValueChange={setGroup}>
            <option value={ALL}>All groups</option>
            {groups.map(name => <option key={name} value={`g:${name}`}>{name}</option>)}
            <option value={UNGROUPED}>Ungrouped</option>
          </SelectField>}
          <Grow />
          {picked.length > 0 && <Inline gap={2} role="status">
            <Text as="span" size="support" tone="muted">{picked.length} selected</Text>
            <LinkButton variant="primary" href={href(bulkProxyPath(picked.map(account => account.account_id)))}>Change proxy</LinkButton>
            <Button variant="ghost" onClick={() => setSelected(new Set())}>Clear</Button>
          </Inline>}
        </Inline>}
        {shown.length === 0
          ? <EmptyState size="compact" title="No account in this group" actions={<Button onClick={() => setGroup(ALL)}>Show all groups</Button>} />
          : <StackedTable label="Accounts" className="relay-ui-accounts">
            <TableHead><TableRow>
              {canEdit && <TableHeaderCell className="relay-ui-select"><Checkbox label={<VisuallyHidden>Select all shown accounts</VisuallyHidden>} checked={allShown} indeterminate={!allShown && picked.length > 0}
                onCheckedChange={on => setSelected(on ? new Set(shown.map(account => account.account_id)) : new Set())} /></TableHeaderCell>}
              <TableHeaderCell>Account</TableHeaderCell>
              <TableHeaderCell>Proxy</TableHeaderCell>
              <TableHeaderCell title="The account’s group on Gray’s panel. Groups are set there.">Group</TableHeaderCell>
              <TableHeaderCell title="What Gray’s panel says of the account, from the VM’s own report.">State on Gray</TableHeaderCell>
            </TableRow></TableHead>
            <TableBody>{shown.map(account => {
              const to = href(accountPath(account.account_id));
              const accountGroup = groupOf(account);
              return <TableRow key={account.account_id} href={to} inactive={account.status !== 'active' && account.status !== 'limited'}>
                {canEdit && <TableCell className="relay-ui-select"><Checkbox label={<VisuallyHidden>Select {account.account_id}</VisuallyHidden>} checked={selected.has(account.account_id)}
                  onCheckedChange={on => toggle(account.account_id, on)} /></TableCell>}
                {/* One line under the name says what the account is; a row is two lines unless it needs a look. */}
                <TableCell data-label="Account"><Stack gap={0}>
                  <Text as="span" weight="medium" truncate className="relay-ui-name"><a href={to}>{account.account_id}</a></Text>
                  <Facts size="meta">{VENDOR_LABEL[account.vendor]}{kindPhrase(account)}{account.status === 'active' ? null : account.status}</Facts>
                  {account.panel_id && account.panel_id !== account.account_id && <Text as="span" size="meta" tone="muted" truncate className="relay-ui-name">On Gray: {account.panel_id}</Text>}
                </Stack></TableCell>
                {/* The list's name for it (its address is the tooltip and the Proxies screen's); one written in the account has no name. */}
                <TableCell data-label="Proxy">{account.proxy
                  ? account.proxy_id
                    ? <Text as="span" truncate className="relay-ui-proxy" title={proxyAddress(account.proxy)}>{account.proxy_id}</Text>
                    : <Text as="span" size="meta" mono truncate className="relay-ui-proxy">{proxyAddress(account.proxy)}</Text>
                  : <Text as="span" size="meta" tone="muted">None</Text>}</TableCell>
                <TableCell data-label="Group">{accountGroup !== null
                  ? <Badge>{accountGroup}</Badge>
                  : <Text as="span" size="meta" tone="muted">{gray ? 'Ungrouped' : 'Not available'}</Text>}</TableCell>
                <TableCell data-label="State on Gray" wide>
                  <StateCell state={panelState(gray, account, now)} leftOut={account.sealed.state === 'parked' ? parkReason(account.sealed.reason) : null} />
                </TableCell>
              </TableRow>;
            })}</TableBody>
          </StackedTable>}
      </Stack>}
    </Stack>
  </Page>;
}
