// Accounts: what the relay's source holds and where each account's key is, sealed for Gray's VM or on its way. The
// page answers, in order: is gray-assistant sealing at all; can this page change the source; which accounts need a hand;
// then every account with its credential, its sealed version, models and proxy. Keys are added, replaced and removed
// here; they are never shown again once saved.
import { useState } from 'react';
import { Trash } from '../../components/icons';
import {
  Badge, Button, Drawer, EmptyState, Field, Inline, LinkButton, Menu, MenuItem, MenuSeparator, Notice, Page, PageHeader, SegmentedControl, Skeleton, Stack, StackedTable, Step, Steps,
  TableBody, TableCell, TableHead, TableHeaderCell, TableRow, Text, TextInput, VisuallyHidden, toast, useConfirm,
} from '../../ui';
import { ApiError, write, type Account, type AccountsView, type PastedCredentialType, type RelayInfo } from '../api';
import { BUSY_MS, LIVE_MS, useLocal, useNow } from '../data';
import { href } from '../router';
import {
  clockText, credentialLabel, credentialPhrase, fieldError, keyFits, keyHint, modelsPhrase, parkReason, recognizeKey, refusalText, relativeTime, VENDOR_LABEL,
} from '../words';
import { AgentNotice } from './parts';

export function AccountsPage({ relay }: { relay: RelayInfo }) {
  const accounts = useLocal<AccountsView>('accounts', { live: data => data?.accounts.some(account => account.sealed.state === 'waiting') ? BUSY_MS : LIVE_MS });
  const confirm = useConfirm();
  const [replacing, setReplacing] = useState<{ account: Account; key: number } | null>(null), [replaceOpen, setReplaceOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const view = accounts.data;
  const source = view?.source;
  const canEdit = !!source && source.kind === 'file' && source.writable && source.problem === null;
  const list = view?.accounts ?? [];
  const pollSeconds = Math.round((view?.source_poll_ms ?? 30_000) / 1000);
  const leftOut = list.filter(account => account.sealed.state === 'parked');

  async function remove(account: Account) {
    if (!await confirm({
      title: `Remove ${account.account_id}?`,
      description: 'gray-assistant deletes its key from accounts.json and revokes it from Gray’s VM at its next poll. Gray’s panel keeps the account until you delete it there.',
      confirmLabel: 'Remove account',
      tone: 'danger',
    })) return;
    setBusy(account.account_id);
    try {
      accounts.set(await write<AccountsView>('DELETE', `accounts/${encodeURIComponent(account.account_id)}`));
      toast.success(`Removed ${account.account_id}.`, { description: 'gray-assistant revokes it from the VM at its next poll.' });
    } catch (error) {
      toast.error(`Couldn’t remove ${account.account_id}.`, { description: refusalText(error instanceof ApiError ? error.code : 'internal') });
    } finally {
      setBusy(null);
    }
  }

  return <Page>
    <Stack gap={6}>
      <PageHeader title="Accounts" description="The vendor accounts gray-assistant seals for Gray’s VM. Keys stay on the relay’s machine: gray-assistant seals each one for the VM itself."
        actions={source?.kind === 'file' && (canEdit
          ? <LinkButton variant="primary" href={href('/accounts/new')}>Add account</LinkButton>
          : <Button variant="primary" disabled title={source.problem ? 'Fix accounts.json first.' : 'accounts.json is read-only here.'}>Add account</Button>)} />
      <AgentNotice relay={view?.relay ?? relay} />
      {accounts.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void accounts.reload()}>Try again</Button>}>Couldn’t read the accounts: {refusalText(accounts.error.code)}</Notice>}
      {source && source.kind !== 'file' && <Notice title={`Accounts come from ${source.kind === 'cliproxyapi' ? 'CLIProxyAPI' : 'your relay software'}`}>
        Add, change and remove accounts there{source.url ? ` (${source.url})` : ''}: gray-assistant reads them every {pollSeconds} seconds and seals each one itself. This page changes accounts only for the file source, accounts.json.
      </Notice>}
      {source?.problem && <Notice tone="danger" role="alert" title="accounts.json can’t be read">
        gray-assistant refuses it as it is ({source.problem.detail}), so nothing in it is sealed and this page can’t change it. Fix that entry in {source.path}, then reload this page.
      </Notice>}
      {source?.kind === 'file' && !source.writable && !source.problem && <Notice tone="warning" title="accounts.json is read-only here">
        gray-assistant can read {source.path} but not replace it: its folder is mounted read-only. Mount the folder writable for the process that serves this page (the guide’s “Local page” section shows how), or edit the file by hand.
      </Notice>}
      {leftOut.length > 0 && <Notice tone="warning" title={leftOut.length === 1 ? `gray-assistant leaves ${leftOut[0]!.account_id} out` : `gray-assistant leaves ${leftOut.length} accounts out`}>
        {leftOut.length === 1 ? parkReason(leftOut[0]!.sealed.reason) : 'Each row below says why.'}
      </Notice>}

      {accounts.loading && <Skeleton rows={3} label="Loading the accounts" />}
      {view && source?.kind === 'file' && !source.problem && list.length === 0 && <EmptyState title="No accounts yet"
        description="Add a vendor account with its key. gray-assistant writes it to accounts.json on the relay’s machine and seals it for Gray’s VM."
        actions={canEdit && <LinkButton variant="primary" href={href('/accounts/new')}>Add account</LinkButton>} />}
      {list.length > 0 && <StackedTable label="Accounts" className="relay-ui-accounts">
        <TableHead><TableRow>
          <TableHeaderCell>Account</TableHeaderCell>
          <TableHeaderCell>Credential</TableHeaderCell>
          <TableHeaderCell title="Whether gray-assistant has sealed the account’s current key for Gray’s VM, with the version of the message that carried it.">Sealed</TableHeaderCell>
          <TableHeaderCell>Models</TableHeaderCell>
          <TableHeaderCell>Proxy</TableHeaderCell>
          {canEdit && <TableHeaderCell kind="menu"><VisuallyHidden>Actions</VisuallyHidden></TableHeaderCell>}
        </TableRow></TableHead>
        <TableBody>{list.map(account => {
          return <TableRow key={account.account_id} inactive={account.status !== 'active' && account.status !== 'limited'}>
            <TableCell data-label="Account"><Stack gap={0}>
              <Text as="span" weight="medium" truncate className="relay-ui-name">{account.account_id}</Text>
              {account.panel_id && account.panel_id !== account.account_id && <Text as="span" size="meta" tone="muted" truncate className="relay-ui-name">Gray panel id: {account.panel_id}</Text>}
              <Text as="span" size="meta" tone="muted">{VENDOR_LABEL[account.vendor]}{account.status === 'active' ? '' : ` · ${account.status}`}</Text>
            </Stack></TableCell>
            <TableCell data-label="Credential"><Stack gap={1}>
              <span>{credentialPhrase(account)}</span>
              {account.credential_expires_at_ms !== null && <Text as="span" size="meta" tone="muted">Expires {clockText(account.credential_expires_at_ms, Date.now())}</Text>}
            </Stack></TableCell>
            <TableCell data-label="Sealed" wide><SealedCell account={account} pollSeconds={pollSeconds} /></TableCell>
            <TableCell data-label="Models"><Text as="span" size="support" truncate className="relay-ui-models" title={account.models === '*' ? undefined : account.models.join(', ')}>{modelsPhrase(account.models)}</Text></TableCell>
            <TableCell data-label="Proxy">{account.proxy
              ? <Text as="span" size="support" truncate className="relay-ui-proxy">{account.proxy.type} · {account.proxy.host}:{account.proxy.port}</Text>
              : <Text as="span" size="support" tone="muted">None</Text>}</TableCell>
            {canEdit && <TableCell kind="menu"><Menu label={`Actions for ${account.account_id}`}>
              {/* A sign_in or password account signs in inside the VM (gray-assistant login <account>): no key to replace. */}
              {pasted(account.credential_type) && <><MenuItem disabled={busy !== null} onSelect={() => { setReplacing({ account, key: Date.now() }); setReplaceOpen(true); }}>Replace key</MenuItem>
              <MenuSeparator /></>}
              <MenuItem tone="danger" disabled={busy !== null} icon={<Trash size={15} aria-hidden="true" />} onSelect={() => void remove(account)}>Remove account</MenuItem>
            </Menu></TableCell>}
          </TableRow>;
        })}</TableBody>
      </StackedTable>}
      {view && source?.kind === 'file' && source.path && <Text size="meta" tone="muted">Source: {source.path}{view.agent_last_poll_at_ms ? ` · gray-assistant last read it ${relativeTime(view.agent_last_poll_at_ms, Date.now())}` : ''}</Text>}
    </Stack>
    {replacing && <ReplaceKey key={replacing.key} account={replacing.account} open={replaceOpen} onOpenChange={setReplaceOpen} onSaved={next => accounts.set(next)} pollSeconds={pollSeconds} />}
  </Page>;
}

/** A credential this page pastes, so a key it can replace. */
function pasted(type: Account['credential_type']): type is PastedCredentialType {
  return type === 'api_key' || type === 'oauth_access_token';
}

/** Where the account's key is: sealed (with its version and when), on its way, left out (and why), or unknown. */
function SealedCell({ account, pollSeconds }: { account: Account; pollSeconds: number }) {
  const now = useNow(15_000);
  const sealed = account.sealed;
  if (sealed.state === 'sealed' || sealed.state === 'partly') return <Stack gap={1}>
    <Inline gap={2}>
      <Badge tone={sealed.state === 'sealed' ? 'success' : 'info'} dot>{sealed.state === 'sealed' ? 'Sealed' : 'On some lanes'}</Badge>
      {sealed.at_ms !== null && <Text as="span" size="meta" tone="muted" title={clockText(sealed.at_ms, now)}>{relativeTime(sealed.at_ms, now)}</Text>}
    </Inline>
    {/* A version that is a time (gray-assistant numbers by the clock) says no more than the time above it. */}
    {sealed.version !== null && !/^\d{13,}$/.test(sealed.version) && <Text as="span" size="meta" tone="muted" numeric>Version {sealed.version}</Text>}
  </Stack>;
  if (sealed.state === 'waiting') return <Stack gap={1}>
    <span><Badge tone="info" dot>Waiting to seal</Badge></span>
    <Text as="span" size="meta" tone="muted">{`Within ${pollSeconds} seconds.`}</Text>
  </Stack>;
  if (sealed.state === 'parked') return <Stack gap={1}>
    <span><Badge tone="warning" dot>Left out</Badge></span>
    <Text as="span" size="meta" tone="muted">{parkReason(sealed.reason)}</Text>
  </Stack>;
  // gray-assistant isn't running: the page's notice says so once, not every row.
  return <span><Badge dot>Not sealed now</Badge></span>;
}

/** Replace one account's key in a side sheet; the key field starts empty and the old key is never shown. */
function ReplaceKey({ account, open, onOpenChange, onSaved, pollSeconds }: { account: Account; open: boolean; onOpenChange(open: boolean): void; onSaved(view: AccountsView): void; pollSeconds: number }) {
  const types = account.vendor === 'anthropic' ? (['api_key', 'oauth_access_token'] as const) : account.vendor === 'chatgpt_codex' ? (['oauth_access_token'] as const) : (['api_key'] as const);
  const [type, setType] = useState<PastedCredentialType>(pasted(account.credential_type) ? account.credential_type : types[0]);
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ field: string | null; text: string } | null>(null);
  const seen = recognizeKey(value);
  const fits = keyFits(account.vendor, type, seen);
  async function submit() {
    setBusy(true);
    setError(null);
    try {
      onSaved(await write<AccountsView>('PUT', `accounts/${encodeURIComponent(account.account_id)}/credential`, { credential: { type, value } }));
      setValue('');
      onOpenChange(false);
      toast.success(`Replaced ${account.account_id}’s key.`, { description: `gray-assistant seals it at its next read, within ${pollSeconds} seconds.` });
    } catch (failure) {
      const refusal = failure instanceof ApiError ? failure : null;
      setError(refusal?.field ? { field: refusal.field, text: fieldError(refusal.field, refusal.code) } : { field: null, text: refusalText(refusal?.code ?? 'internal', refusal?.detail) });
    } finally {
      setBusy(false);
    }
  }
  return <Drawer side="end" open={open} onOpenChange={onOpenChange} title={`Replace ${account.account_id}’s key`}
    description={`${VENDOR_LABEL[account.vendor]} account. The new key replaces the old one in accounts.json on the relay’s machine.`}
    onSubmit={() => void submit()}
    footer={<Inline gap={2}>
      <Button type="submit" variant="primary" loading={busy} disabled={!value.trim()}>Replace key</Button>
      <Button disabled={busy} onClick={() => onOpenChange(false)}>Cancel</Button>
    </Inline>}>
    <Stack gap={5}>
      {error && error.field === null && <Notice tone="danger" role="alert">{error.text}</Notice>}
      {types.length > 1 && <Field label="Kind of key"><div><SegmentedControl aria-label="Kind of key" value={type} onValueChange={next => setType(next)} options={types.map(item => ({ value: item, label: credentialLabel(account.vendor, item) }))} /></div></Field>}
      <Field label="New key" hint={seen ? `${seen.label}.${fits ? '' : ` This account needs: ${keyHint(account.vendor, type)}`}` : keyHint(account.vendor, type)} error={error?.field === 'credential' ? error.text : undefined}>
        <TextInput type="password" mono required autoComplete="off" spellCheck={false} data-1p-ignore="" data-lpignore="true" value={value} onChange={event => setValue(event.target.value)} />
      </Field>
      <Steps aria-label="What happens next">
        <Step title="gray-assistant writes the key to accounts.json"><Text size="support" tone="muted">On the relay’s machine, readable by gray-assistant’s user only.</Text></Step>
        <Step title="It seals the key for Gray’s VM"><Text size="support" tone="muted">At its next read of the file, within {pollSeconds} seconds, with a new version.</Text></Step>
        <Step title="The VM uses the new key"><Text size="support" tone="muted">The old key stops being used once the VM has the new one.</Text></Step>
      </Steps>
    </Stack>
  </Drawer>;
}

