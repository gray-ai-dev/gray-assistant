// Proxies: the relay's list of proxies, which accounts name by id. Each row is an address (scheme, host, port, user
// name), whether a password is saved (never the password) and how many accounts leave through it. Add one in fields
// or paste several, one a line; remove one no account uses; move a proxy's accounts to another in one step.
import { useState } from 'react';
import { Trash } from '../../components/icons';
import {
  Button, Drawer, EmptyState, Field, FormGrid, Inline, Menu, MenuItem, MenuSeparator, Notice, Page, PageHeader, Panel, SegmentedControl, SelectField, Skeleton, Stack, StackedTable, TableBody, TableCell,
  TableHead, TableHeaderCell, TableRow, Text, TextArea, TextInput, VisuallyHidden, toast, useConfirm,
} from '../../ui';
import { ApiError, write, type AccountsView, type ProxiesView, type Proxy } from '../api';
import { useChanged, useLocal } from '../data';
import { linesOf, proxyUrl, refusalText, refusalWords } from '../words';
import { editable, ProxyPicker, SourceNotice } from './parts';

const SCHEMES = ['socks5', 'socks5h', 'http', 'https'] as const;
const EMPTY = { type: 'socks5', host: '', port: '', username: '', password: '' };

const refusal = (error: unknown): string => refusalWords(error instanceof ApiError ? error : null);

const uses = (count: number) => count === 0 ? 'No account' : count === 1 ? '1 account' : `${count} accounts`;

export function ProxiesPage() {
  const accounts = useLocal<AccountsView>('accounts');
  const source = accounts.data?.source;
  const file = source?.kind === 'file';
  const canEdit = editable(source);
  const proxies = useLocal<ProxiesView>('proxies', { enabled: file });
  const changed = useChanged();
  const confirm = useConfirm();
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [moving, setMoving] = useState<Proxy | null>(null), [moveOpen, setMoveOpen] = useState(false);
  const list = proxies.data?.proxies ?? [];
  const note = (id: string, text: string | null) => setNotes(current => {
    const { [id]: _, ...rest } = current;
    return text === null ? rest : { ...rest, [id]: text };
  });

  async function remove(proxy: Proxy) {
    // gray-assistant refuses to remove a proxy an account names; say so beside the row without asking it.
    if (proxy.used_by.length > 0) {
      note(proxy.id, `${uses(proxy.used_by.length)} ${proxy.used_by.length === 1 ? 'leaves' : 'leave'} through it. Move ${proxy.used_by.length === 1 ? 'it' : 'them'} to another proxy first.`);
      return;
    }
    if (!await confirm({ title: `Remove ${proxy.id}?`, description: 'gray-assistant deletes its address and password from the relay’s machine. No account uses it.', confirmLabel: 'Remove proxy', tone: 'danger' })) return;
    setBusy(proxy.id);
    note(proxy.id, null);
    try {
      await write('DELETE', `proxies/${encodeURIComponent(proxy.id)}`);
      await changed();
      toast.success(`Removed ${proxy.id}.`);
    } catch (failure) {
      note(proxy.id, refusal(failure));
      await proxies.reload();
    } finally {
      setBusy(null);
    }
  }

  return <Page>
    <Stack gap={6}>
      <PageHeader title="Proxies" />
      {accounts.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void accounts.reload()}>Try again</Button>}>Couldn’t read the accounts: {refusalText(accounts.error.code)}</Notice>}
      {proxies.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void proxies.reload()}>Try again</Button>}>Couldn’t read the proxies: {refusalText(proxies.error.code)}</Notice>}
      <SourceNotice source={source} signIn={false} />
      {(accounts.loading || proxies.loading) && <Skeleton rows={3} label="Loading the proxies" />}
      {file && proxies.data && list.length === 0 && <EmptyState title="No proxy yet"
        description="Add one below, then choose it for an account." />}
      {list.length > 0 && <StackedTable label="Proxies" className="relay-ui-proxies">
        <TableHead><TableRow>
          <TableHeaderCell>Proxy</TableHeaderCell>
          <TableHeaderCell>Scheme</TableHeaderCell>
          <TableHeaderCell>Host</TableHeaderCell>
          <TableHeaderCell kind="numeric">Port</TableHeaderCell>
          <TableHeaderCell>User name</TableHeaderCell>
          <TableHeaderCell>Password</TableHeaderCell>
          <TableHeaderCell>Used by</TableHeaderCell>
          {canEdit && <TableHeaderCell kind="menu"><VisuallyHidden>Actions</VisuallyHidden></TableHeaderCell>}
        </TableRow></TableHead>
        <TableBody>{list.map(proxy => <TableRow key={proxy.id}>
          <TableCell data-label="Proxy" wide><Stack gap={1}>
            <Text as="span" weight="medium" truncate className="relay-ui-name">{proxy.id}</Text>
            {notes[proxy.id] && <Text as="span" size="meta" tone="danger" role="alert">{notes[proxy.id]}</Text>}
          </Stack></TableCell>
          <TableCell data-label="Scheme">{proxy.type}</TableCell>
          <TableCell data-label="Host"><Text as="span" mono truncate className="relay-ui-proxy">{proxy.host}</Text></TableCell>
          <TableCell data-label="Port" kind="numeric"><Text as="span" mono>{proxy.port}</Text></TableCell>
          <TableCell data-label="User name">{proxy.username
            ? <Text as="span" mono truncate className="relay-ui-proxy">{proxy.username}</Text>
            : <Text as="span" size="support" tone="muted">None</Text>}</TableCell>
          <TableCell data-label="Password">{proxy.has_password ? 'Password saved' : <Text as="span" size="support" tone="muted">No password</Text>}</TableCell>
          <TableCell data-label="Used by" title={proxy.used_by.length > 0 ? proxy.used_by.join(', ') : undefined}>{proxy.used_by.length === 0
            ? <Text as="span" size="support" tone="muted">{uses(0)}</Text>
            : uses(proxy.used_by.length)}</TableCell>
          {canEdit && <TableCell kind="menu"><Menu label={`Actions for ${proxy.id}`}>
            <MenuItem disabled={busy !== null || proxy.used_by.length === 0} onSelect={() => { note(proxy.id, null); setMoving(proxy); setMoveOpen(true); }}>Move its accounts to…</MenuItem>
            <MenuSeparator />
            <MenuItem tone="danger" disabled={busy !== null} icon={<Trash size={15} aria-hidden="true" />} onSelect={() => void remove(proxy)}>Remove proxy</MenuItem>
          </Menu></TableCell>}
        </TableRow>)}</TableBody>
      </StackedTable>}
      {canEdit && proxies.data && <AddProxies />}
    </Stack>
    {moving && <MoveAccounts key={moving.id} proxy={moving} proxies={list} open={moveOpen} onOpenChange={setMoveOpen} />}
  </Page>;
}

/** Add one proxy in fields (its password masked), or paste several addresses, one a line. Nothing typed stays after saving. */
function AddProxies() {
  const changed = useChanged();
  const [mode, setMode] = useState<'one' | 'several'>('one');
  const [one, setOne] = useState(EMPTY);
  const [several, setSeveral] = useState('');
  const [busy, setBusy] = useState(false);
  // A refused address is said beside the field it is in; anything else above the form.
  const [error, setError] = useState<{ field: boolean; text: string } | null>(null);
  const set = (patch: Partial<typeof EMPTY>) => setOne(current => ({ ...current, ...patch }));
  const lines = linesOf(several);
  const port = Number(one.port);
  const portOk = /^\d{1,5}$/.test(one.port.trim()) && port >= 1 && port <= 65_535;
  const ready = mode === 'one' ? one.host.trim() !== '' && portOk && (one.password === '' || one.username.trim() !== '') : lines.length > 0;

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      // The ids of the addresses sent, in their order; one the list had already answers the id it has.
      const ids = [...new Set((await write<{ ids: string[] }>('POST', 'proxies', { urls: mode === 'one' ? [proxyUrl(one)] : lines })).ids)];
      setOne(EMPTY);
      setSeveral('');
      await changed();
      toast.success(ids.length === 1 ? `Added ${ids[0]}.` : `Added ${ids.length} proxies.`, ids.length > 1 ? { description: ids.join(', ') } : undefined);
    } catch (failure) {
      setError({ field: failure instanceof ApiError && failure.field === 'proxy', text: refusal(failure) });
    } finally {
      setBusy(false);
    }
  }

  return <Panel title="Add proxies">
    <form onSubmit={event => { event.preventDefault(); void submit(); }}>
      <Stack gap={4}>
        {error && !(error.field && mode === 'several') && <Notice tone="danger" role="alert">{error.text}</Notice>}
        <div><SegmentedControl aria-label="How many" value={mode} onValueChange={next => { setMode(next); setError(null); }} options={[{ value: 'one', label: 'One' }, { value: 'several', label: 'Paste several' }]} /></div>
        {/* As the address reads, scheme://host:port, then who signs in to it. */}
        {mode === 'one' ? <Stack gap={4}><FormGrid columns={3}>
          <Field label="Scheme">
            <SelectField value={one.type} onValueChange={type => set({ type })} disabled={busy}>
              {SCHEMES.map(scheme => <option key={scheme} value={scheme}>{scheme}</option>)}
            </SelectField>
          </Field>
          <Field label="Host">
            <TextInput mono autoComplete="off" spellCheck={false} placeholder="203.0.113.9" value={one.host} disabled={busy} onChange={event => set({ host: event.target.value })} />
          </Field>
          <Field label="Port" error={one.port.trim() !== '' && !portOk ? 'A port is a number from 1 to 65535.' : undefined}>
            <TextInput mono inputMode="numeric" autoComplete="off" placeholder="1080" value={one.port} disabled={busy} onChange={event => set({ port: event.target.value })} />
          </Field>
        </FormGrid><FormGrid columns={2}>
          <Field label="User name" optional>
            <TextInput mono autoComplete="off" spellCheck={false} data-1p-ignore="" data-lpignore="true" value={one.username} disabled={busy} onChange={event => set({ username: event.target.value })} />
          </Field>
          <Field label="Password" optional hint="Never shown again." error={one.password !== '' && one.username.trim() === '' ? 'A password needs a user name.' : undefined}>
            <TextInput type="password" mono autoComplete="off" spellCheck={false} data-1p-ignore="" data-lpignore="true" value={one.password} disabled={busy} onChange={event => set({ password: event.target.value })} />
          </Field>
        </FormGrid></Stack> : <Field label="Addresses" hint="One a line: scheme://user:password@host:port" error={error?.field ? error.text : undefined}>
          <TextArea mono rows={5} wrap="off" autoComplete="off" spellCheck={false} placeholder={'socks5://user:password@203.0.113.9:1080\nhttp://203.0.113.10:3128'} value={several} disabled={busy} onChange={event => setSeveral(event.target.value)} />
        </Field>}
        <Inline gap={2}>
          <Button type="submit" variant="primary" loading={busy} disabled={!ready}>{mode === 'one' || lines.length < 2 ? 'Add proxy' : `Add ${lines.length} proxies`}</Button>
        </Inline>
      </Stack>
    </form>
  </Panel>;
}

/** Moves every account of one proxy to another (or to none) in one write, so the proxy can then be removed. */
function MoveAccounts({ proxy, proxies, open, onOpenChange }: { proxy: Proxy; proxies: readonly Proxy[]; open: boolean; onOpenChange(open: boolean): void }) {
  const changed = useChanged();
  const others = proxies.filter(item => item.id !== proxy.id);
  const [choice, setChoice] = useState<string | null>(others[0]?.id ?? null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await write('PUT', 'accounts/proxy', { account_ids: proxy.used_by, proxy_id: choice });
      await changed();
      onOpenChange(false);
      toast.success(`Moved ${uses(proxy.used_by.length).toLowerCase()} ${choice === null ? 'off any proxy' : `to ${choice}`}.`);
    } catch (failure) {
      setError(refusal(failure));
    } finally {
      setBusy(false);
    }
  }
  return <Drawer side="end" open={open} onOpenChange={onOpenChange} title={`Move ${proxy.id}’s accounts`}
    description={`${uses(proxy.used_by.length)} ${proxy.used_by.length === 1 ? 'leaves' : 'leave'} through ${proxy.id} now.`}
    onSubmit={() => void submit()}
    footer={<Inline gap={2}>
      <Button type="submit" variant="primary" loading={busy}>{choice === null ? 'Use no proxy' : 'Move accounts'}</Button>
      <Button disabled={busy} onClick={() => onOpenChange(false)}>Cancel</Button>
    </Inline>}>
    <Stack gap={5}>
      {error && <Notice tone="danger" role="alert">{error}</Notice>}
      <Field label="Move them to" hint={others.length === 0 ? 'The list has no other proxy: add one first, or choose No proxy.' : undefined}>
        <ProxyPicker proxies={proxies} without={proxy.id} value={choice} onChange={setChoice} disabled={busy} />
      </Field>
      <Text size="support" tone="muted" preWrap>{proxy.used_by.join('\n')}</Text>
    </Stack>
  </Drawer>;
}
