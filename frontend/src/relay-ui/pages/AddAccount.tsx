// Add account: a subscription, or API keys. A subscription has no key to paste: the form takes its vendor, its ID and
// its proxy, saves it and goes straight to the sign-in steps on the account's screen. API keys are pasted, one or
// several (one a line; several get an ID prefix). Gray's panel links here with what it knows
// (`?id=&vendor=&type=&group=`). The group is Gray's: gray-assistant puts the account in it once Gray has the account.
// Keys stay on the relay's machine: gray-assistant writes them there and sends them sealed to the VM by itself.
import { useMemo, useState } from 'react';
import { AutocompleteInput, Button, Field, Fieldset, FormGrid, Inline, LinkButton, Notice, Page, PageHeader, Panel, SegmentedControl, SelectField, Skeleton, Stack, TextArea, TextInput, TextLink, toast } from '../../ui';
import { ApiError, write, type AccountsView, type PanelView, type ProxiesView, type Vendor } from '../api';
import { useChanged, useLocal, wantSignIn } from '../data';
import { href, navigate } from '../router';
import { accountPath } from '../screens';
import { fieldError, groupSuggestions, KEY_VENDORS, keyFits, keyHint, linesOf, recognizeKey, refusalText, refusalWords, SUBSCRIPTION_VENDORS, VENDOR_LABEL, VENDORS } from '../words';
import { editable, ProxyPicker, SourceNotice } from './parts';

type Kind = 'subscription' | 'key';
type Form = { kind: Kind; vendor: Vendor; id: string; proxy: string | null; group: string; many: boolean; key: string; keys: string; prefix: string };

const vendorsOf = (kind: Kind) => kind === 'subscription' ? SUBSCRIPTION_VENDORS : KEY_VENDORS;

/** What Gray's panel's link asks for: the account's ID, its vendor and its type (a subscription unless it says a key). */
function initialForm(query: URLSearchParams): Form {
  const asked = VENDORS.find(item => item === query.get('vendor')) ?? null;
  const type = query.get('type');
  const kind: Kind = type === 'api_key' ? 'key' : type === 'sign_in' || type === 'password' || type === 'oauth_access_token' ? 'subscription'
    : asked !== null && !SUBSCRIPTION_VENDORS.includes(asked) ? 'key' : 'subscription';
  const vendor = asked !== null && vendorsOf(kind).includes(asked) ? asked : vendorsOf(kind)[0]!;
  return { kind, vendor, id: (query.get('id') ?? '').trim(), proxy: null, group: (query.get('group') ?? '').trim(), many: false, key: '', keys: '', prefix: '' };
}

export function AddAccountPage({ query }: { query: URLSearchParams }) {
  const accounts = useLocal<AccountsView>('accounts', { live: 60_000 });
  const source = accounts.data?.source;
  const canEdit = editable(source);
  const proxies = useLocal<ProxiesView>('proxies', { enabled: canEdit });
  // The groups in use on Gray, to pick from; the field takes a new name all the same while Gray does not answer.
  const panel = useLocal<PanelView>('panel', { enabled: canEdit });
  const changed = useChanged();
  const [form, setForm] = useState<Form>(() => initialForm(query));
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const set = (patch: Partial<Form>) => setForm(current => ({ ...current, ...patch }));
  const taken = useMemo(() => new Set((accounts.data?.accounts ?? []).map(account => account.account_id)), [accounts.data]);
  const id = form.id.trim(), prefix = form.prefix.trim(), group = form.group.trim() || null;
  const groups = useMemo(() => [...new Set((panel.data?.accounts ?? []).map(account => account.group).filter((name): name is string => !!name))].sort((a, b) => a.localeCompare(b)), [panel.data]);
  const idTaken = taken.has(id);
  const keys = linesOf(form.keys);
  const seen = recognizeKey(form.key);
  const fits = keyFits(form.vendor, 'api_key', seen);
  const several = form.kind === 'key' && form.many;
  const ready = form.kind === 'subscription' ? id !== '' && !idTaken
    : several ? keys.length > 0
    : id !== '' && !idTaken && form.key.trim() !== '';

  function refuse(error: unknown) {
    const refusal = error instanceof ApiError ? error : null;
    // The form's fields by the server's names; a subscription's proxy is refused as `proxy`, a key's as `proxy_id`.
    if (refusal?.field) setErrors({ [refusal.field === 'proxy' ? 'proxy_id' : refusal.field]: fieldError(refusal.field, refusal.code, refusal.detail) });
    else setFailure(refusalText(refusal?.code ?? 'internal', refusal?.detail));
  }

  async function submit() {
    setBusy(true);
    setErrors({});
    setFailure(null);
    try {
      if (form.kind === 'subscription') {
        // No secret: the account is listed with its proxy (the list's id), and signed in inside the VM next.
        await write('POST', 'accounts', { account_id: id, vendor: form.vendor, credential: { type: 'sign_in' }, models: null, proxy: form.proxy, group });
        await changed();
        wantSignIn(id);
        navigate(accountPath(id, 'sign-in'), { replace: true });
      } else if (several) {
        const added = await write<{ ids: string[] }>('POST', 'accounts/keys', { vendor: form.vendor, keys, proxy_id: form.proxy, id_prefix: prefix === '' ? null : prefix, group });
        set({ keys: '' });
        await changed();
        toast.success(added.ids.length === 1 ? `Added ${added.ids[0]}.` : `Added ${added.ids.length} accounts.`, added.ids.length > 1 ? { description: `${added.ids[0]} to ${added.ids.at(-1)}` } : undefined);
        navigate('/accounts', { replace: true });
      } else {
        // One key keeps the ID given (Gray's panel names it). A key account's proxy is set by the list's own call.
        await write('POST', 'accounts', { account_id: id, vendor: form.vendor, credential: { type: 'api_key', value: form.key.trim() }, models: null, proxy: null, group });
        set({ key: '' });
        let withProxy = true;
        if (form.proxy !== null) {
          try {
            await write('PUT', 'accounts/proxy', { account_ids: [id], proxy_id: form.proxy });
          } catch (error) {
            withProxy = false;
            toast.error(`Added ${id}, but its proxy isn’t set.`, { description: refusalWords(error instanceof ApiError ? error : null) });
          }
        }
        await changed();
        if (withProxy) toast.success(`Added ${id}.`);
        navigate(withProxy ? '/accounts' : accountPath(id, 'proxy'), { replace: true });
      }
    } catch (error) {
      refuse(error);
    } finally {
      setBusy(false);
    }
  }

  const list = proxies.data?.proxies ?? [];
  return <Page size="narrow">
    <Stack gap={6}>
      <PageHeader back={{ href: href('/accounts'), label: 'Accounts' }} title="Add account"
        description="Nothing typed here passes through Gray’s website." />
      {accounts.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void accounts.reload()}>Try again</Button>}>Couldn’t read the accounts: {refusalText(accounts.error.code)}</Notice>}
      <SourceNotice source={source} />
      {failure && <Notice tone="danger" role="alert">{failure}</Notice>}
      {(accounts.loading || proxies.loading) && <Skeleton lines={6} label="Loading the form" />}
      {canEdit && !proxies.loading && <Panel>
        <form onSubmit={event => { event.preventDefault(); void submit(); }}>
          <Fieldset disabled={busy} gap={5}>
            <div><SegmentedControl aria-label="Kind of account" value={form.kind}
              onValueChange={kind => { set({ kind, vendor: vendorsOf(kind).includes(form.vendor) ? form.vendor : vendorsOf(kind)[0]! }); setErrors({}); }}
              options={[{ value: 'subscription', label: 'Account sign-in' }, { value: 'key', label: 'API key' }]} /></div>
            <FormGrid columns={2}>
              <Field label="Vendor" error={errors['vendor']}>
                <SelectField value={form.vendor} onValueChange={value => set({ vendor: value as Vendor })}>
                  {vendorsOf(form.kind).map(vendor => <option key={vendor} value={vendor}>{VENDOR_LABEL[vendor]}</option>)}
                </SelectField>
              </Field>
              <Field label="Proxy" error={errors['proxy_id']} aside={<TextLink href={href('/proxies')}>Add a proxy</TextLink>}>
                <ProxyPicker proxies={list} value={form.proxy} onChange={proxy => set({ proxy })} />
              </Field>
            </FormGrid>
            {form.kind === 'key' && <div><SegmentedControl aria-label="How many keys" value={form.many ? 'several' : 'one'} onValueChange={next => { set({ many: next === 'several' }); setErrors({}); }}
              options={[{ value: 'one', label: 'One key' }, { value: 'several', label: 'Several keys' }]} /></div>}
            {!several && <Field label="Account ID" error={errors['account_id'] ?? (idTaken ? fieldError('account_id', 'taken') : undefined)}>
              <TextInput mono required autoComplete="off" spellCheck={false} value={form.id} onChange={event => set({ id: event.target.value })} />
            </Field>}
            {form.kind === 'key' && !several && <Field label="Key" hint={seen ? `${seen.label}.${fits ? '' : ` ${keyHint(form.vendor, 'api_key')}`}` : keyHint(form.vendor, 'api_key')} error={errors['credential']}>
              <TextInput type="password" mono required autoComplete="off" spellCheck={false} data-1p-ignore="" data-lpignore="true" value={form.key} onChange={event => set({ key: event.target.value })} />
            </Field>}
            {several && <>
              <Field label="Keys" hint={`One a line. ${keyHint(form.vendor, 'api_key')}`} error={errors['keys']}>
                <TextArea mono rows={6} wrap="off" autoComplete="off" spellCheck={false} data-1p-ignore="" data-lpignore="true" value={form.keys} onChange={event => set({ keys: event.target.value })} />
              </Field>
              <Field label="ID prefix" optional hint={`IDs become ${prefix || form.vendor}-1, ${prefix || form.vendor}-2.`} error={errors['id_prefix']}>
                <TextInput mono autoComplete="off" spellCheck={false} placeholder={form.vendor} value={form.prefix} onChange={event => set({ prefix: event.target.value })} />
              </Field>
            </>}
            <Field label="Group" optional error={errors['group']}>
              <AutocompleteInput value={form.group} onValueChange={value => set({ group: value })} suggestions={groupSuggestions(groups, form.group)} maxLength={64}
                placeholder={groups.length ? 'Pick a group or type a new name' : 'Type a name'} />
            </Field>
            <Inline gap={2}>
              <Button type="submit" variant="primary" loading={busy} disabled={!ready}>
                {form.kind === 'subscription' ? 'Save and sign in' : several && keys.length > 1 ? `Add ${keys.length} accounts` : 'Add account'}
              </Button>
              <LinkButton href={href('/accounts')}>Cancel</LinkButton>
            </Inline>
          </Fieldset>
        </form>
      </Panel>}
    </Stack>
  </Page>;
}
