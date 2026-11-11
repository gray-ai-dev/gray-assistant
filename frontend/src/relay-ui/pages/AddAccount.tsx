// Add account: the one form where a key is typed. Gray's panel links here with the account's ID, vendor and models
// (`/accounts/new?id=…&vendor=…&models=…`), so the operator only pastes the key. gray-assistant writes the account to
// accounts.json on the relay's machine and seals it for Gray's VM at its next read.
import { useMemo, useState } from 'react';
import { Button, Field, Fieldset, FormGrid, Inline, LinkButton, Notice, Page, PageHeader, Panel, Section, SegmentedControl, SelectField, Skeleton, Stack, Step, Steps, Text, TextInput, toast } from '../../ui';
import { ApiError, write, type AccountsView, type PastedCredentialType, type RelayInfo, type Vendor } from '../api';
import { useLocal } from '../data';
import { href, navigate } from '../router';
import { CREDENTIAL_CHOICES, credentialLabel, fieldError, keyFits, keyHint, recognizeKey, refusalText, VENDOR_LABEL, VENDORS } from '../words';
import { AgentNotice } from './parts';

type Form = { id: string; vendor: Vendor; type: PastedCredentialType; key: string; models: string; proxy: string };

function initialForm(query: URLSearchParams): Form {
  const id = (query.get('id') ?? '').trim();
  const vendor = VENDORS.find(item => item === query.get('vendor')) ?? 'anthropic';
  const asked = query.get('type');
  const type = CREDENTIAL_CHOICES[vendor].find(item => item === asked) ?? CREDENTIAL_CHOICES[vendor][0]!;
  const models = (query.get('models') ?? '').split(',').map(model => model.trim()).filter(Boolean).join(', ');
  return { id, vendor, type, key: '', models, proxy: '' };
}

export function AddAccountPage({ relay, query }: { relay: RelayInfo; query: URLSearchParams }) {
  const accounts = useLocal<AccountsView>('accounts', { live: 60_000 });
  const fromPanel = query.has('id') || query.has('vendor') || query.has('models');
  const [form, setForm] = useState<Form>(() => initialForm(query));
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const set = (patch: Partial<Form>) => setForm(current => ({ ...current, ...patch }));
  const source = accounts.data?.source;
  const taken = useMemo(() => new Set((accounts.data?.accounts ?? []).map(account => account.account_id)), [accounts.data]);
  const seen = recognizeKey(form.key);
  const fits = keyFits(form.vendor, form.type, seen);
  const pollSeconds = Math.round((accounts.data?.source_poll_ms ?? 30_000) / 1000);
  const blocked = !!source && (source.kind !== 'file' || !source.writable || source.problem !== null);
  const idTaken = taken.has(form.id.trim());

  async function submit() {
    setBusy(true);
    setErrors({});
    setFailure(null);
    const id = form.id.trim();
    const models = form.models.split(',').map(model => model.trim()).filter(Boolean);
    try {
      await write<AccountsView>('POST', 'accounts', {
        account_id: id,
        vendor: form.vendor,
        credential: { type: form.type, value: form.key },
        models: models.length ? models : null,
        proxy: form.proxy.trim() || null,
      });
      set({ key: '' });
      toast.success(`Added ${id}.`, { description: `gray-assistant seals its key at its next read, within ${pollSeconds} seconds.` });
      navigate('/accounts', { replace: true });
    } catch (error) {
      const refusal = error instanceof ApiError ? error : null;
      if (refusal?.field) setErrors({ [refusal.field]: fieldError(refusal.field, refusal.code) });
      else setFailure(refusalText(refusal?.code ?? 'internal', refusal?.detail));
    } finally {
      setBusy(false);
    }
  }

  return <Page size="narrow">
    <Stack gap={6}>
      <PageHeader back={{ href: '/accounts', label: 'Accounts' }} title="Add account"
        description="The key stays on the relay’s machine: gray-assistant writes it to accounts.json and seals it for Gray’s VM itself. Gray’s website never sees it." />
      {fromPanel && <Notice title={form.id ? 'Opened from Gray’s panel: paste the key' : 'Opened from Gray’s panel'}>{form.id ? null : 'Fill in the account and paste its key.'}</Notice>}
      <AgentNotice relay={accounts.data?.relay ?? relay} what="The account waits in accounts.json until then." />
      {source && source.kind !== 'file' && <Notice tone="warning" title={`Add it in ${source.kind === 'cliproxyapi' ? 'CLIProxyAPI' : 'your relay software'} instead`}>
        This relay’s accounts come from {source.kind === 'cliproxyapi' ? 'CLIProxyAPI' : 'its own software'}{source.url ? ` at ${source.url}` : ''}, not from accounts.json. Add the account there with the same ID{form.id ? ` (${form.id})` : ''}; gray-assistant reads it within {pollSeconds} seconds and seals it.
      </Notice>}
      {source?.kind === 'file' && source.problem && <Notice tone="danger" role="alert" title="accounts.json can’t be read">Fix it first ({source.problem.detail}); this page won’t change a file gray-assistant refuses.</Notice>}
      {source?.kind === 'file' && !source.writable && !source.problem && <Notice tone="warning" title="accounts.json is read-only here">Its folder is mounted read-only for gray-assistant, so this page can’t add the account. Mount the folder writable, or add the entry by hand.</Notice>}
      {failure && <Notice tone="danger" role="alert">{failure}</Notice>}
      {accounts.loading && <Skeleton lines={6} label="Loading the form" />}
      {!accounts.loading && !blocked && <Panel>
        <form onSubmit={event => { event.preventDefault(); void submit(); }}>
          <Fieldset disabled={busy} gap={6}>
            <Section title="The account" level={2} size="sm">
              <FormGrid columns={2}>
                <Field label="Account ID" hint="The same ID as in Gray’s panel, so the panel finds it." error={errors['account_id'] ?? (idTaken ? fieldError('account_id', 'taken') : undefined)}>
                  <TextInput mono required autoComplete="off" spellCheck={false} value={form.id} onChange={event => set({ id: event.target.value })} />
                </Field>
                <Field label="Vendor" error={errors['vendor']}>
                  <SelectField value={form.vendor} onValueChange={value => { const vendor = value as Vendor; set({ vendor, type: CREDENTIAL_CHOICES[vendor][0]! }); }}>
                    {VENDORS.map(vendor => <option key={vendor} value={vendor}>{VENDOR_LABEL[vendor]}</option>)}
                  </SelectField>
                </Field>
              </FormGrid>
            </Section>
            <Section title="Its credential" level={2} size="sm">
              <Stack gap={4}>
                {CREDENTIAL_CHOICES[form.vendor].length > 1 && <div><SegmentedControl aria-label="Kind of credential" value={form.type} onValueChange={type => set({ type })}
                  options={CREDENTIAL_CHOICES[form.vendor].map(type => ({ value: type, label: credentialLabel(form.vendor, type) }))} /></div>}
                <Field label="Key" hint={seen ? `${seen.label}.${fits ? '' : ` ${keyHint(form.vendor, form.type)}`}` : keyHint(form.vendor, form.type)} error={errors['credential']}>
                  <TextInput type="password" mono required autoComplete="off" spellCheck={false} data-1p-ignore="" data-lpignore="true" value={form.key} onChange={event => set({ key: event.target.value })} />
                </Field>
              </Stack>
            </Section>
            <Section title="Serving" level={2} size="sm">
              <FormGrid columns={1}>
                <Field label="Models" optional hint="Model IDs separated by commas. Empty: every model of the vendor." error={errors['models']}>
                  <TextInput mono autoComplete="off" spellCheck={false} value={form.models} placeholder="claude-sonnet-4-5, claude-opus-4-1" onChange={event => set({ models: event.target.value })} />
                </Field>
                <Field label="Proxy" optional hint="Where its calls to the vendor leave from, e.g. socks5://user:password@host:1080. Its password stays on the relay’s machine too." error={errors['proxy']}>
                  <TextInput mono autoComplete="off" spellCheck={false} value={form.proxy} placeholder="socks5://user:password@host:1080" onChange={event => set({ proxy: event.target.value })} />
                </Field>
              </FormGrid>
            </Section>
            <Inline gap={2}>
              <Button type="submit" variant="primary" loading={busy} disabled={!form.id.trim() || idTaken || !form.key.trim()}>Add account</Button>
              <LinkButton href={href('/accounts')}>Cancel</LinkButton>
            </Inline>
          </Fieldset>
        </form>
      </Panel>}
      {!blocked && <Section title="What happens next" level={2} size="sm">
        <Steps aria-label="What happens next">
          <Step title="gray-assistant writes it to accounts.json" aside="mode 0600" />
          <Step title="gray-assistant seals the key for Gray’s VM" aside={`within ${pollSeconds} s`} />
          <Step title="Gray’s panel shows it serving" />
        </Steps>
      </Section>}
    </Stack>
  </Page>;
}
