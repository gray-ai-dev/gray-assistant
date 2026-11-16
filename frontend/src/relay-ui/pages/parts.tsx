// Pieces several local pages share.
import { useEffect, useState } from 'react';
import { Check, Copy } from '../../components/icons';
import { Badge, Button, Facts, Notice, SelectField, Stack, Text } from '../../ui';
import type { AccountsView, Proxy } from '../api';
import { proxyOption, type PanelState } from '../words';

/** Copies one value (a one-time code) and says so on the button, as a code block's copy button does. */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  useEffect(() => { setState('idle'); }, [value]);
  async function copy() {
    try { await navigator.clipboard.writeText(value); setState('copied'); }
    catch { setState('failed'); }
  }
  return <Button icon={state === 'copied' ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />} onClick={() => void copy()}>
    <span aria-live="polite">{state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed: select the code' : label}</span>
  </Button>;
}

/** The picker's value for "No proxy": no proxy id holds a parenthesis. */
const NO_PROXY = '(none)';

/** One proxy of the list, or none. Inside a `Field`, which names it. */
export function ProxyPicker({ proxies, value, onChange, disabled, without }: {
  proxies: readonly Proxy[]; value: string | null; onChange(id: string | null): void; disabled?: boolean;
  /** A proxy left out of the choices: the one its accounts move away from. */
  without?: string;
}) {
  return <SelectField value={value ?? NO_PROXY} disabled={disabled} onValueChange={next => onChange(next === NO_PROXY ? null : next)}>
    <option value={NO_PROXY}>No proxy</option>
    {proxies.filter(proxy => proxy.id !== without).map(proxy => <option key={proxy.id} value={proxy.id}>{proxyOption(proxy)}</option>)}
  </SelectField>;
}

/**
 * An account's state on Gray: the panel's badge, and its few words under it when the account needs a look (one that
 * serves or is paused is its badge alone, as on Gray's panel), or that the state is not known here.
 */
export function StateCell({ state, leftOut }: { state: PanelState; leftOut?: string | null }) {
  // An account gray-assistant leaves out never reaches the VM: that, and why, is its whole state here.
  if (leftOut) return <Stack gap={1}>
    <span><Badge tone="warning" dot>Left out</Badge></span>
    <Text as="span" size="meta" tone="muted">{leftOut}</Text>
  </Stack>;
  return <Stack gap={1}>
    <span>{state.known
      ? <Badge tone={state.tone} dot title={state.reason}>{state.label}</Badge>
      : <Badge title={state.reason}>{state.label}</Badge>}</span>
    {state.known && (state.tone === 'warning' || state.tone === 'danger') && <Facts size="meta">{state.short.split(' · ')}</Facts>}
  </Stack>;
}

/** Whether this page can change the accounts: they are in accounts.json, and gray-assistant can read and replace it. */
export function editable(source: AccountsView['source'] | undefined): boolean {
  return !!source && source.kind === 'file' && source.writable && source.problem === null;
}

/**
 * Why this page cannot change the accounts, and where they are changed instead. A source that is not a file is the
 * relay's own software: accounts are managed there, and this page still signs a subscription account in.
 */
export function SourceNotice({ source, signIn = true }: { source: AccountsView['source'] | undefined; signIn?: boolean }) {
  if (!source) return null;
  if (source.kind !== 'file') return <Notice title="Accounts are managed in your software">
    Change them there{source.url ? ` (${source.url})` : ''}.{signIn ? ' This page still signs accounts in.' : ''}
  </Notice>;
  if (source.problem) return <Notice tone="danger" role="alert" title="accounts.json can’t be read">
    {source.problem.detail}. Fix it in {source.path}: until then nothing in it reaches the VM.
  </Notice>;
  if (!source.writable) return <Notice tone="warning" title="accounts.json is read-only here">
    The folder of {source.path} is mounted read-only. Mount it writable for this page, or edit the file by hand.
  </Notice>;
  return null;
}
