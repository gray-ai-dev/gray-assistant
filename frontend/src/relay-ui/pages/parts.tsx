// Pieces several local pages share.
import { useEffect, useState, type ReactNode } from 'react';
import { Check, Copy } from '../../components/icons';
import { Button, InlineCode, Notice } from '../../ui';
import type { RelayInfo } from '../api';
import { clockText, relayCommand, relativeTime } from '../words';

/** Says when gray-assistant is not sealing: not running, silent, stopped or paused. Nothing while it runs. */
export function AgentNotice({ relay, what = 'Changes you make here wait in accounts.json until then.' }: { relay: RelayInfo; what?: ReactNode }) {
  const agent = relay.agent;
  const run = <InlineCode>{relayCommand(relay, 'run')}</InlineCode>;
  if (agent.state === 'running' && !agent.paused) return null;
  if (agent.state === 'running') return <Notice tone="warning" title="gray-assistant is paused">
    It seals and serves nothing until you resume it: <InlineCode>{relayCommand(relay, 'resume')}</InlineCode>
  </Notice>;
  if (agent.state === 'not_running') return <Notice tone="warning" title="gray-assistant isn’t running">
    Nothing is sealed for Gray’s VM until it runs. {what} Start it on the relay’s machine: {run}
  </Notice>;
  const last = agent.as_of_ms === null ? null : `${relativeTime(agent.as_of_ms, Date.now())} (${clockText(agent.as_of_ms, Date.now())})`;
  if (agent.state === 'stopped') return <Notice tone="danger" title="gray-assistant has stopped">
    It stopped {last ?? 'at some point'} and seals nothing now. Start it again: {run}
  </Notice>;
  return <Notice tone="warning" title="gray-assistant stopped reporting">
    Its last report is from {last ?? 'a while ago'}; it reports every few seconds while it runs. Check that {run} is still running on the relay’s machine.
  </Notice>;
}

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
