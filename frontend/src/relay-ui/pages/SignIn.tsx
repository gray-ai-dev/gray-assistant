// Signing in to the relay's own page. On 127.0.0.1 the operator pastes the one-time code `gray-assistant ui link` printed
// (the page asked for, e.g. a link from Gray's panel, stays open). On the relay's public origin there is no code and no
// password: a passkey enrolled with `gray-assistant ui enroll`, through the browser's own WebAuthn prompt
// (@simplewebauthn/browser; the server checks the answer with @simplewebauthn/server).
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { browserSupportsWebAuthn, startAuthentication, startRegistration, WebAuthnError } from '@simplewebauthn/browser';
import { Button, CodeBlock, Field, InlineCode, Notice, Page, PageHeader, Panel, Stack, Text, TextInput, toast } from '../../ui';
import { ApiError, write, type UiMode } from '../api';
import { navigate } from '../router';
import { fieldError, refusalText } from '../words';

export function SignInPage({ mode, expired }: { mode: UiMode; expired: boolean }) {
  return mode === 'public' ? <PasskeySignIn /> : <CodeSignIn expired={expired} />;
}

/** Why a passkey prompt ended without an answer, in words; the browser's own error names are not shown. */
function promptFailure(error: unknown): string {
  if (error instanceof WebAuthnError) {
    if (error.code === 'ERROR_CEREMONY_ABORTED') return 'The passkey prompt was closed.';
    if (error.code === 'ERROR_INVALID_DOMAIN') return 'This browser refuses passkeys on this address.';
    if (error.code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED') return 'This device already holds a passkey for this relay.';
  }
  if (error instanceof Error && error.name === 'NotAllowedError') return 'The passkey prompt was closed or timed out.';
  if (error instanceof ApiError) return error.code === 'passkey_refused' ? 'gray-assistant didn’t accept that passkey. Is it one enrolled for this relay?' : refusalText(error.code);
  return 'The passkey prompt failed.';
}

/** Public origin: a passkey, nothing else. */
function PasskeySignIn() {
  const client = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const supported = browserSupportsWebAuthn();
  async function signIn() {
    setBusy(true);
    setFailure(null);
    try {
      const begin = await write<{ ceremony: string; options: Parameters<typeof startAuthentication>[0]['optionsJSON'] }>('POST', 'login/options', {});
      const response = await startAuthentication({ optionsJSON: begin.options });
      await write('POST', 'login/verify', { ceremony: begin.ceremony, response });
      await client.invalidateQueries();
      toast.success('Signed in.');
    } catch (error) {
      setFailure(promptFailure(error));
    } finally {
      setBusy(false);
    }
  }
  return <Page size="narrow">
    <Stack gap={6}>
      <PageHeader title="Sign in to gray-assistant" description="This page is your relay’s own: gray-assistant serves it from your relay’s address, and the keys you enter go to gray-assistant and nowhere else. Sign in with a passkey." />
      {!supported && <Notice tone="warning" role="alert">This browser can’t use passkeys. Open the page in a current Chrome, Safari, Edge or Firefox.</Notice>}
      {failure && <Notice tone="danger" role="alert">{failure}</Notice>}
      <Panel>
        <Stack gap={4}>
          <Text size="support" tone="muted">Your device asks for its fingerprint, face or PIN. No password is involved.</Text>
          <div><Button variant="primary" loading={busy} disabled={!supported} onClick={() => void signIn()}>Sign in with a passkey</Button></div>
        </Stack>
      </Panel>
      <CodeBlock language="bash" title="First time here?" level={2} copyLabel="Copy command"
        description="Add a passkey: run this on the relay’s machine, then open the link it prints on the device that will hold the passkey. The link works once, for 15 minutes."
        code="gray-assistant ui enroll" />
    </Stack>
  </Page>;
}

/** 127.0.0.1: the code `gray-assistant ui link` printed; the page asked for stays open. */
function CodeSignIn({ expired }: { expired: boolean }) {
  const client = useQueryClient();
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ field: boolean; text: string } | null>(null);
  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await write('POST', 'session', { code: code.trim() });
      if (expired) navigate('/accounts', { replace: true });
      await client.invalidateQueries();
      toast.success('Signed in.');
    } catch (failure) {
      const refusal = failure instanceof ApiError ? failure : null;
      setError(refusal?.field === 'code' ? { field: true, text: fieldError('code', refusal.code) } : { field: false, text: refusalText(refusal?.code ?? 'internal') });
    } finally {
      setBusy(false);
    }
  }
  return <Page size="narrow">
    <Stack gap={6}>
      <PageHeader title="Sign in to gray-assistant" description="This page runs on your relay’s own machine. Sign in with the one-time link or code gray-assistant printed in its terminal." />
      {expired && <Notice tone="warning" title="That sign-in link has been used or has expired">A link works once, for 10 minutes. Get a new one with the command below.</Notice>}
      {error && !error.field && <Notice tone="danger" role="alert">{error.text}</Notice>}
      <Panel>
        <form onSubmit={event => { event.preventDefault(); void submit(); }}>
          <Stack gap={4}>
            <Field label="Sign-in code" hint="43 characters, the end of the link gray-assistant printed." error={error?.field ? error.text : undefined}>
              <TextInput mono required autoFocus autoComplete="off" spellCheck={false} value={code} onChange={event => setCode(event.target.value)} />
            </Field>
            <div><Button type="submit" variant="primary" loading={busy} disabled={!code.trim()}>Sign in</Button></div>
          </Stack>
        </form>
      </Panel>
      <CodeBlock language="bash" title="Get a new link" level={2} copyLabel="Copy command"
        description="On the relay’s machine. gray-assistant prints the link and its code to that terminal only. Add --config <file> if your config isn’t at $GRAY_ASSISTANT_CONFIG, /etc/gray-assistant/gray-assistant.jsonc or ./gray-assistant.jsonc."
        code="gray-assistant ui link" />
      <Text size="support" tone="muted">From another computer, forward the port first (<InlineCode>ssh -L 7470:127.0.0.1:7470 your-relay-host</InlineCode>), then open the link there.</Text>
    </Stack>
  </Page>;
}

/** `gray-assistant ui enroll`'s link: name the device, let it make a passkey, and be signed in with it. */
export function EnrollPage({ code }: { code: string }) {
  const client = useQueryClient();
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<{ field: boolean; text: string } | null>(null);
  const supported = browserSupportsWebAuthn();
  async function enroll() {
    setBusy(true);
    setFailure(null);
    try {
      const begin = await write<{ ceremony: string; options: Parameters<typeof startRegistration>[0]['optionsJSON'] }>('POST', 'passkeys/options', { code });
      const response = await startRegistration({ optionsJSON: begin.options });
      await write('POST', 'passkeys/verify', { code, ceremony: begin.ceremony, label: label.trim(), response });
      await client.invalidateQueries();
      toast.success('Passkey added. You’re signed in.');
      navigate('/accounts', { replace: true });
    } catch (error) {
      if (error instanceof ApiError && error.code === 'enroll_link_invalid') setFailure({ field: false, text: 'This link has been used or has expired: each works once, for 15 minutes. Run gray-assistant ui enroll again.' });
      else if (error instanceof ApiError && error.field === 'label') setFailure({ field: true, text: 'Give the device a name of up to 64 characters.' });
      else setFailure({ field: false, text: promptFailure(error) });
    } finally {
      setBusy(false);
    }
  }
  return <Page size="narrow">
    <Stack gap={6}>
      <PageHeader title="Add a passkey" description="This device will sign in to the gray-assistant page with its fingerprint, face or PIN. The link that opened this page works once." />
      {!supported && <Notice tone="warning" role="alert">This browser can’t make passkeys. Open the link in a current Chrome, Safari, Edge or Firefox.</Notice>}
      {failure && !failure.field && <Notice tone="danger" role="alert">{failure.text}</Notice>}
      <Panel>
        <form onSubmit={event => { event.preventDefault(); void enroll(); }}>
          <Stack gap={4}>
            <Field label="Name of this device" hint="So you can tell passkeys apart in gray-assistant ui passkeys list, e.g. “Ops laptop”." error={failure?.field ? failure.text : undefined}>
              <TextInput required autoFocus maxLength={64} value={label} onChange={event => setLabel(event.target.value)} />
            </Field>
            <div><Button type="submit" variant="primary" loading={busy} disabled={!supported || !label.trim()}>Create passkey</Button></div>
          </Stack>
        </form>
      </Panel>
      <Notice tone="warning" title="Only from a link you made yourself">Add a passkey only if you ran gray-assistant ui enroll on the relay’s machine just now. A passkey added here can change your relay’s accounts.</Notice>
    </Stack>
  </Page>;
}
