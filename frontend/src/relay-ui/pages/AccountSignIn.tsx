// Signing a subscription account in. The sign-in runs inside the VM (what `gray-assistant login <account>` does); this
// screen is its input and output, in three steps: open the vendor's page (a link, or a device code and its address),
// give back what the vendor shows (a code, or the address the browser ended on: the browser is on the operator's
// machine, so its return cannot reach the relay by itself; the server's `paste` says which), and wait while the VM
// finishes. Nothing typed here is a key, and nothing the vendor returns is kept on this page after it is sent.
import { useEffect, useRef, useState } from 'react';
import { Button, Field, Inline, InlineCode, LinkButton, Notice, Progress, Stack, Step, Steps, Text, TextInput, type StepState } from '../../ui';
import { ApiError, write, type Account, type SignInView } from '../api';
import { BUSY_MS, keepSignInSession, signInSession, takeSignIn, useChanged, useLocal, useNow } from '../data';
import { clockText, refusalText, refusalWords, VENDOR_LABEL } from '../words';
import { CopyButton } from './parts';

/** An address the page may open: the vendor's own, over http(s) only. */
function webAddress(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

/** What the field takes back, by the prompt's `paste`. */
const PASTE = {
  code: {
    step: 'Paste the code it shows',
    label: 'Code',
    hint: undefined,
  },
  address: {
    step: 'Paste the address the browser ended on',
    label: 'Address',
    hint: <>It starts with <InlineCode>http://localhost</InlineCode> and doesn’t load. Copy all of it from the address bar.</>,
  },
} as const;

export function AccountSignIn({ account }: { account: Account }) {
  const id = account.account_id;
  const changed = useChanged();
  const now = useNow(30_000);
  const [session, setSession] = useState<string | null>(() => signInSession(id));
  // What the write that started or fed the sign-in answered, until the next read of it.
  const [answered, setAnswered] = useState<SignInView | null>(null);
  const [busy, setBusy] = useState<'start' | 'input' | 'cancel' | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  // The page's server was started without the sign-in (501): only the command signs this account in.
  const [unavailable, setUnavailable] = useState(false);
  const [text, setText] = useState('');
  // The vendor's link this operator opened from here: the first step is theirs until they do (or paste what it gave).
  const [openedUrl, setOpenedUrl] = useState<string | null>(null);
  const stage = useRef(1);
  const sign = useLocal<SignInView>(`sign-in/${encodeURIComponent(session ?? '')}`, {
    enabled: session !== null,
    live: data => !data || data.state === 'starting' || data.state === 'prompt' || data.state === 'working' ? BUSY_MS : false,
  });
  const view = session === null ? null : sign.data ?? answered;
  const state = view?.state ?? null;
  // The session is gone (gray-assistant restarted, or it ended long ago): nothing to follow, so start over.
  const lost = session !== null && sign.error !== null && sign.error.status === 404;

  function follow(next: SignInView | null) {
    stage.current = 1;
    keepSignInSession(id, next?.session ?? null);
    setAnswered(next);
    setSession(next?.session ?? null);
    setText('');
    setOpenedUrl(null);
  }

  async function start() {
    setBusy('start');
    setFailure(null);
    try {
      follow(await write<SignInView>('POST', `accounts/${encodeURIComponent(id)}/sign-in`));
    } catch (error) {
      if (error instanceof ApiError && error.code === 'not_available') setUnavailable(true);
      else setFailure(refusalWords(error instanceof ApiError ? error : null));
    } finally {
      setBusy(null);
    }
  }

  async function send() {
    if (session === null || text.trim() === '') return;
    setBusy('input');
    setFailure(null);
    try {
      // Whoever pastes the vendor's answer has been to the vendor's page, however they opened it.
      setOpenedUrl(view?.prompt?.url ?? null);
      sign.set(await write<SignInView>('POST', `sign-in/${encodeURIComponent(session)}/input`, { text: text.trim() }));
      setText('');
    } catch (error) {
      setFailure(refusalWords(error instanceof ApiError ? error : null));
      await sign.reload();
    } finally {
      setBusy(null);
    }
  }

  async function cancel() {
    if (session === null) return;
    setBusy('cancel');
    try {
      await write('DELETE', `sign-in/${encodeURIComponent(session)}`);
    } catch {
      // Cancelled either way: a session that is gone has nothing left to cancel.
    } finally {
      setBusy(null);
      setFailure(null);
      follow(null);
    }
  }

  // The add form sends a new subscription account straight here: its sign-in starts without another click.
  useEffect(() => { if (session === null && takeSignIn(id)) void start(); }, []);
  // Signed in: the account's state on this page and on Gray is news.
  useEffect(() => { if (state === 'done') void changed(); }, [state]);

  if (session === null || lost) return <Stack gap={4}>
    {failure && <Notice tone="danger" role="alert">{failure}</Notice>}
    {unavailable && <Notice tone="warning" role="alert" title="This page can’t sign accounts in">
      Run <InlineCode>gray-assistant login {id}</InlineCode> on the relay’s machine.
    </Notice>}
    {lost && <Notice tone="warning">That sign-in ended. Start it again.</Notice>}
    <Text size="support" tone="muted">You sign in on {VENDOR_LABEL[account.vendor]}’s own page and bring back what it shows. The tokens stay in the VM.</Text>
    <div><Button variant="primary" loading={busy === 'start'} onClick={() => void start()}>Start sign-in</Button></div>
  </Stack>;

  const prompt = view?.prompt ?? null;
  const device = prompt?.kind === 'device_code';
  const paste = prompt?.paste ?? null;
  const link = webAddress(prompt?.url);
  const failed = state === 'failed', done = state === 'done';
  // Which step the sign-in is at. A failure does not say where it stopped, so it marks the last step seen under way.
  // A link that changed (the sign-in started over at the vendor) is to open again.
  const opened = prompt !== null && (openedUrl === prompt.url || text.trim() !== '');
  if (state === 'starting') stage.current = 1;
  else if (state === 'prompt') stage.current = opened ? 2 : 1;
  else if (state === 'working' || done) stage.current = 3;
  const reached = stage.current;
  const step = (n: number): StepState => done || n < reached ? 'done' : n === reached ? (failed ? 'failed' : 'current') : 'pending';
  // While a prompt stands, the server's sentence says why the last paste was not it (or that the link changed).
  const notice = state === 'prompt' ? view?.message ?? null : null;

  return <Stack gap={4}>
    {sign.error && !lost && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void sign.reload()}>Try again</Button>}>Couldn’t follow the sign-in: {refusalText(sign.error.code)}</Notice>}
    {failure && <Notice tone="danger" role="alert">{failure}</Notice>}
    {done && <Notice tone="success" role="status" title={`${id} is signed in`} />}
    {failed && <Notice tone="danger" role="alert" title="The sign-in didn’t finish">{view?.message ?? 'gray-assistant gave no reason.'}</Notice>}
    <Steps aria-label="Sign-in steps">
      <Step title={device ? 'Open the vendor’s page and enter the code' : 'Open the vendor’s page'} state={step(1)}
        actions={link && !done && !failed && <LinkButton href={link} target="_blank" rel="noreferrer" variant={state === 'prompt' && !opened ? 'primary' : 'secondary'}
          onClick={() => setOpenedUrl(prompt?.url ?? null)} onAuxClick={() => setOpenedUrl(prompt?.url ?? null)}>Open {VENDOR_LABEL[account.vendor]} in a new tab</LinkButton>}>
        {state === 'starting' && <Stack gap={2}>
          <Text size="support" tone="muted">{view?.message ?? 'Asking the VM for the vendor’s link.'}</Text>
          <Progress label="Starting the sign-in inside the VM" />
        </Stack>}
        {prompt && !done && !failed && <Stack gap={2}>
          <Text size="support" tone="muted">{device
            ? 'Sign in as the account’s owner and enter this code.'
            : 'Sign in as the account’s owner and approve.'} The link works until {clockText(prompt.expires_at_ms, now).replaceAll(' ', '\u00A0')}.</Text>
          {device && prompt.code && <Inline gap={3}>
            <Text as="span" size="body" weight="medium" mono>{prompt.code}</Text>
            <CopyButton value={prompt.code} label="Copy code" />
          </Inline>}
          {!link && <Text size="support" mono>{prompt.url}</Text>}
        </Stack>}
      </Step>
      <Step title={paste ? PASTE[paste].step : device ? 'Approve it there' : 'Give back what the vendor shows'} state={step(2)}>
        {state === 'prompt' && (paste === null
          ? <Stack gap={2}>
            <Text size="support" tone="muted">This page goes on by itself once you approve.</Text>
            {notice && <Text size="support" tone="warning" role="status">{notice}</Text>}
          </Stack>
          : <form onSubmit={event => { event.preventDefault(); void send(); }}>
            <Stack gap={3}>
              <Field label={PASTE[paste].label} hint={PASTE[paste].hint} error={notice ?? undefined}>
                <TextInput mono autoComplete="off" spellCheck={false} data-1p-ignore="" data-lpignore="true" value={text} onChange={event => setText(event.target.value)} />
              </Field>
              <div><Button type="submit" variant="primary" loading={busy === 'input'} disabled={text.trim() === ''}>Continue</Button></div>
            </Stack>
          </form>)}
      </Step>
      <Step title="The VM signs the account in" state={step(3)}>
        {state === 'working' && <Stack gap={2}>
          <Text size="support" tone="muted">{view?.message ?? 'Exchanging the vendor’s answer inside the VM.'}</Text>
          <Progress label="Signing in inside the VM" />
        </Stack>}
      </Step>
    </Steps>
    <Inline gap={2}>
      {done || failed
        ? <Button variant={failed ? 'primary' : 'secondary'} loading={busy === 'start'} onClick={() => void start()}>{failed ? 'Start again' : 'Sign in again'}</Button>
        : <Button loading={busy === 'cancel'} onClick={() => void cancel()}>Cancel</Button>}
    </Inline>
  </Stack>;
}
