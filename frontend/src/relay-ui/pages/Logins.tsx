// Logins: the ChatGPT sign-ins gray-assistant keeps fresh for Codex accounts. A sign-in runs here: gray-assistant asks ChatGPT for
// a one-time code, this page shows it and the link to enter it at, and the page follows the sign-in until it is done.
// The code and the link are shown on this page only; the tokens never leave gray-assistant's login file. Gray's panel links
// here as `/logins/<login>` to sign one in again (`?login=<login>` works too).
import { useState } from 'react';
import {
  Badge, Button, EmptyState, Inline, LinkButton, Notice, Page, PageHeader, Panel, Progress, Skeleton, Spinner, Stack, StackedTable, Stat, Step, Steps, TableBody, TableCell, TableHead,
  TableHeaderCell, TableRow, Text, VisuallyHidden, toast, useConfirm,
} from '../../ui';
import { ApiError, write, type Login, type LoginsView, type RelayInfo, type SignIn } from '../api';
import { BUSY_MS, LIVE_MS, useLocal, useNow } from '../data';
import { clockText, countdown, LOGIN_WORDS, loginProblem, refusalText, relativeTime, signInError } from '../words';
import { AgentNotice, CopyButton } from './parts';
import { href } from '../router';

const ACTIVE = new Set<SignIn['state']>(['starting', 'waiting', 'exchanging']);

export function LoginsPage({ relay, login: asked }: { relay: RelayInfo; login: string | null }) {
  const logins = useLocal<LoginsView>('logins', { live: data => data?.sign_ins.some(sign => ACTIVE.has(sign.state)) ? BUSY_MS : LIVE_MS });
  const confirm = useConfirm();
  const now = useNow(1_000);
  const [starting, setStarting] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const view = logins.data;
  // gray-assistant lists the running sign-ins and those that ended in the last minutes, by its own clock.
  const signIns = view?.sign_ins ?? [];
  // The newest sign-in per login; older ones of the same login are history.
  const shown = signIns.filter((sign, index) => signIns.findIndex(other => other.login === sign.login) === index);
  const askedLogin = asked === null ? null : view?.logins.find(login => login.login === asked) ?? null;
  const askedRunning = asked !== null && shown.some(sign => sign.login === asked && ACTIVE.has(sign.state));
  const askedDone = asked !== null && shown.some(sign => sign.login === asked);

  async function start(login: string, force: boolean) {
    if (force && !await confirm({
      title: `Sign ${login} in again?`,
      description: 'ChatGPT shows a new code to approve. The current sign-in keeps working until you approve the new one.',
      confirmLabel: 'Start sign-in',
    })) return;
    setStarting(login);
    setFailure(null);
    try {
      await write<SignIn>('POST', 'logins', { login, force });
      await logins.reload();
    } catch (error) {
      const refusal = error instanceof ApiError ? error : null;
      if (refusal?.code === 'login_exists') await start(login, true);
      else setFailure(refusalText(refusal?.code ?? 'internal'));
    } finally {
      setStarting(null);
    }
  }
  async function cancel(sign: SignIn) {
    try {
      await write<SignIn>('DELETE', `logins/${encodeURIComponent(sign.id)}`);
      await logins.reload();
      toast.info(`Cancelled the sign-in of ${sign.login}.`);
    } catch (error) {
      setFailure(refusalText(error instanceof ApiError ? error.code : 'internal'));
    }
  }

  return <Page>
    <Stack gap={6}>
      <PageHeader title="Logins" description="ChatGPT sign-ins gray-assistant keeps fresh for your Codex accounts. A sign-in shows its code on this page only." />
      <AgentNotice relay={view?.relay ?? relay} what="A sign-in still works; its accounts are sealed once it runs." />
      {view && view.source_kind !== 'file' && <Notice title="Logins belong to the file source">This relay’s accounts come from its own software, which signs in and refreshes its accounts itself.</Notice>}
      {failure && <Notice tone="danger" role="alert">{failure}</Notice>}
      {logins.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void logins.reload()}>Try again</Button>}>Couldn’t read the logins: {refusalText(logins.error.code)}</Notice>}

      {shown.map(sign => <SignInPanel key={sign.id} sign={sign} now={now} onCancel={() => void cancel(sign)} onRestart={() => void start(sign.login, true)} />)}
      {asked !== null && !askedRunning && !askedDone && view && <Panel title={askedLogin && askedLogin.state !== 'missing' ? `Sign ${asked} in again` : `Sign ${asked} in`}
        description={askedLogin && askedLogin.state !== 'missing' ? loginProblem(askedLogin) ?? 'Start a new sign-in; the current one keeps working until you approve the new one.' : 'ChatGPT shows a one-time code here; you approve it in your browser.'}>
        <Inline gap={3}>
          <Button variant="primary" loading={starting === asked} onClick={() => void start(asked, !!askedLogin && askedLogin.state !== 'missing')}>Start sign-in</Button>
          <Text as="span" size="support" tone="muted">You’ll need the password of the ChatGPT account this login serves.</Text>
        </Inline>
      </Panel>}

      {logins.loading && <Skeleton rows={2} label="Loading the logins" />}
      {view && view.source_kind === 'file' && view.logins.length === 0 && shown.length === 0 && asked === null && <EmptyState title="No logins yet"
        description="A login is a ChatGPT account gray-assistant signs in to once and keeps fresh. Add a ChatGPT Codex account with “Sign in with ChatGPT” to start one."
        actions={<LinkButton variant="primary" href={href('/accounts/new?vendor=chatgpt_codex')}>Add a Codex account</LinkButton>} />}
      {view && view.logins.length > 0 && <StackedTable label="Logins" className="relay-ui-logins">
        <TableHead><TableRow>
          <TableHeaderCell>Login</TableHeaderCell>
          <TableHeaderCell>State</TableHeaderCell>
          <TableHeaderCell title="When its current access token stops working. gray-assistant refreshes it well before.">Access ends</TableHeaderCell>
          <TableHeaderCell>Next refresh</TableHeaderCell>
          <TableHeaderCell kind="actions"><VisuallyHidden>Actions</VisuallyHidden></TableHeaderCell>
        </TableRow></TableHead>
        <TableBody>{view.logins.map(login => <LoginRow key={login.login} login={login} now={now} highlighted={login.login === asked}
          starting={starting === login.login} running={shown.some(sign => sign.login === login.login && ACTIVE.has(sign.state))}
          onSignIn={() => void start(login.login, login.state !== 'missing')} />)}</TableBody>
      </StackedTable>}
      {view?.logins_dir && <Text size="meta" tone="muted">Login files: {view.logins_dir} (each 0600, in gray-assistant’s state volume)</Text>}
    </Stack>
  </Page>;
}

function LoginRow({ login, now, highlighted, starting, running, onSignIn }: { login: Login; now: number; highlighted: boolean; starting: boolean; running: boolean; onSignIn: () => void }) {
  const words = LOGIN_WORDS[login.state];
  const problem = loginProblem(login);
  const needsHand = login.state === 'missing' || login.state === 'failed' || login.state === 'expired';
  return <TableRow aria-current={highlighted || undefined}>
    <TableCell data-label="Login"><Stack gap={0}>
      <Text as="span" weight="medium" truncate className="relay-ui-name">{login.login}</Text>
      <Text as="span" size="meta" tone="muted">{login.account_ids.length ? `Used by ${login.account_ids.length <= 2 ? login.account_ids.join(' and ') : `${login.account_ids.slice(0, 2).join(', ')} and ${login.account_ids.length - 2} more`}` : 'No account uses it'}</Text>
    </Stack></TableCell>
    <TableCell data-label="State" wide><Stack gap={1}>
      <span><Badge tone={words.tone} dot>{words.label}</Badge></span>
      {problem && <Text as="span" size="meta" tone="muted">{problem}</Text>}
    </Stack></TableCell>
    <TableCell data-label="Access ends" nowrap>{login.access_expires_at_ms === null ? <Text as="span" tone="muted">—</Text> : <Text as="span" size="support" title={clockText(login.access_expires_at_ms, now)}>{relativeTime(login.access_expires_at_ms, now)}</Text>}</TableCell>
    <TableCell data-label="Next refresh" nowrap>{login.next_refresh_at_ms === null ? <Text as="span" tone="muted">{login.state === 'failed' ? 'After a new sign-in' : '—'}</Text> : <Text as="span" size="support" title={clockText(login.next_refresh_at_ms, now)}>{relativeTime(login.next_refresh_at_ms, now)}</Text>}</TableCell>
    <TableCell kind="actions"><Button size="sm" variant={needsHand && !running ? 'primary' : 'secondary'} loading={starting} disabled={running}
      title={running ? 'Its sign-in is running above.' : undefined} onClick={onSignIn}>{login.state === 'missing' ? 'Sign in' : 'Sign in again'}</Button></TableCell>
  </TableRow>;
}

/** One sign-in as it goes: the code to enter, the wait, and how it ended. */
function SignInPanel({ sign, now, onCancel, onRestart }: { sign: SignIn; now: number; onCancel: () => void; onRestart: () => void }) {
  if (sign.state === 'done') return <Notice tone="success" role="status" title={`${sign.login} is signed in`}
    actions={<LinkButton size="sm" href={href('/accounts')}>Go to Accounts</LinkButton>}>
    {sign.access_expires_at_ms ? `Its access token works until ${clockText(sign.access_expires_at_ms, now)}; ` : ''}gray-assistant refreshes it from now on and seals it for every account that uses it.
  </Notice>;
  if (sign.state === 'failed') return <Notice tone="danger" role="alert" title={`${sign.login} isn’t signed in`} actions={<Button size="sm" onClick={onRestart}>Start again</Button>}>{signInError(sign)}</Notice>;
  if (sign.state === 'cancelled') return <Notice title={`You cancelled the sign-in of ${sign.login}`} actions={<Button size="sm" onClick={onRestart}>Start again</Button>}>Nothing changed: the login is as it was before.</Notice>;
  const left = sign.expires_at_ms === null ? null : sign.expires_at_ms - now;
  return <Panel title={`Sign ${sign.login} in`} description="On any device with a browser. The code works once and for 15 minutes."
    actions={<Button size="sm" variant="ghost" onClick={onCancel}>Cancel</Button>}>
    <Stack gap={5}>
      {sign.state === 'starting' && <Stack gap={2} role="status">
        <Text size="support" tone="muted">Asking ChatGPT for a code…</Text>
        <Progress label="Asking ChatGPT for a code" />
      </Stack>}
      {sign.state !== 'starting' && <Steps aria-label="Sign-in steps">
        <Step title="Open ChatGPT’s sign-in page" done={sign.state === 'exchanging'}
          actions={sign.verification_url && sign.state === 'waiting' && <LinkButton size="sm" variant="primary" href={sign.verification_url} target="_blank" rel="noopener noreferrer">Open sign-in page</LinkButton>}>
          <Text size="support" tone="muted">Sign in to the ChatGPT account this relay serves{sign.verification_url ? ` (${new URL(sign.verification_url).host})` : ''}.</Text>
        </Step>
        <Step title="Enter this code" done={sign.state === 'exchanging'}>
          {sign.user_code && <Inline gap={4}>
            <Stat label="One-time code" value={sign.user_code} />
            <CopyButton value={sign.user_code} label="Copy code" />
          </Inline>}
        </Step>
        <Step title={sign.state === 'exchanging' ? 'Approved: finishing the sign-in' : 'Approve it, then come back'}>
          <Stack gap={1} role="status">
            <Inline gap={2} wrap={false}>
              <Spinner />
              <Text as="span" size="support" tone="muted">{sign.state === 'exchanging' ? 'Saving the sign-in on the relay’s machine' : 'Waiting for your approval'}</Text>
            </Inline>
            {sign.state === 'waiting' && left !== null && <Text as="span" size="meta" tone="muted" numeric>The code expires in {countdown(left)}.</Text>}
          </Stack>
        </Step>
      </Steps>}
      <Notice tone="warning" title="Only for a sign-in you started">Enter the code only if you started this sign-in on this page yourself. If a website or another person gave you the code, cancel.</Notice>
    </Stack>
  </Panel>;
}
