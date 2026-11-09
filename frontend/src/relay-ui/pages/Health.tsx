// Health: gray-assistant's own checks (`gray-assistant doctor`) on request: its files, the source, Gray's release list, each
// lane, the clock and the scheduler. Problems come first, each with its next step; passing checks fold away. A run takes
// up to a minute (it attests every lane), so the page shows it running and keeps the last result "as of" its time.
import { Badge, Button, Disclosure, EmptyState, List, Notice, Page, PageHeader, Panel, Progress, Skeleton, Stack, Text } from '../../ui';
import { ApiError, write, type HealthView, type RelayInfo } from '../api';
import { BUSY_MS, useLocal, useNow } from '../data';
import { clockText, refusalText, relativeTime } from '../words';

type Line = NonNullable<HealthView['lines']>[number];

const STATUS: Record<Line['status'], { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral' }> = {
  fail: { label: 'Problem', tone: 'danger' },
  warn: { label: 'Warning', tone: 'warning' },
  ok: { label: 'OK', tone: 'success' },
  skip: { label: 'Skipped', tone: 'neutral' },
};

/** A check's id as a short title: `origin:https://lane.example` → "Lane lane.example". */
export function checkTitle(id: string): string {
  const [family, ...rest] = id.split(':');
  const subject = rest.join(':');
  const host = (() => { try { return new URL(subject).host; } catch { return subject; } })();
  const titles: Record<string, string> = {
    config: 'Configuration', key_permissions: 'Relay key file', key_content: 'Relay key', accounts_permissions: 'accounts.json file', token_permissions: 'Source token file',
    admin_token_permissions: 'Admin token file', policy_bundle: 'Policy bundle', state_permissions: 'State folder', release_key: 'Gray’s published values', source_detected: 'Account source',
    source_credential: 'Reading a key', source_accounts: 'Selected accounts', release_list: 'Gray’s release list', release_freshness: 'Release list freshness', scheduler_tls: 'Scheduler certificate',
    scheduler_echo: 'Scheduler proxy', stack_files: 'Stack files', stack_registry: 'Registry token', stack_challenge: 'Pull-token service', stack_release_status: 'Release status',
    stack_accounts: 'Stack accounts', agent_status: 'Report to Gray', origin: 'Lane', clock: 'Clock against lane', parked: 'Account', login: 'Login', lane_registration: 'Lane registration',
    stack_account: 'Stack account',
  };
  const title = titles[family ?? ''] ?? (family ?? id).replaceAll('_', ' ');
  return subject ? `${title} ${host}` : title;
}

export function HealthPage({ relay }: { relay: RelayInfo }) {
  const health = useLocal<HealthView>('health', { live: data => data?.running ? BUSY_MS : false });
  const now = useNow(15_000);
  const view = health.data;
  const lines = view?.lines ?? null;
  const problems = (lines ?? []).filter(line => line.status === 'fail' || line.status === 'warn');
  const passing = (lines ?? []).filter(line => line.status === 'ok');
  const skipped = (lines ?? []).filter(line => line.status === 'skip');

  async function run() {
    try {
      health.set(await write<HealthView>('POST', 'health/run'));
    } catch (error) {
      health.set({ ...(view ?? { relay, running: false, started_at_ms: null, finished_at_ms: null, ok: null, lines: null }), error: error instanceof ApiError ? error.code : 'internal' });
    }
  }

  return <Page>
    <Stack gap={6}>
      <PageHeader title="Health" description="gray-assistant’s own checks: its files, your account source, Gray’s release list, each lane and your scheduler. The same as gray-assistant doctor."
        actions={lines !== null && <Button variant="primary" loading={view?.running} onClick={() => void run()}>Run checks again</Button>} />
      {health.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void health.reload()}>Try again</Button>}>Couldn’t read the checks: {refusalText(health.error.code)}</Notice>}
      {view?.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void run()}>Try again</Button>}>The checks couldn’t run: {refusalText(view.error)}</Notice>}
      {health.loading && <Skeleton lines={3} label="Loading the checks" />}
      {view?.running && <Panel>
        <Stack gap={2} role="status">
          <Text weight="medium">The checks are running</Text>
          <Text size="support" tone="muted">Started {view.started_at_ms ? relativeTime(view.started_at_ms, now) : 'just now'}. Attesting each lane can take up to a minute.</Text>
          <Progress label="Running the checks" />
        </Stack>
      </Panel>}
      {view && !view.running && lines === null && !view.error && <EmptyState title="Run the checks"
        description="They take up to a minute: gray-assistant reads its files and your source, verifies Gray’s release list, attests each lane and calls your scheduler through its proxy."
        actions={<Button variant="primary" onClick={() => void run()}>Run checks</Button>} />}
      {lines !== null && view && !view.running && <>
        {problems.length === 0
          ? <Notice tone="success" role="status" title="Every check passes">As of {view.finished_at_ms ? clockText(view.finished_at_ms, now) : 'the last run'}.</Notice>
          : <Notice tone={problems.some(line => line.status === 'fail') ? 'danger' : 'warning'} role="status" title={`${problems.length} ${problems.length === 1 ? 'check needs' : 'checks need'} attention`}>
            As of {view.finished_at_ms ? clockText(view.finished_at_ms, now) : 'the last run'}. Each says what to do.
          </Notice>}
        {problems.length > 0 && <List aria-label="Checks that need attention">{problems.map(line => <li key={line.id} className="relay-ui-check">
          <Stack gap={2}>
            <span className="relay-ui-check__title"><Badge tone={STATUS[line.status].tone} dot>{STATUS[line.status].label}</Badge><Text as="span" weight="medium">{checkTitle(line.id)}</Text></span>
            <Text size="support">{line.message}</Text>
            {line.next_step && <Text size="support" tone="muted"><Text as="span" size="support" weight="medium">Next step: </Text>{line.next_step}</Text>}
          </Stack>
        </li>)}</List>}
        {passing.length > 0 && <Disclosure summary={`${passing.length} ${passing.length === 1 ? 'check passes' : 'checks pass'}`} defaultOpen={problems.length === 0}>
          <List aria-label="Checks that pass">{passing.map(line => <li key={line.id} className="relay-ui-check relay-ui-check--quiet">
            <span className="relay-ui-check__title"><Badge tone="success" dot>OK</Badge><Text as="span">{checkTitle(line.id)}</Text></span>
            <Text size="meta" tone="muted">{line.message}</Text>
          </li>)}</List>
        </Disclosure>}
        {skipped.length > 0 && <Text size="meta" tone="muted">Not checked here: {skipped.map(line => checkTitle(line.id)).join(', ')}.</Text>}
      </>}
    </Stack>
  </Page>;
}
