// Releases: new versions of the software in Gray's VM (and the OS images it boots), from Gray's signed release list.
// gray-assistant seals keys only to a release it accepts: on its own a set time after it first saw the release, or when
// the operator accepts it here (or, for what Gray listed when the relay paired, at pairing); a rejected release is never
// accepted. The page answers: what waits for a decision,
// how long until it is accepted anyway, and what is accepted or rejected now.
import { useState } from 'react';
import { Badge, Button, EmptyState, Inline, Menu, MenuItem, Notice, Page, PageHeader, Skeleton, Stack, StackedTable, TableBody, TableCell, TableHead, TableHeaderCell, TableRow, Text, VisuallyHidden, toast, useConfirm } from '../../ui';
import { ApiError, write, type RelayInfo, type Release, type ReleasesView } from '../api';
import { LIVE_MS, useLocal, useNow } from '../data';
import { clockText, durationText, refusalText, relativeTime, releaseName } from '../words';
import { AgentNotice } from './parts';

type Decision = { label: string; tone: 'success' | 'info' | 'warning' | 'danger' | 'neutral'; detail: string };

function decision(release: Release, view: ReleasesView, now: number): Decision {
  if (release.rejected) return { label: 'Rejected', tone: 'danger', detail: 'gray-assistant never seals to it until you take the rejection back.' };
  if (release.kind === 'os_image' && release.refusal === 'os_image_dev') return { label: 'Development image', tone: 'danger', detail: 'Never accepted: it is a development build.' };
  if (release.accepted && release.accepted_at_pairing) return { label: 'Accepted', tone: 'success', detail: 'It was in Gray’s list when this relay paired, so it runs without the wait.' };
  if (release.accepted) return { label: 'Accepted', tone: 'success', detail: 'You accepted it.' };
  if (release.acceptable && release.first_seen_ms === 0) return { label: 'Accepted', tone: 'success', detail: 'It was in the first list gray-assistant read, so it was taken as it was.' };
  if (release.acceptable) return { label: 'Accepted', tone: 'success', detail: `Accepted on its own, ${view.delay_days} days after gray-assistant first saw it.` };
  if (view.accept_mode === 'manual') return { label: 'Waiting for you', tone: 'warning', detail: 'This relay accepts releases only by hand.' };
  if (release.acceptable_at_ms !== null) return { label: 'Waiting', tone: 'info', detail: `Accepted on its own in ${durationText(release.acceptable_at_ms - now)}, unless you accept or reject it first.` };
  return { label: 'Waiting', tone: 'info', detail: 'Not accepted yet.' };
}

export function ReleasesPage({ relay }: { relay: RelayInfo }) {
  const releases = useLocal<ReleasesView>('releases', { live: LIVE_MS });
  const confirm = useConfirm();
  const now = useNow(30_000);
  const [busy, setBusy] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const view = releases.data;
  const rows = [...(view?.releases ?? [])].sort((a, b) => Number(a.accepted || a.acceptable) - Number(b.accepted || b.acceptable) || (b.first_seen_ms ?? 0) - (a.first_seen_ms ?? 0));
  const waiting = rows.filter(row => !row.accepted && !row.acceptable && !row.rejected);

  async function act(release: Release, verb: 'accept' | 'reject' | 'unreject') {
    const name = releaseName(release);
    if (verb === 'reject' && !await confirm({
      title: `Reject ${name}?`,
      description: 'gray-assistant stops sealing keys to Gray’s VM while it runs this release, and never accepts it until you take the rejection back.',
      confirmLabel: 'Reject release',
      tone: 'danger',
    })) return;
    setBusy(release.hash);
    setFailure(null);
    try {
      const answer = await write<{ releases: ReleasesView; warning?: string | null }>('POST', `releases/${verb}`, verb === 'accept' ? { id: release.hash } : { hash: release.hash });
      releases.set(answer.releases);
      toast.success(verb === 'accept' ? `Accepted ${name}.` : verb === 'reject' ? `Rejected ${name}.` : `${name} is no longer rejected.`, answer.warning ? { description: answer.warning } : undefined);
    } catch (error) {
      setFailure(`Couldn’t ${verb} ${name}: ${refusalText(error instanceof ApiError ? error.code : 'internal', error instanceof ApiError ? error.detail : null)}`);
    } finally {
      setBusy(null);
    }
  }

  const mode = view ? (view.accept_mode === 'manual' ? 'This relay accepts releases only when you accept them here.' : `gray-assistant accepts a release on its own ${view.delay_days} days after it first sees it; accept it here to use it sooner, or reject it.`) : '';
  return <Page>
    <Stack gap={6}>
      <PageHeader title="Releases" description={`New versions of the software in Gray’s VM. gray-assistant seals keys only to a release it accepts. ${mode}`} />
      <AgentNotice relay={view?.relay ?? relay} what="It reads Gray’s release list once it runs." />
      {failure && <Notice tone="danger" role="alert">{failure}</Notice>}
      {releases.error && <Notice tone="danger" role="alert" actions={<Button size="sm" onClick={() => void releases.reload()}>Try again</Button>}>Couldn’t read the releases: {refusalText(releases.error.code)}</Notice>}
      {view?.release_list?.last_error && <Notice tone="warning" title="Gray’s release list didn’t verify at the last read">
        gray-assistant keeps using the list it read before{view.release_list.current_until_ms ? `, which counts until ${clockText(view.release_list.current_until_ms, now)}` : ''}. ({view.release_list.last_error.replaceAll('_', ' ')})
      </Notice>}
      {waiting.length > 0 && view?.accept_mode === 'manual' && <Notice tone="warning" title={waiting.length === 1 ? `${releaseName(waiting[0]!)} waits for you` : `${waiting.length} releases wait for you`}>
        Gray’s VM gets no keys on a new release until you accept it.
      </Notice>}
      {releases.loading && <Skeleton rows={2} label="Loading the releases" />}
      {view && rows.length === 0 && <EmptyState title={view.relay.agent.state === 'not_running' ? 'No releases read yet' : 'No releases in Gray’s list'}
        description={view.relay.agent.state === 'not_running' ? 'gray-assistant lists Gray’s releases here once it runs and reads the signed list.' : 'Gray’s signed release list names no release for this relay right now.'} />}
      {rows.length > 0 && view && <StackedTable label="Releases" className="relay-ui-releases">
        <TableHead><TableRow>
          <TableHeaderCell>Release</TableHeaderCell>
          <TableHeaderCell title="When gray-assistant first saw it in Gray’s signed list. The waiting time counts from here.">First seen</TableHeaderCell>
          <TableHeaderCell>Decision</TableHeaderCell>
          <TableHeaderCell kind="actions"><VisuallyHidden>Actions</VisuallyHidden></TableHeaderCell>
        </TableRow></TableHead>
        <TableBody>{rows.map(release => {
          const state = decision(release, view, now);
          const decided = release.accepted || release.acceptable;
          return <TableRow key={`${release.kind}:${release.hash}`}>
            <TableCell data-label="Release"><Stack gap={0}>
              <Text as="span" weight="medium" title={`${release.kind === 'os_image' ? 'OS image hash' : 'Compose hash'} ${release.hash}`}>{releaseName(release)}</Text>
              <Text as="span" size="meta" tone="muted">{release.kind === 'os_image' ? 'The VM’s operating system' : 'Gray’s software in the VM'}</Text>
            </Stack></TableCell>
            <TableCell data-label="First seen" nowrap>{release.first_seen_ms === null ? <Text as="span" tone="muted">—</Text>
              : release.first_seen_ms === 0 ? <Text as="span" size="support" tone="muted">From the start</Text>
              : <Text as="span" size="support" title={clockText(release.first_seen_ms, now)}>{relativeTime(release.first_seen_ms, now)}</Text>}</TableCell>
            <TableCell data-label="Decision" wide><Stack gap={1}>
              <span><Badge tone={state.tone} dot>{state.label}</Badge></span>
              <Text as="span" size="meta" tone="muted">{state.detail}</Text>
            </Stack></TableCell>
            <TableCell kind="actions"><Inline gap={1} wrap={false}>
              {!decided && !release.rejected && release.refusal !== 'os_image_dev' && <Button size="sm" variant="primary" loading={busy === release.hash} disabled={busy !== null} onClick={() => void act(release, 'accept')}>Accept</Button>}
              {release.rejected && <Button size="sm" loading={busy === release.hash} disabled={busy !== null} onClick={() => void act(release, 'unreject')}>Take back rejection</Button>}
              {!release.rejected && <Menu label={`More for ${releaseName(release)}`}>
                <MenuItem tone="danger" disabled={busy !== null} onSelect={() => void act(release, 'reject')}>Reject release</MenuItem>
              </Menu>}
            </Inline></TableCell>
          </TableRow>;
        })}</TableBody>
      </StackedTable>}
    </Stack>
  </Page>;
}
