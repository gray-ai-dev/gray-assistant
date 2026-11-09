import type { ReactNode } from 'react';
import { Check, X } from '../components/icons';
import { cx } from './cx';
import { Progress } from './Data';
import { Panel } from './Layout';

/** Where a checklist item stands: done, the one to do now, later, failed (with its fix), or not reported (no signal yet). */
export type ChecklistState = 'done' | 'current' | 'upcoming' | 'failed' | 'unknown';
const STATE_WORDS: Readonly<Record<ChecklistState, string>> = { done: 'done', current: 'to do now', upcoming: 'to do later', failed: 'failed', unknown: 'not reported yet' };

/**
 * A setup's progress, e.g. a new relay's onboarding: the title, how many of the steps are done with a progress bar
 * (Base UI Progress, through `Progress`), and the steps in order (`ChecklistItem`). Once every step is done the page
 * may keep it a while, with Hide in `actions`. A Panel, so it sits among the page's other surfaces.
 */
export function Checklist({ title, description, done, total, label, actions, children, className }: {
  title: ReactNode;
  description?: ReactNode;
  done: number;
  total: number;
  /** Beside the count, e.g. Hide on a finished setup. */
  actions?: ReactNode;
  /** Names the list and the bar for assistive technology, e.g. "Setup steps". */
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return <Panel title={title} description={description} className={className} actions={<span className="ui-checklist__head"><span className="ui-checklist__count">{done} of {total} done</span>{actions}</span>}>
    <div className="ui-checklist">
      <Progress value={done} max={total} label={`${label}: ${done} of ${total} done`} />
      <ol className="ui-checklist__list" aria-label={label}>{children}</ol>
    </div>
  </Panel>;
}

/**
 * One step. Its icon says its state (a check in a filled circle once done, an emphasised ring with its number for the
 * one to do now, a quiet ring for later ones, an error mark when it failed, a dashed ring when nothing reported it).
 * `detail` is one line of plain words: what turned it green, or what to do. A done step folds to one line; only the
 * current or a failed step carries an `action`, and `children`: what the step needs beyond one line (a command with
 * its code inside), under the title across the row. Screen readers hear the state after the title. The icons are
 * `Step`'s markers (ui.css), so a checklist and a timeline read alike. `tag` is a short label after the title that says
 * who moves the step on (a `Badge`: "Agent", "Gray").
 */
export function ChecklistItem({ state, number, title, tag, detail, action, children }: { state: ChecklistState; number: number; title: ReactNode; tag?: ReactNode; detail?: ReactNode; action?: ReactNode; children?: ReactNode }) {
  const icon = state === 'done' ? <Check size={13} weight="bold" aria-hidden="true" /> : state === 'failed' ? <X size={13} weight="bold" aria-hidden="true" /> : state === 'unknown' ? '?' : number;
  const open = state === 'current' || state === 'failed';
  return <li className={cx('ui-checklist__item', `ui-checklist__item--${state}`)} aria-current={state === 'current' ? 'step' : undefined}>
    <span className="ui-checklist__icon" aria-hidden="true">{icon}</span>
    <div className="ui-checklist__body">
      <span className="ui-checklist__title">{title}{tag && <span className="ui-checklist__tag">{tag}</span>}<span className="ui-sr-only"> ({STATE_WORDS[state]})</span></span>
      {detail && <span className="ui-checklist__detail">{detail}</span>}
    </div>
    {action && open && <div className="ui-checklist__action">{action}</div>}
    {children && open && <div className="ui-checklist__content">{children}</div>}
  </li>;
}
