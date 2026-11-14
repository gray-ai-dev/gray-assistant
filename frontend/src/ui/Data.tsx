import { Children, Fragment, isValidElement, type CSSProperties, type HTMLAttributes, type MouseEvent, type ReactNode, type TdHTMLAttributes, type ThHTMLAttributes } from 'react';
import { Collapsible } from '@cloudflare/kumo/primitives/collapsible';
import { Progress as BaseProgress } from '@cloudflare/kumo/primitives/progress';
import { ArrowDown, ArrowUp, CaretDown, Check, X } from '../components/icons';
import { Sparkline } from './Sparkline';
import './chart.css';
import { cx } from './cx';
import { Skeleton } from './Feedback';
import { InfoTip } from './InfoTip';
import { Tooltip } from './Tooltip';

/** Label/value pairs, e.g. request details. `compact` puts values at the right. */
export function DescriptionList({ items, compact, className, children }: {
  items?: ReadonlyArray<{ label: ReactNode; value: ReactNode; key?: string }>;
  compact?: boolean;
  className?: string;
  /** `DescriptionItem` children, when items need their own markup. */
  children?: ReactNode;
}) {
  return <dl className={cx('ui-description-list', compact && 'ui-description-list--compact', className)}>
    {items?.map((item, index) => <DescriptionItem key={item.key ?? index} label={item.label}>{item.value}</DescriptionItem>)}
    {children}
  </dl>;
}

export function DescriptionItem({ label, children }: { label: ReactNode; children: ReactNode }) {
  return <div className="ui-description-list__item"><dt>{label}</dt><dd>{children}</dd></div>;
}

/** How a figure moved against the previous period: `change` is a fraction (0.12 for 12% more), `better` says which way
 *  is good (spend going down is good, requests going up is good), `period` names what it is compared with. */
export type StatDelta = { change: number | null; better: 'up' | 'down' | 'neither'; period: string;
  /** `points` when `change` is a difference of two rates in percentage points (0.004 for +0.4 pt). */
  unit?: 'relative' | 'points' };

/** A headline number with its label, e.g. a balance. `delta` adds its change against the previous period, `trend` a
 *  sparkline of the same measure over the period. `loading` holds the value's place with a skeleton of its height while
 *  its own read is under way and the cards beside it already show theirs. */
export function Stat({ label, value, hint, size = 'md', delta, trend, loading, className }: { label: ReactNode; value: ReactNode; hint?: ReactNode; size?: 'md' | 'sm'; delta?: StatDelta; trend?: readonly number[]; loading?: boolean; className?: string }) {
  return <div className={cx('ui-stat', size === 'sm' && 'ui-stat--sm', className)}>
    <span className="ui-stat__label">{label}</span>
    {loading ? <Skeleton lines={1} label={typeof label === 'string' ? `Loading ${label.toLowerCase()}` : 'Loading'} className="ui-stat__skeleton" /> : <strong className="ui-stat__value">{value}</strong>}
    {delta && !loading && <StatChange delta={delta} />}
    {hint && <p className="ui-stat__hint">{hint}</p>}
    {trend && trend.length > 1 && <Sparkline className="ui-stat__trend" values={trend} />}
  </div>;
}

const percent = new Intl.NumberFormat('en-US', { style: 'percent', maximumFractionDigits: 1, signDisplay: 'exceptZero' });
const points = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 });
function StatChange({ delta }: { delta: StatDelta }) {
  // Nothing to compare with (no earlier data, or none yet): no line, rather than the same sentence on every card.
  if (delta.change == null || !Number.isFinite(delta.change)) return null;
  const up = delta.change > 0, flat = Math.abs(delta.change) < 0.0005;
  const tone = flat || delta.better === 'neither' ? undefined : (up === (delta.better === 'up')) ? 'good' : 'bad';
  const Arrow = up ? ArrowUp : ArrowDown;
  const amount = delta.unit === 'points' ? `${delta.change > 0 ? '+' : '−'}${points.format(Math.abs(delta.change) * 100)} pt` : percent.format(delta.change);
  return <span className="ui-stat__delta" data-tone={tone}>{!flat && <Arrow size={12} aria-hidden="true" />}{flat ? 'No change' : amount} {delta.period}</span>;
}

/** How many stats a group holds, the ones inside fragments counted each. */
function statCount(children: ReactNode): number {
  return Children.toArray(children).reduce<number>((sum, child) => sum + (isValidElement(child) && child.type === Fragment ? statCount((child.props as { children?: ReactNode }).children) : 1), 0);
}

/** Stats side by side; `cards` puts each on its own bordered surface, for a report's headline figures. */
export function StatGroup({ className, children, cards, style, ...rest }: HTMLAttributes<HTMLDivElement> & { cards?: boolean }) {
  // At most four a row, and rows as even as the count allows: six figures sit 3 + 3, not 5 + 1. A fragment's stats
  // count each (a page that groups two behind one condition has four figures, not three: 4 across, never 3 + 1).
  const count = statCount(children);
  const columns = Math.max(1, Math.ceil(count / Math.ceil(count / 4)));
  return <div className={cx('ui-stat-group', cards && 'ui-stat-group--cards', className)} style={{ '--stat-columns': columns, ...style } as CSSProperties} {...rest}>{children}</div>;
}

/** A data table in a bordered, horizontally scrolling frame. Compose it with
 *  `TableHead`, `TableBody`, `TableRow`, `TableHeaderCell` and `TableCell`. */
export function Table({ label, describedBy, caption, className, children, minWidth }: {
  /** Accessible name for the scroll region and table. */
  label?: string;
  /** Id of text that explains the table, e.g. a caveat under it. */
  describedBy?: string;
  caption?: ReactNode;
  className?: string;
  children: ReactNode;
  /** Minimum table width before the frame scrolls, e.g. '44rem'. */
  minWidth?: string;
}) {
  return <div className={cx('ui-table-wrap', className)} role="region" aria-label={label} aria-describedby={describedBy} tabIndex={0}>
    <table className="ui-table" aria-label={label} style={minWidth ? { minWidth } : undefined}>
      {children}
      {caption && <caption>{caption}</caption>}
    </table>
  </div>;
}

export function TableHead({ children }: { children: ReactNode }) { return <thead>{children}</thead>; }
export function TableBody({ children }: { children: ReactNode }) { return <tbody>{children}</tbody>; }
/** `inactive` marks a row whose item is switched off (a disabled key): a muted fill; say why in a cell, e.g. a `Badge`. */
/** A table row. With `href` a click anywhere on the row opens it, except on a control or link inside it or while text
 *  is being selected; keyboard users reach the same address through the row's own link, which the row must have. */
export function TableRow({ className, inactive, href, onClick, ...rest }: HTMLAttributes<HTMLTableRowElement> & { inactive?: boolean; href?: string }) {
  const open = href ? (event: MouseEvent<HTMLTableRowElement>) => {
    onClick?.(event);
    if (event.defaultPrevented || event.button !== 0 || (event.target as Element).closest('a, button, input, select, textarea, label, [role="button"]')) return;
    if (window.getSelection()?.toString()) return;
    if (event.metaKey || event.ctrlKey) window.open(href, '_blank', 'noopener');
    // A plain path of the app (a Provide page) opens in place, as its link does; anything else is a navigation.
    else if (href.startsWith('/') && !href.startsWith('//')) { history.pushState(null, '', href); window.dispatchEvent(new PopStateEvent('popstate')); }
    else location.assign(href);
  } : onClick;
  return <tr className={cx(inactive && 'ui-row--inactive', href && 'ui-row--link', className) || undefined} onClick={open} {...rest} />;
}

type CellLook = {
  /** `numeric` right-aligns figures; `actions` right-aligns and shrinks to its buttons; `menu` holds a row's
   *  action `Menu` and, in a `StackedTable` card on a phone, sits in the card's top corner. */
  kind?: 'text' | 'numeric' | 'actions' | 'menu';
  nowrap?: boolean;
  top?: boolean;
  /** In a `StackedTable` card on a phone, takes the card's full width, e.g. a status with a sentence under it. */
  wide?: boolean;
  /** Lets a long numeric header wrap so its column is as narrow as its figures, e.g. "Requests for model, 24 h". */
  wrap?: boolean;
};
const cellClass = ({ kind = 'text', nowrap, top, wide, wrap }: CellLook, className?: string) => cx(kind !== 'text' && `ui-cell--${kind}`, nowrap && 'ui-cell--nowrap', top && 'ui-cell--top', wide && 'ui-cell--wide', wrap && 'ui-cell--wrap', className) || undefined;

/** `title` on a header cell defines the column (an `InfoTip`: the header text opens it on hover, tap or Enter). On a
 *  body cell it is a tooltip, e.g. the full timestamp behind a short one. */
export function TableHeaderCell({ kind, nowrap, top, wide, wrap, className, scope = 'col', title, children, ...rest }: CellLook & ThHTMLAttributes<HTMLTableCellElement>) {
  return <th scope={scope} className={cellClass({ kind, nowrap, top, wide, wrap }, className)} {...rest}>{title ? <InfoTip term={children}>{title}</InfoTip> : children}</th>;
}
export function TableCell({ kind, nowrap, top, wide, wrap, className, title, ...rest }: CellLook & TdHTMLAttributes<HTMLTableCellElement>) {
  return <Tooltip content={title}><td className={cellClass({ kind, nowrap, top, wide, wrap }, className)} {...rest} /></Tooltip>;
}

/** Show-more content behind a summary line. Base UI Collapsible (through Kumo) owns the button, its expanded state
 *  and the panel's height while it opens and closes; a closed panel stays in the page, so find-in-page opens it.
 *  Uncontrolled by default (`defaultOpen`); pass `open` and `onOpenChange` when the page decides. */
export function Disclosure({ summary, children, plain, className, open, defaultOpen, onOpenChange }: {
  summary: ReactNode;
  children?: ReactNode;
  /** No rule above the summary. */
  plain?: boolean;
  className?: string;
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange?(open: boolean): void;
}) {
  return <Collapsible.Root className={cx('ui-disclosure', plain && 'ui-disclosure--plain', className)} open={open} defaultOpen={defaultOpen} onOpenChange={next => onOpenChange?.(next)}>
    <Collapsible.Trigger className="ui-disclosure__summary">{summary}<CaretDown className="ui-disclosure__chevron" size={14} aria-hidden="true" /></Collapsible.Trigger>
    <Collapsible.Panel className="ui-disclosure__panel" hiddenUntilFound><div className="ui-disclosure__body">{children}</div></Collapsible.Panel>
  </Collapsible.Root>;
}

/** A vertical list of rows with dividers (`plain` drops them). */
export function List({ plain, className, children, ordered, 'aria-label': label }: { plain?: boolean; className?: string; children: ReactNode; ordered?: boolean; 'aria-label'?: string }) {
  const Tag = ordered ? 'ol' : 'ul';
  return <Tag className={cx('ui-list', plain && 'ui-list--plain', className)} aria-label={label}>{children}</Tag>;
}

/** Numbered steps to follow in order, e.g. setting up a tool or a first-run checklist. */
export function Steps({ className, children, 'aria-label': label }: { className?: string; children: ReactNode; 'aria-label'?: string }) {
  return <ol className={cx('ui-steps', className)} aria-label={label}>{children}</ol>;
}
/** Where a step is: `done` (a check), `current` (in progress, its number in an accent ring), `failed` (a cross), `pending` (not reached, muted). */
export type StepState = 'done' | 'current' | 'failed' | 'pending';
const STEP_STATE_TEXT: Readonly<Record<StepState, string>> = { done: 'done', current: 'in progress', failed: 'failed', pending: 'not reached yet' };

/**
 * One step: its number (a check once done), a title, what to do (`children`) and an optional action at the end,
 * which moves under the text on phones; `aside` is a short fact at the end of the row that stays there (the moment the
 * step was reached). `state` says where a step of something under way is, e.g. a VM's start-up: done, current, failed
 * or pending; `done` is the short form for a checklist. The marker is the Checklist's, so a step reads the same in
 * both. Screen readers hear the state after the title.
 */
export function Step({ title, done, state, actions, aside, children }: { title: ReactNode; done?: boolean; state?: StepState; actions?: ReactNode; aside?: ReactNode; children?: ReactNode }) {
  const s = state ?? (done ? 'done' : undefined);
  return <li className={cx('ui-step', s && `ui-step--${s}`)} aria-current={s === 'current' ? 'step' : undefined}>
    <span className="ui-step__marker" aria-hidden="true">{s === 'done' ? <Check size={13} weight="bold" /> : s === 'failed' ? <X size={13} weight="bold" /> : null}</span>
    <div className="ui-step__body">
      <span className="ui-step__title">{title}{s && s !== 'pending' && <span className="ui-sr-only"> ({STEP_STATE_TEXT[s]})</span>}</span>
      {children}
    </div>
    {aside != null && aside !== false && <span className="ui-step__aside">{aside}</span>}
    {actions && <div className="ui-step__actions">{actions}</div>}
  </li>;
}

/** A thin progress bar, e.g. budget used. Without a value it shows activity of unknown length. Base UI Progress
 *  (through Kumo) owns the progressbar role and its values, announced as a percentage of `max`. */
export function Progress({ value, max = 1, label }: { value?: number | null; max?: number; label: string }) {
  const known = value != null && Number.isFinite(value);
  const percent = known && max > 0 ? Math.min(100, Math.max(0, (value / max) * 100)) : 0;
  return <BaseProgress.Root className="ui-progress" value={known ? percent : null} aria-label={label}>
    <BaseProgress.Track className="ui-progress__track"><BaseProgress.Indicator className="ui-progress__bar" /></BaseProgress.Track>
  </BaseProgress.Root>;
}
