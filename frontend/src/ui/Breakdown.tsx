import type { ReactNode } from 'react';
import { Meter } from '@cloudflare/kumo/primitives/meter';
import { cx } from './cx';
import './chart.css';

export type BreakdownItem = { key: string; label: ReactNode; value: number; detail?: ReactNode; href?: string;
  /** A row whose value rests on too little to compare, e.g. a model with a handful of requests: drawn quieter. */
  muted?: boolean;
  /** The value as text, when `format` cannot say it alone (e.g. "2.1 s" for a value in milliseconds). */
  valueText?: string };

/**
 * Where a total comes from, largest first: each row a label, its value, its share of the total and a bar of that
 * share (Base UI Meter). Past `limit` rows the rest is one "Other" row, so the list stays short.
 *
 * With `scale="max"` it ranks a measure that is not part of a total (a speed, a latency, a rate): each bar is the
 * value against the largest, no share is shown and rows past `limit` are left out.
 */
export function Breakdown({ label, items, format = n => n.toLocaleString('en-US'), limit = 6, restLabel = 'Other', empty = 'Nothing in this period.', tone, scale = 'share', className }: {
  /** What the values are, e.g. "Spend by model". */
  label: string;
  items: readonly BreakdownItem[];
  format?: (value: number) => string;
  limit?: number;
  restLabel?: string;
  empty?: ReactNode;
  /** `danger` for what went wrong, e.g. failures by category. */
  tone?: 'danger';
  /** `share` of the total (the default) or against the largest value (`max`). */
  scale?: 'share' | 'max';
  className?: string;
}) {
  const sorted = [...items].filter(item => item.value > 0).sort((a, b) => b.value - a.value);
  const ranked = scale === 'max';
  const total = sorted.reduce((sum, item) => sum + item.value, 0), largest = sorted[0]?.value ?? 0;
  const shown = ranked ? sorted.slice(0, limit) : sorted.length > limit ? sorted.slice(0, limit - 1) : sorted;
  const rest = !ranked && sorted.length > limit ? sorted.slice(limit - 1).reduce((sum, item) => sum + item.value, 0) : 0;
  const rows = rest > 0 ? [...shown, { key: '__rest', label: `${restLabel} · ${sorted.length - shown.length}`, value: rest } as BreakdownItem] : shown;
  const percent = (value: number) => total > 0 ? Math.round((value / total) * 1000) / 10 : 0;
  const bar = (value: number) => ranked ? (largest > 0 ? Math.round((value / largest) * 1000) / 10 : 0) : percent(value);
  const text = (item: BreakdownItem) => item.valueText ?? format(item.value);
  return <section className={cx('ui-breakdown-section', className)} aria-label={label} data-tone={tone}>
    <div className="ui-breakdown">
      <span className="ui-breakdown__head">{label}</span>
      {!rows.length ? <span className="ui-breakdown__detail">{empty}</span> : rows.map(item => <Meter.Root key={item.key} className="ui-breakdown__row" value={bar(item.value)} data-rest={item.key === '__rest' || undefined} data-muted={item.muted || undefined}
        aria-label={`${typeof item.label === 'string' ? item.label : ''} ${text(item)}${ranked ? '' : `, ${percent(item.value)}% of ${label.toLowerCase()}`}`.trim()}>
        <span className="ui-breakdown__label">{item.href ? <a href={item.href}>{item.label}</a> : item.label}</span>
        <span className="ui-breakdown__value">{text(item)}{!ranked && <span className="ui-breakdown__share">{percent(item.value)}%</span>}</span>
        <Meter.Track className="ui-breakdown__meter ui-breakdown__track"><Meter.Indicator className="ui-breakdown__bar" /></Meter.Track>
        {item.detail != null && <span className="ui-breakdown__detail">{item.detail}</span>}
      </Meter.Root>)}
    </div>
  </section>;
}
