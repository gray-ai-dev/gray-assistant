import { Meter as BaseMeter } from '@cloudflare/kumo/primitives/meter';
import { cx } from './cx';
import './meter.css';

/**
 * A short bar for a measure against a known maximum, e.g. a step's duration against the slowest step of the page.
 * Base UI Meter (through Kumo) owns the meter role and its values; `label` names the measure and `valueText` says the
 * value the way the page writes it ("2.31 s"). It is a picture of a figure the page also states in text. The width
 * comes from the page (5rem by default).
 */
export function Meter({ value, max, label, valueText, tone, size = 'sm', className }: {
  value: number;
  max: number;
  label: string;
  valueText?: string;
  /** `danger` for a measure of something that failed; `strong` an ink bar for a measure the row is about, e.g. a ranking weight. */
  tone?: 'danger' | 'strong';
  /** `sm` a 4px hairline beside a figure; `md` an 8px bar that stands for the figure (a `WeightBar`). */
  size?: 'sm' | 'md';
  className?: string;
}) {
  const top = max > 0 ? max : 1;
  return <BaseMeter.Root className={cx('ui-meter', className)} value={Math.min(Math.max(value, 0), top)} min={0} max={top}
    aria-label={label} aria-valuetext={valueText} data-tone={tone} data-size={size === 'sm' ? undefined : size}>
    <BaseMeter.Track className="ui-meter__track"><BaseMeter.Indicator className="ui-meter__bar" /></BaseMeter.Track>
  </BaseMeter.Root>;
}
