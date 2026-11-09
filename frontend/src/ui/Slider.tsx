import { Slider as BaseSlider } from '@cloudflare/kumo/primitives/slider';
import { cx } from './cx';
import './slider.css';

/**
 * A number picked from a short range where the position matters more than the digits, e.g. a temperature from 0 to 2.
 * Base UI Slider (through Kumo) owns dragging, the arrow, Page and Home/End keys and the range input assistive
 * technology reads; the current value is written beside the track. Like `NumberInput` it speaks text: `value` and
 * `onValueChange` carry the number as form state holds it. Inside a `Field` the field's label names it.
 */
export function Slider({ value, onValueChange, min = 0, max = 100, step = 1, disabled, format, className, ...aria }: {
  value: string | number;
  onValueChange(value: string): void;
  min?: number;
  max?: number;
  step?: number;
  disabled?: boolean;
  /** How the value beside the track is written, e.g. `{ minimumFractionDigits: 1 }`. */
  format?: Intl.NumberFormatOptions;
  className?: string;
  'aria-label'?: string;
}) {
  const number = Number(value);
  return <BaseSlider.Root className={cx('ui-slider', className)} value={value !== '' && Number.isFinite(number) ? number : min} onValueChange={next => onValueChange(String(next))}
    min={min} max={max} step={step} disabled={disabled} format={format} locale="en-US">
    <BaseSlider.Control className="ui-slider__control">
      <BaseSlider.Track className="ui-slider__track">
        <BaseSlider.Indicator className="ui-slider__fill" />
        <BaseSlider.Thumb className="ui-slider__thumb" aria-label={aria['aria-label']} />
      </BaseSlider.Track>
    </BaseSlider.Control>
    <BaseSlider.Value className="ui-slider__value" />
  </BaseSlider.Root>;
}
