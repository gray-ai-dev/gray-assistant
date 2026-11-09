import { lazy, Suspense, type ReactNode } from 'react';
import { CalendarBlank } from '../components/icons';
import { cx } from './cx';
import './date-time.css';

export type DateTimeFieldProps = {
  label: ReactNode;
  hideLabel?: boolean;
  /** Adds a muted "(optional)" after the label. */
  optional?: boolean;
  hint?: ReactNode;
  error?: ReactNode;
  value: number | null | undefined;
  onValueChange(value: number | null): void;
  /** Earliest and latest allowed moments, epoch milliseconds. */
  min?: number;
  max?: number;
  required?: boolean;
  disabled?: boolean;
  /** `day` for a date alone. */
  granularity?: 'day' | 'minute';
  className?: string;
};

const DateTimePicker = lazy(() => import('./DateTimePicker'));

/**
 * A date and time in the user's own time zone, as epoch milliseconds (`null` when empty). React Aria's DatePicker
 * (react-aria-components) owns the typed segments, the calendar popover, `min`/`max` and validation; the design system
 * draws it like a `Field` with a `TextInput`. It carries its own label, hint and error, so it is not wrapped in a
 * `Field`. Its code loads with the first date field a page shows; until then the same frame stands in its place.
 */
export function DateTimeField(props: DateTimeFieldProps) {
  const shell = <div className={cx('ui-field ui-date-field', props.className)} aria-busy="true">
    <div className={props.hideLabel ? undefined : 'ui-field__label-row'}><span className={props.hideLabel ? 'ui-sr-only' : 'ui-field__label'}>{props.label}</span></div>
    <div className="ui-date-field__group" data-disabled><span className="ui-date-field__input" /><span className="ui-date-field__button"><CalendarBlank size={16} aria-hidden="true" /></span></div>
    {props.hint && <p className="ui-field__hint">{props.hint}</p>}
  </div>;
  return <Suspense fallback={shell}><DateTimePicker {...props} /></Suspense>;
}
