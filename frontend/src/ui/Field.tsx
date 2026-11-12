import { createContext, forwardRef, useContext, useState, type InputHTMLAttributes, type ReactNode, type TextareaHTMLAttributes } from 'react';
import { Field as BaseField } from '@cloudflare/kumo/primitives/field';
import { Input as BaseInput } from '@cloudflare/kumo/primitives/input';
import { NumberField as BaseNumberField } from '@cloudflare/kumo/primitives/number-field';
import { MagnifyingGlass } from '../components/icons';
import { cx } from './cx';
import { compactsCleanly } from './number';

export type FieldProps = {
  label: ReactNode;
  /** Keeps the label for assistive technology only. */
  hideLabel?: boolean;
  /** Adds a muted "(optional)" after the label. */
  optional?: boolean;
  /** Muted text at the right of the label row, e.g. a counter or unit. */
  aside?: ReactNode;
  /** Helper text under the control. */
  hint?: ReactNode;
  /** Error text under the control; also marks the control invalid. */
  error?: ReactNode;
  disabled?: boolean;
  className?: string;
  /** Exactly one control: TextInput, TextArea, NumberInput, SearchInput, SelectField, Picker, Slider… */
  children: ReactNode;
};

const InsideField = createContext(false);
/** Whether a control sits inside a `Field`. One that does not wraps itself in a Base UI field of its own, so it still
 *  follows a disabled `Fieldset`. */
export const useInsideField = () => useContext(InsideField);

/** Label, control, hint and error in one column. Base UI Field (through Kumo) names and describes the control inside
 *  it, marks it invalid and disables it; every `ui` control picks that up without wiring at the call site. The label
 *  is not a native `label`: clicking it focuses the control, and never opens a select's menu. */
export function Field({ label, hideLabel, optional, aside, hint, error, disabled, className, children }: FieldProps) {
  return <InsideField.Provider value>
    <BaseField.Root className={cx('ui-field', className)} disabled={disabled} invalid={error ? true : undefined}>
      <div className={hideLabel ? undefined : 'ui-field__label-row'}>
        <BaseField.Label nativeLabel={false} render={<div />} className={hideLabel ? 'ui-sr-only' : 'ui-field__label'}>
          {label}{optional && <>{' '}<span className="ui-field__optional">(optional)</span></>}
        </BaseField.Label>
        {aside != null && !hideLabel && <span className="ui-field__aside">{aside}</span>}
      </div>
      {children}
      {hint && <BaseField.Description className="ui-field__hint">{hint}</BaseField.Description>}
      {error && <BaseField.Error match className="ui-field__error" role="alert">{error}</BaseField.Error>}
    </BaseField.Root>
  </InsideField.Provider>;
}

export type TextInputProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'size'> & {
  /** `display` takes the surrounding type (a heading-sized search line); `blank` is a filled gap inside display
   *  type, one line tall, for a sentence whose missing word is the input. */
  size?: 'sm' | 'md' | 'display' | 'blank';
  /** Monospace text for identifiers, keys and addresses. */
  mono?: boolean;
};

/** Single-line text input (Base UI Input). Use inside `Field`, or give it an `aria-label`. A `mono`, `url` or `email`
 *  input is `translate="no"`, so the browser's page translation leaves its placeholder (a model ID, an address) as
 *  written; pass `translate="no"` for another input whose placeholder is a name or an ID. */
export const TextInput = forwardRef<HTMLInputElement, TextInputProps>(function TextInput({ size = 'md', mono, className, type = 'text', defaultValue, translate, ...rest }, ref) {
  // An identifier or an address, and its placeholder, stay as written under the browser's page translation.
  const keep = translate ?? (mono || type === 'url' || type === 'email' ? 'no' : undefined);
  return <BaseInput ref={ref} type={type} className={cx('ui-input', size !== 'md' && `ui-input--${size}`, mono && 'ui-input--mono', className)}
    defaultValue={defaultValue as string | number | string[] | undefined} translate={keep} {...rest} />;
});

const compactExact: Intl.NumberFormatOptions = { notation: 'compact', maximumSignificantDigits: 21 };
const grouped: Intl.NumberFormatOptions = { maximumFractionDigits: 20 };
const LOCALE = 'en-US';

export type NumberInputProps = {
  /** The number as form state holds it: text, '' when empty. */
  value: string | number;
  /** The new number as text, '' when the field is emptied. */
  onValueChange?: (value: string) => void;
  min?: number | string;
  max?: number | string;
  step?: number | string;
  size?: 'sm' | 'md';
  required?: boolean;
  disabled?: boolean;
  placeholder?: string;
  name?: string;
  id?: string;
  className?: string;
  autoFocus?: boolean;
  'aria-label'?: string;
  'aria-describedby'?: string;
};

/**
 * A number (Base UI NumberField): digits only, arrow keys step by `step`, tabular figures. At rest it reads as
 * `formatCount` writes it: a large round number short ("1M", "2.5K", "1T"), any other with thousands separators
 * ("32,768"). While it has focus it is always the complete number, because compact text cannot be parsed back. A value outside `min`–`max` stays as
 * typed, so the page's own validation can name the range.
 */
export const NumberInput = forwardRef<HTMLInputElement, NumberInputProps>(function NumberInput({ value, onValueChange, min, max, step, size = 'md', required, disabled, placeholder, name, id, className, autoFocus, ...aria }, ref) {
  const [focused, setFocused] = useState(false);
  const number = value === '' || value == null || !Number.isFinite(Number(value)) ? null : Number(value);
  const bound = (limit: number | string | undefined) => limit === undefined || limit === '' ? undefined : Number(limit);
  return <BaseNumberField.Root value={number} onValueChange={next => onValueChange?.(next === null ? '' : String(next))} min={bound(min)} max={bound(max)} step={bound(step) ?? 1}
    allowOutOfRange locale={LOCALE} format={!focused && number !== null && compactsCleanly(number) ? compactExact : grouped} required={required} disabled={disabled} name={name} id={id}>
    <BaseNumberField.Input ref={ref} className={cx('ui-input ui-input--number', size === 'sm' && 'ui-input--sm', className)} placeholder={placeholder} autoFocus={autoFocus}
      onFocus={() => setFocused(true)} onBlur={() => setFocused(false)} {...aria} />
  </BaseNumberField.Root>;
});

/** Text input with a leading search icon. */
export const SearchInput = forwardRef<HTMLInputElement, TextInputProps>(function SearchInput({ className, size, ...rest }, ref) {
  return <span className={cx('ui-input-group', size === 'display' && 'ui-input-group--display', className)}><MagnifyingGlass size={16} aria-hidden="true" /><TextInput ref={ref} type="search" size={size} {...rest} /></span>;
});

export type TextAreaProps = TextareaHTMLAttributes<HTMLTextAreaElement> & {
  /** Larger type and padding for the main prompt or document editor. */
  size?: 'md' | 'lg';
  mono?: boolean;
};

/** Multi-line text: a native textarea that Base UI's field control names, describes and marks invalid. */
export const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(function TextArea({ size = 'md', mono, className, ...rest }, ref) {
  return <BaseField.Control render={<textarea ref={ref} className={cx('ui-textarea', size === 'lg' && 'ui-textarea--lg', mono && 'ui-textarea--mono', className)} {...rest} />} />;
});
