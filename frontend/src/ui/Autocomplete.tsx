import { Autocomplete } from '@cloudflare/kumo/primitives/autocomplete';
import type { InputHTMLAttributes } from 'react';
import { cx } from './cx';
import { usePopupPositionMethod } from './popup';
import './select-field.css';

/** One suggestion: the value the input takes, and an optional muted label beside it (e.g. a display name). */
export type Suggestion = { value: string; label?: string };

/**
 * A free-text input that suggests values as you type: a model ID, a host name. Unlike `SelectField`, any text is
 * accepted; a suggestion only fills the input. The page passes the suggestions to show for the current text
 * (`suggestions`), already filtered and capped. Base UI Autocomplete (through Kumo) owns the listbox, keyboard and
 * focus; the input looks like `TextInput` and takes a `Field`'s label, hint and error.
 */
export function AutocompleteInput({ value, onValueChange, suggestions, mono, className, id, required, disabled, placeholder, emptyText, ...rest }: Omit<InputHTMLAttributes<HTMLInputElement>, 'value' | 'onChange' | 'defaultValue' | 'size'> & {
  value: string;
  onValueChange(value: string): void;
  suggestions: readonly Suggestion[];
  /** Monospace text, for identifiers. */
  mono?: boolean;
  /** Shown in the open list when nothing matches; the list stays closed without it. */
  emptyText?: string;
}) {
  const positionMethod = usePopupPositionMethod();
  return <Autocomplete.Root items={suggestions} filteredItems={suggestions} value={value} onValueChange={next => onValueChange(next)}
    itemToStringValue={(item: Suggestion) => item.value} disabled={disabled} required={required}>
    <Autocomplete.Input className={cx('ui-input', mono && 'ui-input--mono', className)} placeholder={placeholder} autoComplete="off" spellCheck={false}
      id={id} {...rest} />
    <Autocomplete.Portal><Autocomplete.Positioner className="select-positioner" positionMethod={positionMethod} sideOffset={4} align="start" collisionPadding={8}>
      <Autocomplete.Popup className="select-popup">
        {emptyText && <Autocomplete.Empty className="select-empty">{emptyText}</Autocomplete.Empty>}
        <Autocomplete.List className="select-list">{(item: Suggestion) => <Autocomplete.Item key={item.value} value={item} className="select-option ui-suggestion">
          <span className={cx('select-option-label', mono && 'ui-suggestion__mono')}>{item.value}</span>
          {item.label && <span className="ui-suggestion__label">{item.label}</span>}
        </Autocomplete.Item>}</Autocomplete.List>
      </Autocomplete.Popup>
    </Autocomplete.Positioner></Autocomplete.Portal>
  </Autocomplete.Root>;
}
