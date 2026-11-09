import { useRef, type ReactNode } from 'react';
import { Combobox } from '@cloudflare/kumo/primitives/combobox';
import { Check, X } from '../components/icons';
import { cx } from './cx';
import { usePopupPositionMethod } from './popup';
import { Tooltip } from './Tooltip';
import './select-field.css';
import './multi-select-field.css';

export type MultiSelectOption = {
  value: string;
  /** Text in the menu; also what the search matches by default. */
  label: string;
  /** Muted second line in the menu, e.g. an identifier. */
  detail?: string;
};

/** Several choices from a searchable list, shown as removable chips in a
 *  field the height of a TextInput. The menu is the SelectField menu. Kumo's
 *  Base UI Combobox owns selection, filtering and keyboard behaviour. */
export function MultiSelectField({ options, value, onValueChange, disabled, placeholder, emptyText = 'No options found.', chipText = option => option.label, filter, className, ...aria }: {
  options: readonly MultiSelectOption[];
  value: readonly string[];
  onValueChange: (next: string[]) => void;
  disabled?: boolean;
  placeholder?: string;
  /** Shown in the menu when nothing matches. */
  emptyText?: ReactNode;
  /** Text inside a chip; defaults to the label. */
  chipText?: (option: MultiSelectOption) => string;
  /** Replaces the default label match. */
  filter?: (option: MultiSelectOption, query: string) => boolean;
  className?: string;
  /** Accessible name of the search input; inside a `Field` the field label names it instead. */
  'aria-label'?: string;
}) {
  const anchor = useRef<HTMLDivElement>(null);
  const positionMethod = usePopupPositionMethod();
  const selected = options.filter(option => value.includes(option.value));
  return <Combobox.Root<MultiSelectOption, true> multiple items={options} value={selected} disabled={disabled}
    isItemEqualToValue={(a, b) => a.value === b.value} itemToStringLabel={option => option.label} itemToStringValue={option => option.value}
    filter={filter} onValueChange={(next, details) => {
      // Escape on a closed list would clear every chip; keep them. Chips still remove one at a time.
      if (details.reason !== 'escape-key') onValueChange(next.map(option => option.value));
    }}>
    <Combobox.Chips className={cx('ui-chips', className)} ref={anchor}>
      <Combobox.Value>{(current: MultiSelectOption[]) => <>
        {current.map(option => <Combobox.Chip key={option.value} className="ui-chip" aria-label={chipText(option)}>
          <Tooltip content={chipText(option) === option.label ? null : option.label}><span className="ui-chip__text">{chipText(option)}</span></Tooltip>
          <Combobox.ChipRemove className="ui-chip__remove" aria-label={`Remove ${chipText(option)}`}><X size={13} aria-hidden="true" /></Combobox.ChipRemove>
        </Combobox.Chip>)}
        <Combobox.Input className="ui-chips__input" placeholder={placeholder} aria-label={aria['aria-label']} {...(aria['aria-label'] ? { 'aria-labelledby': undefined } : null)} />
      </>}</Combobox.Value>
    </Combobox.Chips>
    <Combobox.Portal><Combobox.Positioner className="select-positioner" positionMethod={positionMethod} sideOffset={4} align="start" collisionPadding={8} anchor={anchor}>
      <Combobox.Popup className="select-popup">
        <Combobox.Empty className="select-empty">{emptyText}</Combobox.Empty>
        <Combobox.List className="select-list">{(option: MultiSelectOption) => <Combobox.Item key={option.value} className="select-option" value={option}>
          <span className="select-option-label">{option.label}{option.detail && <span className="ui-multi-select__detail">{option.detail}</span>}</span>
          <Combobox.ItemIndicator className="select-check"><Check size={14} aria-hidden="true" /></Combobox.ItemIndicator>
        </Combobox.Item>}</Combobox.List>
      </Combobox.Popup>
    </Combobox.Positioner></Combobox.Portal>
  </Combobox.Root>;
}
