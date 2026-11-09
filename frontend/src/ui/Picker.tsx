import { useMemo, useRef, useState, type ReactNode } from 'react';
import { Combobox } from '@cloudflare/kumo/primitives/combobox';
import { CaretDown, Check, MagnifyingGlass } from '../components/icons';
import { cx } from './cx';
import { usePopupPositionMethod } from './popup';
import './select-field.css';
import './picker.css';

export type PickerChoice = {
  value: string;
  /** The name in the trigger and the list. The default search matches it and the value. */
  label: string;
  /** Muted second line, e.g. an exact ID and a price. */
  detail?: ReactNode;
  /** Muted note at the end of the row, e.g. a provider count. */
  meta?: ReactNode;
};

const includes = (choice: PickerChoice, query: string) => `${choice.label} ${choice.value}`.toLowerCase().includes(query.trim().toLowerCase());

/**
 * One choice from a long list with a detail per option, e.g. a model with its ID, price and provider count: the
 * SelectField trigger opens a search row over a capped list. The page says what matches (`match`), which match
 * comes first (`rank`) and how many rows to show (`limit`); Base UI Combobox (through Kumo) owns the popup, focus,
 * keyboard and listbox. `open` and `onOpenChange` let another control open it, e.g. "Choose another model".
 * Inside a `Field` the trigger takes the field's label, hint and disabled state (Base UI Field). Prefer SelectField
 * when it fits.
 */
export function Picker({ choices, value, onValueChange, open, onOpenChange, valueText, placeholder = 'Choose…', searchPlaceholder = 'Search…', searchLabel, popupLabel,
  match = includes, rank, limit = 80, emptyText = 'No matches.', noun = 'options', disabled, className, popupClassName, id, ...aria }: {
  /** Every choice, in the order to list them. */
  choices: readonly PickerChoice[];
  value: string;
  onValueChange(value: string): void;
  open?: boolean;
  onOpenChange?(open: boolean): void;
  /** Text in the trigger for the current value; defaults to its label, e.g. for a value that is no longer a choice. */
  valueText?: string;
  /** Text in the trigger with no value. */
  placeholder?: string;
  searchPlaceholder?: string;
  /** Accessible name of the search input; defaults to the placeholder. */
  searchLabel?: string;
  /** Names the popup, e.g. "Choose another model". */
  popupLabel: string;
  /** Whether a choice fits the search text. Pass a stable function. */
  match?: (choice: PickerChoice, query: string) => boolean;
  /** Orders the matches of a search, lower first; ties keep the list order. Pass a stable function. */
  rank?: (choice: PickerChoice, query: string) => number;
  /** The most rows to show; a note under the list says how many more match. */
  limit?: number;
  /** Shown when nothing matches; receives the trimmed search text. */
  emptyText?: ReactNode | ((query: string) => ReactNode);
  /** What the choices are, for the note under a capped list: "Showing 80 of 312 models." */
  noun?: string;
  disabled?: boolean;
  /** On the trigger. */
  className?: string;
  /** On the popup, e.g. a page class with a wider minimum. */
  popupClassName?: string;
  id?: string;
  'aria-label'?: string;
  'aria-describedby'?: string;
}) {
  const [ownOpen, setOwnOpen] = useState(false), [query, setQuery] = useState('');
  const positionMethod = usePopupPositionMethod();
  const isOpen = open ?? ownOpen;
  // Every opening starts a fresh search, whichever control opened it.
  const [wasOpen, setWasOpen] = useState(isOpen);
  if (isOpen !== wasOpen) { setWasOpen(isOpen); if (isOpen) setQuery(''); }
  const search = useRef<HTMLInputElement>(null);
  const selected = choices.find(choice => choice.value === value) ?? null;
  const term = query.trim();
  const matches = useMemo(() => {
    const found = choices.filter(choice => match(choice, term));
    if (!rank || !term) return found;
    return found.map((choice, order) => ({ choice, order, rank: rank(choice, term) })).sort((a, b) => a.rank - b.rank || a.order - b.order).map(entry => entry.choice);
  }, [choices, match, rank, term]);
  const shown = useMemo(() => {
    const rows = matches.slice(0, limit);
    // Opening the list must not hide the current choice behind the cap.
    if (!term && selected && rows.length === limit && !rows.includes(selected) && matches.includes(selected)) rows[limit - 1] = selected;
    return rows;
  }, [matches, limit, term, selected]);
  const all = useMemo(() => [...choices], [choices]);

  return <Combobox.Root<PickerChoice> items={all} filteredItems={shown} value={selected} disabled={disabled} autoHighlight
    isItemEqualToValue={(a, b) => a.value === b.value} itemToStringLabel={choice => choice.label} itemToStringValue={choice => choice.value}
    inputValue={query} onInputValueChange={setQuery} onValueChange={choice => { if (choice) onValueChange(choice.value); }}
    open={isOpen} onOpenChange={next => { setOwnOpen(next); onOpenChange?.(next); }}>
    {/* An explicit name on the trigger wins over the field's label. */}
    <Combobox.Trigger className={cx('select-trigger', className)} id={id} {...aria} {...(aria['aria-label'] ? { 'aria-labelledby': undefined } : null)}>
      <span className="select-value">{valueText ?? selected?.label ?? (value || placeholder)}</span><CaretDown size={14} aria-hidden="true" />
    </Combobox.Trigger>
    <Combobox.Portal><Combobox.Positioner className="select-positioner" positionMethod={positionMethod} sideOffset={4} align="start" collisionPadding={8}>
      <Combobox.Popup className={cx('select-popup', popupClassName)} aria-label={popupLabel} initialFocus={search}>
        <div className="select-search"><MagnifyingGlass size={16} aria-hidden="true" /><Combobox.Input ref={search} className="select-search-input" placeholder={searchPlaceholder} aria-label={searchLabel ?? searchPlaceholder.replace(/…$/, '')} aria-labelledby={undefined} /></div>
        <Combobox.Empty className="select-empty">{typeof emptyText === 'function' ? emptyText(term) : emptyText}</Combobox.Empty>
        <Combobox.List className="select-list">{(choice: PickerChoice) => <Combobox.Item key={choice.value} value={choice} className="select-option ui-picker__option">
          <span className="ui-picker__option-text"><span className="ui-picker__option-label">{choice.label}</span>{choice.detail != null && <span className="ui-picker__option-detail">{choice.detail}</span>}</span>
          {choice.meta != null && <span className="ui-picker__option-meta">{choice.meta}</span>}
          <Combobox.ItemIndicator className="select-check"><Check size={14} aria-hidden="true" /></Combobox.ItemIndicator>
        </Combobox.Item>}</Combobox.List>
        {matches.length > shown.length && <p className="ui-picker__note">Showing {shown.length} of {matches.length} {noun}. Search to narrow the list.</p>}
      </Combobox.Popup>
    </Combobox.Positioner></Combobox.Portal>
  </Combobox.Root>;
}
