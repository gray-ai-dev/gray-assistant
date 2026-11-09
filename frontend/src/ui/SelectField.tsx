import { Children, Fragment, isValidElement, useMemo, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { Field as BaseField } from '@cloudflare/kumo/primitives/field';
import { Select } from '@cloudflare/kumo/primitives/select';
import { Combobox } from '@cloudflare/kumo/primitives/combobox';
import { CaretDown, Check, MagnifyingGlass } from '../components/icons';
import { useInsideField } from './Field';
import { usePopupPositionMethod } from './popup';
import './select-field.css';

type Choice = { value: string; label: string; disabled: boolean };
type ChoiceGroup = { label: string; items: Choice[] };
type SelectFieldProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'value' | 'defaultValue' | 'onChange' | 'children' | 'type'> & {
  value?: string | number;
  defaultValue?: string | number;
  onValueChange?: (value: string) => void;
  children: ReactNode;
  required?: boolean;
  autoComplete?: string;
  searchable?: boolean;
  searchPlaceholder?: string;
};

function optionText(node: ReactNode): string {
  return Children.toArray(node).map(child => isValidElement<{ children?: ReactNode }>(child)
    ? optionText(child.props.children) : String(child)).join('');
}

// Keep option values and optgroup semantics at existing form call sites. Kumo's
// Base UI primitives own selection, filtering, positioning and keyboard behavior.
function choiceGroups(children: ReactNode): ChoiceGroup[] {
  const groups: ChoiceGroup[] = [];
  const append = (nodes: ReactNode, label = '', disabled = false) => {
    Children.forEach(nodes, child => {
      if (!isValidElement<{ children?: ReactNode; value?: string | number; label?: string; disabled?: boolean }>(child)) return;
      if (child.type === Fragment) { append(child.props.children, label, disabled); return; }
      if (child.type === 'optgroup') { append(child.props.children, child.props.label || '', disabled || !!child.props.disabled); return; }
      if (child.type !== 'option') return;
      const text = child.props.label ?? optionText(child.props.children);
      let group = groups.at(-1);
      if (!group || group.label !== label) { group = { label, items: [] }; groups.push(group); }
      group.items.push({ value: String(child.props.value ?? optionText(child.props.children)), label: text, disabled: disabled || !!child.props.disabled });
    });
  };
  append(children);
  return groups;
}

export function SelectField({ value, defaultValue, onValueChange, children, required, disabled, name, form, autoComplete, searchable, searchPlaceholder = 'Search options…', className = '', id, ...triggerProps }: SelectFieldProps) {
  const groups = useMemo(() => choiceGroups(children), [children]);
  const options = groups.flatMap(group => group.items);
  const [localValue, setLocalValue] = useState(() => String(defaultValue ?? options[0]?.value ?? ''));
  const current = value === undefined ? localValue : String(value);
  const selected = options.find(option => option.value === current);
  const searchEnabled = searchable ?? options.length > 10;
  const [query, setQuery] = useState('');
  const search = useRef<HTMLInputElement>(null);
  const insideField = useInsideField();
  const positionMethod = usePopupPositionMethod();

  function change(next: string) {
    if (!options.some(option => option.value === next && !option.disabled)) return;
    setLocalValue(next);
    onValueChange?.(next);
  }
  const triggerContent = <><span className="select-value">{selected?.label ?? current}</span><CaretDown size={14} aria-hidden="true" /></>;
  const common = { id, name, form, required, disabled, autoComplete };
  // An explicit name on the trigger wins over the field's label.
  const triggerAttributes = { ...triggerProps, ...(triggerProps['aria-label'] ? { 'aria-labelledby': undefined } : null), className: `select-trigger ${className}`.trim() };
  const renderComboItem = (option: Choice) => <Combobox.Item key={option.value} className="select-option" value={option} disabled={option.disabled}>
    <span className="select-option-label">{option.label}</span><Combobox.ItemIndicator className="select-check"><Check size={14} aria-hidden="true" /></Combobox.ItemIndicator>
  </Combobox.Item>;

  const control = searchEnabled ? <Combobox.Root<Choice> {...common} items={groups} value={selected ?? null}
      isItemEqualToValue={(a, b) => a.value === b.value} itemToStringLabel={option => option.label} itemToStringValue={option => option.value}
      inputValue={query} onInputValueChange={setQuery} onValueChange={option => { if (option) change(option.value); }}
      onOpenChange={next => { if (next) setQuery(''); }}>
      <Combobox.Trigger {...triggerAttributes}>{triggerContent}</Combobox.Trigger>
      <Combobox.Portal><Combobox.Positioner className="select-positioner" positionMethod={positionMethod} sideOffset={4} align="start" collisionPadding={8}>
        <Combobox.Popup className="select-popup" initialFocus={search}>
          <div className="select-search"><MagnifyingGlass size={16} aria-hidden="true" /><Combobox.Input ref={search} className="select-search-input" placeholder={searchPlaceholder} aria-label={searchPlaceholder.replace(/…$/, '')} aria-labelledby={undefined} /></div>
          <Combobox.Empty className="select-empty">No options found.</Combobox.Empty>
          <Combobox.List className="select-list">{(group: ChoiceGroup) => <Combobox.Group key={group.label} items={group.items}>
            {group.label && <Combobox.GroupLabel className="select-group-label">{group.label}</Combobox.GroupLabel>}
            <Combobox.Collection>{renderComboItem}</Combobox.Collection>
          </Combobox.Group>}</Combobox.List>
        </Combobox.Popup>
      </Combobox.Positioner></Combobox.Portal>
    </Combobox.Root> : <Select.Root<string> {...common} items={options} value={current} modal={false}
      onValueChange={next => { if (next !== null) change(next); }}>
      <Select.Trigger {...triggerAttributes}>{triggerContent}</Select.Trigger>
      <Select.Portal><Select.Positioner className="select-positioner" positionMethod={positionMethod} sideOffset={4} align="start" collisionPadding={8} alignItemWithTrigger={false}>
        <Select.Popup className="select-popup"><Select.List className="select-list">
          {groups.map((group, index) => <Select.Group key={`${group.label}-${index}`}>
            {group.label && <Select.GroupLabel className="select-group-label">{group.label}</Select.GroupLabel>}
            {group.items.map(option => <Select.Item key={option.value} className="select-option" value={option.value} disabled={option.disabled}>
              <Select.ItemText className="select-option-label">{option.label}</Select.ItemText><Select.ItemIndicator className="select-check"><Check size={14} aria-hidden="true" /></Select.ItemIndicator>
            </Select.Item>)}
          </Select.Group>)}
        </Select.List></Select.Popup>
      </Select.Positioner></Select.Portal>
    </Select.Root>;
  // Outside a `Field` it is a field of its own, so a disabled `Fieldset` still locks it.
  return insideField ? <span className="select-field">{control}</span> : <BaseField.Root className="select-field" render={<span />}>{control}</BaseField.Root>;
}
