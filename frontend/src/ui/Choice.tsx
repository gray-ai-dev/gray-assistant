import type { ReactNode } from 'react';
import { Field as BaseField } from '@cloudflare/kumo/primitives/field';
import { Checkbox as BaseCheckbox } from '@cloudflare/kumo/primitives/checkbox';
import { Switch as BaseSwitch } from '@cloudflare/kumo/primitives/switch';
import { Check, Minus } from '../components/icons';
import { cx } from './cx';

type ChoiceProps = {
  /** Visible label. It wraps the control, so clicking it toggles. */
  label: ReactNode;
  /** Muted second line under the label; read as the control's description. */
  description?: ReactNode;
  checked?: boolean;
  defaultChecked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  disabled?: boolean;
  required?: boolean;
  /** Form field name; the value is submitted with the form like a native input. */
  name?: string;
  value?: string;
  id?: string;
  className?: string;
  /** `between` puts the label at the start and the control at the end of a full-width row. */
  layout?: 'inline' | 'between';
  'aria-describedby'?: string;
};

/** A control with its label and description, the way Base UI's forms guide lays out a single checkbox or switch:
 *  a field whose label encloses the control. The field also passes on a disabled `Fieldset`. */
function Choice({ layout, description, className, label, children }: Pick<ChoiceProps, 'layout' | 'description' | 'className' | 'label'> & { children: ReactNode }) {
  return <BaseField.Root className={cx('ui-choice', layout === 'between' && 'ui-choice--between', className)}>
    <BaseField.Label className="ui-choice__label">{children}<span className="ui-choice__text">{label}</span></BaseField.Label>
    {description != null && <BaseField.Description className="ui-choice__description">{description}</BaseField.Description>}
  </BaseField.Root>;
}

/** A checkbox with its label. Base UI owns the checked state, keyboard and form value. */
export function Checkbox({ label, description, layout, className, onCheckedChange, indeterminate, ...control }: ChoiceProps & { indeterminate?: boolean }) {
  return <Choice label={label} description={description} layout={layout} className={className}>
    <BaseCheckbox.Root className="ui-checkbox" indeterminate={indeterminate} onCheckedChange={checked => onCheckedChange?.(checked)} {...control}>
      <BaseCheckbox.Indicator className="ui-checkbox__mark">{indeterminate ? <Minus size={12} weight="bold" aria-hidden="true" /> : <Check size={12} weight="bold" aria-hidden="true" />}</BaseCheckbox.Indicator>
    </BaseCheckbox.Root>
  </Choice>;
}

/** An on/off setting that applies immediately. Defaults to a full-width row
 *  with the label at the start, the way settings panels read. */
export function Switch({ label, description, layout = 'between', className, onCheckedChange, ...control }: ChoiceProps) {
  return <Choice label={label} description={description} layout={layout} className={className}>
    <BaseSwitch.Root className="ui-switch" onCheckedChange={checked => onCheckedChange?.(checked)} {...control}>
      <BaseSwitch.Thumb className="ui-switch__thumb" />
    </BaseSwitch.Root>
  </Choice>;
}
