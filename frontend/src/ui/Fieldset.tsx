import type { FieldsetHTMLAttributes, ReactNode } from 'react';
import { Fieldset as BaseFieldset } from '@cloudflare/kumo/primitives/fieldset';
import { cx } from './cx';
import './fieldset.css';

type Gap = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;

/** A group of controls, optionally under a legend, stacked with a gap. Base UI Fieldset (through Kumo) names the
 *  group by its legend, and `disabled` locks every control inside it at once, e.g. while a form is saving: native
 *  inputs and buttons through the fieldset element, Base UI controls through its context. */
export function Fieldset({ legend, hideLegend, gap = 4, className, children, ...rest }: Omit<FieldsetHTMLAttributes<HTMLFieldSetElement>, 'title'> & {
  /** Names the group, e.g. the question a set of checkboxes answers. */
  legend?: ReactNode;
  hideLegend?: boolean;
  gap?: Gap;
}) {
  return <BaseFieldset.Root className={cx('ui-fieldset', `ui-gap-${gap}`, className)} {...rest}>
    {legend != null && <BaseFieldset.Legend className={hideLegend ? 'ui-sr-only' : 'ui-fieldset__legend'}>{legend}</BaseFieldset.Legend>}
    {children}
  </BaseFieldset.Root>;
}
