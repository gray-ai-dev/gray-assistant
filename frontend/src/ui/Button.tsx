import { forwardRef, type AnchorHTMLAttributes, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { Button as BaseButton } from '@cloudflare/kumo/primitives/button';
import { cx } from './cx';
import { Tooltip } from './Tooltip';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'link';
/** `display` takes the surrounding type and stands one line tall: a button set as a word in a large sentence. */
export type ButtonSize = 'sm' | 'md' | 'display';
type Look = {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Icon before the label. */
  icon?: ReactNode;
  /** Icon after the label, e.g. an arrow on a navigation action. */
  iconEnd?: ReactNode;
  /** Stretches to the container width. */
  block?: boolean;
  /** Sits inside running text: no control height or padding (link variant). */
  inline?: boolean;
  /** Lets a long label wrap: the height grows from the control height and the
   *  content starts at the leading edge, e.g. full-width choices in a menu. */
  wrap?: boolean;
};

export function buttonClass({ variant = 'secondary', size = 'md', block, inline, wrap, iconOnly }: Look & { iconOnly?: boolean }, className?: string) {
  return cx('ui-button', `ui-button--${variant}`, size !== 'md' && `ui-button--${size}`, block && 'ui-button--block', inline && 'ui-button--inline', wrap && 'ui-button--wrap', iconOnly && 'ui-button--icon', className);
}

export type ButtonProps = Look & Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'color'> & {
  /** Shows a spinner, sets aria-busy and blocks clicks. */
  loading?: boolean;
  /** A tooltip that explains the action; assistive technology reads it as the button's description. */
  title?: string;
};

/** The one button. `type` defaults to "button"; pass `type="submit"` in forms. */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button({ variant, size, icon, iconEnd, block, inline, wrap, loading, className, children, disabled, title, type = 'button', ...rest }, ref) {
  return <Tooltip content={title} describes>
    <BaseButton ref={ref} type={type} className={buttonClass({ variant, size, block, inline, wrap }, className)} disabled={disabled || loading} aria-busy={loading || undefined} {...rest}>
      {loading ? <span className="ui-spinner" aria-hidden="true" /> : icon}{children}{iconEnd}
    </BaseButton>
  </Tooltip>;
});

export type LinkButtonProps = Look & AnchorHTMLAttributes<HTMLAnchorElement> & { href: string };

/** A link that looks like a button, for navigation actions. */
export const LinkButton = forwardRef<HTMLAnchorElement, LinkButtonProps>(function LinkButton({ variant, size, icon, iconEnd, block, inline, wrap, className, children, title, ...rest }, ref) {
  return <Tooltip content={title} describes>
    <a ref={ref} className={buttonClass({ variant, size, block, inline, wrap }, className)} {...rest}>{icon}{children}{iconEnd}</a>
  </Tooltip>;
});

export type IconButtonProps = Omit<ButtonProps, 'icon' | 'iconEnd' | 'children' | 'block' | 'inline' | 'wrap' | 'title'> & {
  /** Accessible name and tooltip. */
  label: string;
  icon: ReactNode;
};

/** A square, icon-only button. Defaults to the ghost look used in toolbars. */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton({ label, icon, variant = 'ghost', size, className, type = 'button', ...rest }, ref) {
  return <Tooltip content={label}>
    <BaseButton ref={ref} type={type} aria-label={label} className={buttonClass({ variant, size, iconOnly: true }, className)} {...rest}>{icon}</BaseButton>
  </Tooltip>;
});
