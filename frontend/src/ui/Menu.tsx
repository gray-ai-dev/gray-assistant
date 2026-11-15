import type { ReactNode } from 'react';
import { Menu as BaseMenu } from '@cloudflare/kumo/primitives/menu';
import { DotsThree } from '../components/icons';
import { buttonClass, type ButtonSize } from './Button';
import { cx } from './cx';
import { usePopupPositionMethod } from './popup';
import { Tooltip } from './Tooltip';
import './menu.css';

/** A menu of actions behind one icon button, e.g. the actions of a table row.
 *  `label` names the trigger ("Actions for Staging worker"). Base UI Menu (through
 *  Kumo) owns opening, focus, arrow keys, typeahead, Escape and the ARIA roles. */
export function Menu({ label, icon, size = 'sm', align = 'end', children, className }: {
  label: string;
  /** Replaces the "…" icon. */
  icon?: ReactNode;
  size?: ButtonSize;
  align?: 'start' | 'center' | 'end';
  /** `MenuItem` and `MenuSeparator` children. */
  children: ReactNode;
  className?: string;
}) {
  const positionMethod = usePopupPositionMethod();
  return <BaseMenu.Root>
    <Tooltip content={label}>
      <BaseMenu.Trigger className={buttonClass({ variant: 'ghost', size, iconOnly: true }, className)} aria-label={label}>
        {icon ?? <DotsThree size={16} aria-hidden="true" />}
      </BaseMenu.Trigger>
    </Tooltip>
    <BaseMenu.Portal>
      <BaseMenu.Positioner className="ui-menu-positioner" positionMethod={positionMethod} sideOffset={4} align={align} collisionPadding={8}>
        <BaseMenu.Popup className="ui-menu">{children}</BaseMenu.Popup>
      </BaseMenu.Positioner>
    </BaseMenu.Portal>
  </BaseMenu.Root>;
}

/** One action in a `Menu`. `tone="danger"` for destructive actions; the menu closes after `onSelect`. */
export function MenuItem({ onSelect, tone = 'default', disabled, icon, children }: { onSelect(): void; tone?: 'default' | 'danger'; disabled?: boolean; icon?: ReactNode; children: ReactNode }) {
  return <BaseMenu.Item className={cx('ui-menu__item', tone === 'danger' && 'ui-menu__item--danger')} disabled={disabled} onClick={onSelect}>
    {icon && <span className="ui-menu__icon" aria-hidden="true">{icon}</span>}{children}
  </BaseMenu.Item>;
}

/** A menu item that is a link (Base UI Menu.LinkItem): `newTab` opens it in a new tab, e.g. a page on another origin. */
export function MenuLinkItem({ href, newTab, icon, children }: { href: string; newTab?: boolean; icon?: ReactNode; children: ReactNode }) {
  return <BaseMenu.LinkItem className="ui-menu__item ui-menu__item--link" href={href} closeOnClick {...(newTab ? { target: '_blank', rel: 'noopener noreferrer' } : {})}>
    {icon && <span className="ui-menu__icon" aria-hidden="true">{icon}</span>}{children}
  </BaseMenu.LinkItem>;
}

/** Items that belong together under a quiet label that says what they share ("On your relay’s page"). */
export function MenuGroup({ label, children }: { label: ReactNode; children: ReactNode }) {
  return <BaseMenu.Group>
    <BaseMenu.GroupLabel className="ui-menu__label">{label}</BaseMenu.GroupLabel>
    {children}
  </BaseMenu.Group>;
}

/** A rule between groups of menu items. */
export function MenuSeparator() { return <BaseMenu.Separator className="ui-menu__separator" />; }
