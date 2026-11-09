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

/** A rule between groups of menu items. */
export function MenuSeparator() { return <BaseMenu.Separator className="ui-menu__separator" />; }
