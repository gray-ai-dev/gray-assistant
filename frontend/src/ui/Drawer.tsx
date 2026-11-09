import type { FormEvent, ReactNode } from 'react';
import { Drawer as BaseDrawer } from '@cloudflare/kumo/primitives/drawer';
import { X } from '../components/icons';
import { IconButton } from './Button';
import { cx } from './cx';
import { FixedLayer } from './popup';
import './drawer.css';

/**
 * A sheet over the page. `side="bottom"` (the default) rises from the bottom edge of a phone: the navigation menu, a
 * page's filters. `side="end"` slides in from the right edge: an editor opened from a table row, so the row stays in
 * the page beside it; on a phone it takes the whole width. Base UI Drawer (through Kumo) owns the focus trap, the
 * scroll lock, Escape, the swipe that dismisses it (down, or right for `end`) and the return of focus to the control
 * that opened it. The sheet is a `FixedLayer`: popups opened from it stay on their triggers while the page under it
 * scrolls. The page holds `open`; any control may set it. `title` names the sheet; `header` replaces it on screen when
 * the sheet's first row is a control (the workspace switcher), the title then naming it for assistive technology only.
 * `actions` sit beside the close button, e.g. Reset. `description` is a muted line under the title.
 *
 * An `end` sheet keeps its frame still, as Base UI's drawer guide advises: the header and `footer` (the form's Save and
 * Cancel) stay put and the body between them scrolls. With `onSubmit` the sheet's content is a form, so a submit
 * button in the footer submits it.
 */
export function Drawer({ open, onOpenChange, title, header, description, actions, footer, onSubmit, side = 'bottom', className, children }: {
  open: boolean;
  onOpenChange(open: boolean): void;
  title: ReactNode;
  header?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  footer?: ReactNode;
  onSubmit?(event: FormEvent<HTMLFormElement>): void;
  side?: 'bottom' | 'end';
  className?: string;
  children: ReactNode;
}) {
  const end = side === 'end';
  return <BaseDrawer.Root open={open} onOpenChange={next => onOpenChange(next)} swipeDirection={end ? 'right' : 'down'}>
    <BaseDrawer.Portal>
      <BaseDrawer.Backdrop className="ui-drawer-backdrop" />
      <BaseDrawer.Viewport className={cx('ui-drawer-viewport', end && 'ui-drawer-viewport--end')}>
        <BaseDrawer.Popup className={cx('ui-drawer', end && 'ui-drawer--end', className)}>
          {!end && <div className="ui-drawer__handle" aria-hidden="true" />}
          <BaseDrawer.Content className="ui-drawer__content" render={onSubmit ? <form onSubmit={event => { event.preventDefault(); onSubmit(event); }} /> : undefined}><FixedLayer>
            <div className="ui-drawer__header">
              <div className="ui-drawer__heading">
                <BaseDrawer.Title className={header ? 'ui-sr-only' : 'ui-drawer__title'}>{title}</BaseDrawer.Title>
                {header && <div className="ui-drawer__header-content">{header}</div>}
                {description && <BaseDrawer.Description className="ui-drawer__description">{description}</BaseDrawer.Description>}
              </div>
              <div className="ui-drawer__actions">{actions}<BaseDrawer.Close render={<IconButton size="sm" label="Close" icon={<X size={17} aria-hidden="true" />} />} /></div>
            </div>
            {end ? <div className="ui-drawer__body">{children}</div> : children}
            {footer && <div className="ui-drawer__footer">{footer}</div>}
          </FixedLayer></BaseDrawer.Content>
        </BaseDrawer.Popup>
      </BaseDrawer.Viewport>
    </BaseDrawer.Portal>
  </BaseDrawer.Root>;
}
