import { useCallback, useRef, type FormEvent, type KeyboardEvent, type ReactNode, type Ref, type RefObject } from 'react';
import { Dialog as BaseDialog } from '@cloudflare/kumo/primitives/dialog';
import { X } from '../components/icons';
import { IconButton } from './Button';
import { cx } from './cx';
import { FixedLayer } from './popup';
import './dialog.css';

/**
 * A form over the page, centred, for a task that belongs to the page but should not push its content down: creating
 * or editing one record. Its frame keeps still, as the side sheet's does: the title row and `footer` (the form's
 * submit and Cancel) stay put, and the body between them scrolls when the form is longer than the window. On a phone it
 * is a full sheet. With `onSubmit` its content is a form, so a submit button in the footer submits it; the page checks
 * the values itself (the browser's own checks are off), so its message shows in the form.
 *
 * Base UI Dialog (through Kumo) owns the focus trap, the scroll lock, Escape and the return of focus to the control
 * that was focused before it opened; `finalFocus` sends focus elsewhere on close (to what the form made, say). A press
 * outside does not close it, so a half-filled form is not lost by a stray click: Escape, Cancel and the close button do.
 * The dialog is a `FixedLayer`: popups opened from it (selects, menus, infotips) stay on their triggers. Escape in an
 * open list inside it (a select's), or in a search field that opens one (a model picker's), leaves the form open.
 * A message the form shows in its body (an element with `role="alert"`, its refusal) is scrolled into view when it
 * appears and after each submit: the body may be scrolled down to the end of a long form, on a phone above all.
 *
 * `size="page"` gives it a page's width (1184px), for content made for a page: a new API key's setup, whose code
 * blocks then have the room they have on the page. `escapable={false}` keeps it open on Escape too, for a step that shows something
 * only once (a new key): it closes by its own button or the close button. `titleRef` focuses the title when the
 * dialog's step changes, as a panel's heading takes focus.
 */
export function Dialog({ open, onOpenChange, title, description, footer, onSubmit, finalFocus, size = 'md', escapable = true, titleRef, className, children }: {
  open: boolean;
  onOpenChange(open: boolean): void;
  title: ReactNode;
  description?: ReactNode;
  footer?: ReactNode;
  onSubmit?(event: FormEvent<HTMLFormElement>): void;
  finalFocus?: RefObject<HTMLElement | null>;
  size?: 'md' | 'page';
  escapable?: boolean;
  titleRef?: Ref<HTMLHeadingElement>;
  className?: string;
  children: ReactNode;
}) {
  // Escape pressed in an open list inside the dialog (a model picker's, a select's) closes that list only: the dialog's
  // own Escape would also close the form under it. The key is read before the list handles it, while it still reads
  // open: in the dialog's own handler when that runs first, else in a capture handler on the popup. Escape elsewhere in
  // the form (a text field, a button, a closed select) closes the dialog.
  const listEscape = useRef(false);
  // A search field that opens a list (a model picker's) counts with its list closed too: its list may be fading out
  // as the key comes, and Escape there clears or closes the search, never the form.
  const inOpenList = (target: EventTarget | null | undefined) => target instanceof Element
    && (target.getAttribute('aria-expanded') === 'true' || !!target.closest('[role="listbox"], [role="menu"]')
      || (target.tagName === 'INPUT' && target.getAttribute('role') === 'combobox'));
  // The body's alert into view: when one is added (a refusal said once the submit's work is done), and after a submit
  // (the same refusal again leaves the alert in place, so nothing is added).
  const body = useRef<HTMLDivElement | null>(null), watcher = useRef<MutationObserver | null>(null);
  const showAlert = () => body.current?.querySelector('[role="alert"]')?.scrollIntoView({ block: 'nearest' });
  const bodyRef = useCallback((node: HTMLDivElement | null) => {
    watcher.current?.disconnect(); watcher.current = null; body.current = node;
    if (!node || typeof MutationObserver === 'undefined') return;
    const alerting = (added: Node) => added instanceof Element && (added.matches('[role="alert"]') || !!added.querySelector('[role="alert"]'));
    watcher.current = new MutationObserver(records => { if (records.some(record => Array.from(record.addedNodes).some(alerting))) showAlert(); });
    watcher.current.observe(node, { childList: true, subtree: true });
  }, []);
  const onKeyDownCapture = (event: KeyboardEvent) => {
    if (event.key !== 'Escape' || !inOpenList(event.target)) return;
    listEscape.current = true;
    setTimeout(() => { listEscape.current = false; });
  };
  return <BaseDialog.Root open={open} onOpenChange={(next, details) => {
    if (!next && details.reason === 'escape-key' && (!escapable || listEscape.current || inOpenList(details.event?.target))) return;
    onOpenChange(next);
  }} disablePointerDismissal>
    <BaseDialog.Portal>
      <BaseDialog.Backdrop className="ui-dialog-backdrop" />
      <BaseDialog.Viewport className="ui-dialog-viewport ui-dialog-viewport--form">
        <BaseDialog.Popup className={cx('ui-dialog', 'ui-dialog--form', size === 'page' && 'ui-dialog--page', className)} finalFocus={finalFocus}
          onKeyDownCapture={onKeyDownCapture} render={onSubmit ? <form noValidate onSubmit={event => { event.preventDefault(); onSubmit(event); requestAnimationFrame(showAlert); }} /> : undefined}><FixedLayer>
          <div className="ui-dialog__header">
            <div className="ui-dialog__heading">
              <BaseDialog.Title className="ui-dialog__title" ref={titleRef} tabIndex={titleRef ? -1 : undefined}>{title}</BaseDialog.Title>
              {description != null && <BaseDialog.Description className="ui-dialog__description">{description}</BaseDialog.Description>}
            </div>
            <BaseDialog.Close render={<IconButton size="sm" label="Close" icon={<X size={17} aria-hidden="true" />} />} />
          </div>
          <div className="ui-dialog__body" ref={bodyRef}>{children}</div>
          {footer && <div className="ui-dialog__footer">{footer}</div>}
        </FixedLayer></BaseDialog.Popup>
      </BaseDialog.Viewport>
    </BaseDialog.Portal>
  </BaseDialog.Root>;
}
