import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import { AlertDialog } from '@cloudflare/kumo/primitives/alert-dialog';
import { Button } from './Button';
import { FixedLayer } from './popup';
import { ToastRegion } from './Toast';
import { TooltipProvider } from './Tooltip';
import './dialog.css';

export type ConfirmOptions = {
  /** The question, e.g. "Suspend this provider?". */
  title: ReactNode;
  /** What happens if they agree, in a sentence. */
  description?: ReactNode;
  /** The action in its own words ("Suspend provider"), never "OK". */
  confirmLabel: string;
  cancelLabel?: string;
  /** `danger` for an action that removes or stops something. */
  tone?: 'default' | 'danger';
};

const ConfirmContext = createContext<((options: ConfirmOptions) => Promise<boolean>) | null>(null);

/** Asks the user to confirm an action in a dialog; resolves true when they agree. Use it in place of the browser's
 *  `confirm()`: `if (await confirm({ title, confirmLabel })) …`. */
export function useConfirm() {
  const confirm = useContext(ConfirmContext);
  if (!confirm) throw new Error('useConfirm needs a UiProvider above it');
  return confirm;
}

/** Mounted once around the app: the shared tooltip timing, the toast stack and the dialog `useConfirm` opens. Base UI AlertDialog
 *  (through Kumo) owns the focus trap, scroll lock, Escape and the return of focus to the control that asked. */
export function UiProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<ConfirmOptions | null>(null);
  const [open, setOpen] = useState(false);
  const resolver = useRef<((agreed: boolean) => void) | null>(null);
  const settle = (agreed: boolean) => { resolver.current?.(agreed); resolver.current = null; setOpen(false); };
  const confirm = useCallback((options: ConfirmOptions) => new Promise<boolean>(resolve => {
    resolver.current?.(false);
    resolver.current = resolve;
    setRequest(options);
    setOpen(true);
  }), []);
  return <ConfirmContext.Provider value={confirm}>
    <TooltipProvider>{children}</TooltipProvider>
    <ToastRegion />
    <AlertDialog.Root open={open} onOpenChange={next => { if (!next) settle(false); }} onOpenChangeComplete={next => { if (!next) setRequest(null); }}>
      <AlertDialog.Portal>
        <AlertDialog.Backdrop className="ui-dialog-backdrop" />
        <AlertDialog.Viewport className="ui-dialog-viewport">
          <AlertDialog.Popup className="ui-dialog"><FixedLayer>
            <AlertDialog.Title className="ui-dialog__title">{request?.title}</AlertDialog.Title>
            {request?.description != null && <AlertDialog.Description className="ui-dialog__description">{request.description}</AlertDialog.Description>}
            <div className="ui-dialog__actions">
              <AlertDialog.Close render={<Button />}>{request?.cancelLabel ?? 'Cancel'}</AlertDialog.Close>
              <Button variant={request?.tone === 'danger' ? 'danger' : 'primary'} onClick={() => settle(true)}>{request?.confirmLabel}</Button>
            </div>
          </FixedLayer></AlertDialog.Popup>
        </AlertDialog.Viewport>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  </ConfirmContext.Provider>;
}
