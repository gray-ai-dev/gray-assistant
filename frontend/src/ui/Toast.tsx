import type { ReactNode } from 'react';
import { Toaster, toast as sonner } from 'sonner';
import { CheckCircle, Info, WarningCircle, X, XCircle } from '../components/icons';
import './toast.css';

/**
 * The stack `toast` adds to, mounted once by `UiProvider`. Sonner's stacking, expand on hover and focus, swipe to
 * dismiss, motion, polite live region and Alt+T shortcut are as shipped; the design system only skins it, through
 * Sonner's own `classNames` on unstyled toasts. The region is named for what it holds: results of the user's actions.
 */
export function ToastRegion() {
  return <Toaster position="bottom-right" gap={10} visibleToasts={4} closeButton containerAriaLabel="Action results"
    icons={{ success: <CheckCircle size={18} aria-hidden="true" />, info: <Info size={18} aria-hidden="true" />, warning: <WarningCircle size={18} aria-hidden="true" />, error: <XCircle size={18} aria-hidden="true" />, close: <X size={14} aria-hidden="true" /> }}
    toastOptions={{ unstyled: true, classNames: { toast: 'ui-toast', content: 'ui-toast__content', title: 'ui-toast__title', description: 'ui-toast__description', icon: 'ui-toast__icon', closeButton: 'ui-toast__close', actionButton: 'ui-toast__action' } }} />;
}

type ToastOptions = {
  /** A second, muted line. */
  description?: ReactNode;
  /** One follow-up the result invites, e.g. Undo. */
  action?: { label: string; onClick(): void };
};
// The same result again (same kind and title) updates the toast still on screen instead of stacking a copy of it:
// Sonner updates a toast by its id. A toast with an action stays its own, because its action belongs to that one result.
const show = (kind: 'success' | 'info' | 'warning' | 'error') => (title: string, { description, action }: ToastOptions = {}) => {
  sonner[kind](title, { id: action ? undefined : `${kind}:${title}`, description, action });
};

/**
 * Says what an action just did, without moving the page: "Key revoked.", "Draft saved.". It appears wherever the user
 * is on the page and leaves by itself, so it suits a result that needs no further step. What the user must still act
 * on, or read later (a failed check, a payment being verified, the next step of a flow), stays in the page as a
 * `Notice`; an error that blocks the task is a `Notice role="alert"` beside it.
 */
export const toast = { success: show('success'), info: show('info'), warning: show('warning'), error: show('error') };
