import { useLayoutEffect, useState, type CSSProperties, type ReactNode, type RefObject } from 'react';
import { Dialog } from '@cloudflare/kumo/primitives/dialog';
import MessageCircle from 'lucide-react/dist/esm/icons/message-circle.mjs';
import { Minus } from '../components/icons';
import { IconButton } from './Button';
import { FixedLayer } from './popup';
import './floating-chat.css';

/** A persistent non-modal chat: the page stays interactive, and Base UI owns focus and Escape. */
export function FloatingChat({ open, onOpenChange, title, busy, actions, anchorRef, launcherAnchorRef, children }: {
  open: boolean;
  onOpenChange(open: boolean): void;
  title: string;
  busy?: boolean;
  actions?: ReactNode;
  anchorRef?: RefObject<HTMLElement | null>;
  launcherAnchorRef?: RefObject<HTMLElement | null>;
  children: ReactNode;
}) {
  const [bounds, setBounds] = useState<CSSProperties>();
  useLayoutEffect(() => {
    if (!anchorRef && !launcherAnchorRef) return;
    const measure = () => {
      const rect = anchorRef?.current?.getBoundingClientRect();
      const button = launcherAnchorRef?.current?.getBoundingClientRect();
      setBounds({
        ...(rect && { '--floating-chat-top': `${rect.top}px`, '--floating-chat-bottom': `${innerHeight - rect.bottom}px`,
          '--floating-chat-right': `${innerWidth - rect.right}px` }),
        ...(button && { '--floating-chat-launcher-bottom': `${innerHeight - button.bottom}px` }),
      } as CSSProperties);
    };
    const observer = new ResizeObserver(measure);
    // Sibling composer refs are attached after this component's layout effect.
    const frame = requestAnimationFrame(() => {
      if (anchorRef?.current) observer.observe(anchorRef.current);
      if (launcherAnchorRef?.current) observer.observe(launcherAnchorRef.current);
      measure();
    });
    window.addEventListener('resize', measure);
    window.addEventListener('scroll', measure, true);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
      window.removeEventListener('resize', measure);
      window.removeEventListener('scroll', measure, true);
    };
  }, [open, anchorRef, launcherAnchorRef]);
  return <FixedLayer>
    <Dialog.Root open={open} onOpenChange={onOpenChange} modal={false} disablePointerDismissal>
      <Dialog.Trigger render={<IconButton variant="secondary" className="ui-floating-chat-trigger" style={bounds}
        icon={<MessageCircle size={18} aria-hidden="true" />} label={busy ? `${title} · working` : title}
        aria-busy={busy || undefined} />} />
      <Dialog.Portal>
        <Dialog.Popup className={'ui-floating-chat' + (anchorRef ? ' ui-floating-chat--aligned' : '')} style={bounds}>
          <ChatHeader title={<Dialog.Title render={<span />}>{title}</Dialog.Title>} actions={<>
              {actions}
              <Dialog.Close render={<IconButton size="sm" variant="ghost" label={`Minimize ${title.toLowerCase()}`} icon={<Minus size={16} />} />} />
          </>} />
          <div className="ui-floating-chat__body">{children}</div>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  </FixedLayer>;
}

/** Matching title rows keep adjacent conversation boundaries on the same baseline. */
export function ChatHeader({ title, actions }: { title: ReactNode; actions?: ReactNode }) {
  return <header className="ui-chat-header">
    <div className="ui-chat-header__title">{title}</div>
    <div className="ui-chat-header__actions">{actions}</div>
  </header>;
}
