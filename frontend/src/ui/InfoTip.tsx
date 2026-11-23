import type { ReactNode } from 'react';
import { Popover } from '@cloudflare/kumo/primitives/popover';
import { usePopupPositionMethod } from './popup';
import './infotip.css';

/**
 * A term whose definition opens beside it, e.g. a column header "TTFT (ms)" and what it measures. It is a button:
 * hovering opens it for a mouse, a tap or Enter opens it on a phone or with a keyboard, so the definition reaches
 * everyone. A Tooltip suits only a visual extra (Base UI's guidance for infotips: a Popover, not a Tooltip).
 */
export function InfoTip({ term, children, align = 'center' }: {
  /** What the reader sees, e.g. the column name. */
  term: ReactNode;
  /** The definition. */
  children: ReactNode;
  /**
   * Which edge of the term the definition lines up with. `start` keeps it off a control to the term's left: an open
   * definition stays open while the pointer is on it (Base UI's safe polygon), so one over a button takes its press.
   */
  align?: 'start' | 'center' | 'end';
}) {
  const positionMethod = usePopupPositionMethod();
  return <Popover.Root>
    <Popover.Trigger openOnHover delay={300} closeDelay={100} className="ui-infotip">{term}</Popover.Trigger>
    <Popover.Portal>
      <Popover.Positioner className="ui-infotip-positioner" positionMethod={positionMethod} align={align} sideOffset={6} collisionPadding={8}>
        <Popover.Popup className="ui-infotip__popup">{children}</Popover.Popup>
      </Popover.Positioner>
    </Popover.Portal>
  </Popover.Root>;
}
