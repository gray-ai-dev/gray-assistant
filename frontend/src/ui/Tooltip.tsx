import type { ReactElement, ReactNode } from 'react';
import { Tooltip as BaseTooltip } from '@cloudflare/kumo/primitives/tooltip';
import { usePopupPositionMethod } from './popup';
import './tooltip.css';

/** Mounted once around the app. Tooltips wait a moment before the first one opens; moving to a neighbour within
 *  400ms opens the next one at once, e.g. along a toolbar. */
export function TooltipProvider({ children }: { children: ReactNode }) {
  return <BaseTooltip.Provider delay={400} timeout={400}>{children}</BaseTooltip.Provider>;
}

/**
 * A short label that appears over the element it wraps, on hover and on keyboard focus. Base UI Tooltip (through
 * Kumo) owns timing, placement inside the viewport and dismissal; it does not show on touch.
 *
 * A tooltip is a visual extra, never the only place a fact lives: an icon button still needs its `aria-label`, and
 * anything a user must read belongs in the page. `describes` also gives the text to assistive technology as the
 * element's description, for a control whose tooltip explains it (what a column measures). With no `content` the
 * child renders as it is.
 */
export function Tooltip({ content, children, side = 'top', align = 'center', delay, disabled, describes }: {
  content: ReactNode;
  /** The one element the tooltip belongs to. It must accept a ref and spread props (every `ui` component does). */
  children: ReactElement;
  side?: 'top' | 'bottom' | 'left' | 'right';
  align?: 'start' | 'center' | 'end';
  /** Milliseconds before it opens on hover, e.g. 0 for the bars of a chart. */
  delay?: number;
  /** Keeps the tooltip closed, e.g. while a text is not cut off. */
  disabled?: boolean;
  describes?: boolean;
}) {
  const positionMethod = usePopupPositionMethod();
  if (content == null || content === false || content === '') return children;
  return <BaseTooltip.Root disabled={disabled}>
    <BaseTooltip.Trigger render={children} delay={delay} aria-description={describes && typeof content === 'string' ? content : undefined} />
    <BaseTooltip.Portal>
      <BaseTooltip.Positioner className="ui-tooltip-positioner" positionMethod={positionMethod} side={side} align={align} sideOffset={6} collisionPadding={8}>
        <BaseTooltip.Popup className="ui-tooltip">{content}</BaseTooltip.Popup>
      </BaseTooltip.Positioner>
    </BaseTooltip.Portal>
  </BaseTooltip.Root>;
}
