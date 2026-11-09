import type { ReactNode } from 'react';
import { CheckCircle, Info, WarningCircle, XCircle } from '../components/icons';
import { cx } from './cx';
import { Tooltip } from './Tooltip';

export type Tone = 'neutral' | 'info' | 'success' | 'warning' | 'danger';

const noticeIcons: Record<Tone, ReactNode> = {
  neutral: <Info size={18} aria-hidden="true" />,
  info: <Info size={18} aria-hidden="true" />,
  success: <CheckCircle size={18} aria-hidden="true" />,
  warning: <WarningCircle size={18} aria-hidden="true" />,
  danger: <XCircle size={18} aria-hidden="true" />,
};

/** A message about the page or a section: status, warning or error. Actions
 *  sit at the end of the row, never inside the sentence. */
export function Notice({ tone = 'neutral', title, actions, icon, role, className, children, id }: {
  tone?: Tone;
  title?: ReactNode;
  actions?: ReactNode;
  /** Replace the tone icon, or pass `false` for none. */
  icon?: ReactNode | false;
  /** `alert` for errors that need attention now; `status` for polite updates. */
  role?: 'alert' | 'status';
  className?: string;
  children?: ReactNode;
  id?: string;
}) {
  const glyph = icon === false ? null : icon ?? noticeIcons[tone];
  return <div id={id} role={role} className={cx('ui-notice', tone !== 'neutral' && tone !== 'info' && `ui-notice--${tone}`, className)}>
    {glyph && <span className="ui-notice__icon">{glyph}</span>}
    <div className="ui-notice__body">
      {title && <span className="ui-notice__title">{title}</span>}
      {children}
    </div>
    {actions && <div className="ui-notice__actions">{actions}</div>}
  </div>;
}

/** What a list, table or page shows when there is nothing in it yet. */
export function EmptyState({ icon, title, description, actions, size = 'md', className, headingLevel = 2 }: {
  icon?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  size?: 'md' | 'compact';
  className?: string;
  headingLevel?: 2 | 3;
}) {
  const Heading = `h${headingLevel}` as const;
  return <div className={cx('ui-empty', size === 'compact' && 'ui-empty--compact', className)}>
    {icon && <span className="ui-empty__icon" aria-hidden="true">{icon}</span>}
    <Heading className="ui-empty__title">{title}</Heading>
    {description && <p className="ui-empty__description">{description}</p>}
    {actions && <div className="ui-empty__actions">{actions}</div>}
  </div>;
}

/** A short status or category label. Colour supports the text, never replaces it. */
export function Badge({ tone = 'neutral', variant = 'soft', dot, icon, className, children, title }: {
  tone?: Tone;
  variant?: 'soft' | 'outline';
  /** A leading status dot. */
  dot?: boolean;
  /** A leading icon (14px), e.g. a check on a verified fact; mark it `aria-hidden` and say the meaning in text. */
  icon?: ReactNode;
  className?: string;
  children: ReactNode;
  /** A tooltip with a detail the label leaves out, e.g. the chain ID behind a network name. */
  title?: string;
}) {
  return <Tooltip content={title}>
    <span className={cx('ui-badge', tone !== 'neutral' && `ui-badge--${tone}`, variant === 'outline' && 'ui-badge--outline', className)}>
      {dot && <span className="ui-badge__dot" aria-hidden="true" />}{icon}{children}
    </span>
  </Tooltip>;
}

/** An indeterminate busy indicator; pair it with text. */
export function Spinner({ label }: { label?: string }) {
  return <span className="ui-spinner" role={label ? 'status' : undefined} aria-label={label} aria-hidden={label ? undefined : true} />;
}

/**
 * Content that has not loaded yet, drawn in the shape it will take (text lines, table rows or one block), so nothing on
 * the page moves when it arrives. It shows only after 400 ms: a read that answers sooner shows nothing in between.
 * `label` is what assistive technology hears, once (the placeholder itself is hidden from it). Static: no shimmer.
 */
export function Skeleton({ lines = 3, rows, height, label = 'Loading', className }: {
  /** Lines of body text; the last of several stops short, as a paragraph does. */
  lines?: number;
  /** Rows of a table or list instead of text lines, each `height` px tall (44 by default, a table row). */
  rows?: number;
  /** With neither `rows` nor `lines` > 1, one block this many px tall (a chart, a figure). */
  height?: number;
  label?: string;
  className?: string;
}) {
  const count = Math.max(1, Math.min(rows ?? lines, 24));
  const kind = rows ? 'rows' : height ? 'block' : 'text';
  return <div role="status" className={cx('ui-skeleton', `ui-skeleton--${kind}`, className)} style={height ? { ['--skeleton-height' as string]: `${height}px` } : undefined}>
    <span className="ui-sr-only">{label}</span>
    <span className="ui-skeleton__shape" aria-hidden="true">
      {kind === 'block' ? <span className="ui-skeleton__bar" /> : Array.from({ length: count }, (_, index) => <span key={index} className="ui-skeleton__bar" />)}
    </span>
  </div>;
}
