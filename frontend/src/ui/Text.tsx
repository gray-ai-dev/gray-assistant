import { useLayoutEffect, useRef, useState, type AnchorHTMLAttributes, type ElementType, type HTMLAttributes, type ReactNode } from 'react';
import { cx } from './cx';
import { Tooltip } from './Tooltip';

export type TextProps = HTMLAttributes<HTMLElement> & {
  as?: ElementType;
  /** body 16px, support 14px (explanations), meta 13px (timestamps, ids), micro 12px (units). */
  size?: 'body' | 'support' | 'meta' | 'micro';
  tone?: 'default' | 'muted' | 'success' | 'warning' | 'danger';
  weight?: 'regular' | 'medium' | 'strong';
  mono?: boolean;
  numeric?: boolean;
  /** Caps the line length at 75 characters for prose. */
  measure?: boolean;
  /** Keeps line breaks and spaces, e.g. model output. */
  preWrap?: boolean;
  /** One line ending in an ellipsis when it does not fit; the whole text is the tooltip only then. Give it a width
   *  limit (its container's, or `max-width` on a page class), e.g. a model ID in a table column. */
  truncate?: boolean;
  /** A tooltip, e.g. the whole ID behind a shortened one. */
  title?: string;
  children?: ReactNode;
};

/** Text in one of the typography roles from DESIGN.md. */
export function Text({ as: Tag = 'p', size = 'body', tone = 'default', weight = 'regular', mono, numeric, measure, preWrap, truncate, title, className, ...rest }: TextProps) {
  const classes = cx('ui-text', size !== 'body' && `ui-text--${size}`, tone !== 'default' && `ui-text--${tone}`, weight !== 'regular' && `ui-text--${weight}`, mono && 'ui-text--mono', numeric && 'ui-text--numeric', measure && 'ui-text--measure', preWrap && 'ui-text--pre-wrap', truncate && 'ui-text--truncate', className);
  return truncate ? <TruncatedText as={Tag} className={classes} title={title} {...rest} /> : <Tooltip content={title}><Tag className={classes} {...rest} /></Tooltip>;
}
/** Whether the element `ref` points at is cut off by its ellipsis now; measured again when it resizes or `content`
 *  changes. For a tooltip that should appear only while a name does not fit. */
export function useTruncated<E extends HTMLElement>(content: unknown) {
  const ref = useRef<E>(null), [cut, setCut] = useState(false);
  useLayoutEffect(() => {
    const node = ref.current;
    if (!node) return;
    const measure = () => setCut(node.scrollWidth > node.clientWidth + 1);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, [content]);
  return [ref, cut] as const;
}

/** A one-line Text that names its whole content in a tooltip only while the ellipsis cuts it. */
function TruncatedText({ as: Tag, title, children, ...rest }: HTMLAttributes<HTMLElement> & { as: ElementType }) {
  const [ref, cut] = useTruncated<HTMLElement>(children);
  return <Tooltip content={title ?? children} disabled={title == null && !cut}><Tag ref={ref} {...rest}>{children}</Tag></Tooltip>;
}

/** An identifier or short code inside running text. */
export function InlineCode({ children }: { children: ReactNode }) {
  return <code className="ui-inline-code">{children}</code>;
}

/** Text for screen readers only. */
export function VisuallyHidden({ as: Tag = 'span', children }: { as?: ElementType; children: ReactNode }) {
  return <Tag className="ui-sr-only">{children}</Tag>;
}

/** A standalone text link, e.g. "View usage in Activity". Links inside
 *  running text can stay plain anchors; they inherit the prose style. */
export function TextLink({ size = 'support', tone = 'default', className, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { size?: TextProps['size']; tone?: 'default' | 'muted' }) {
  return <a className={cx('ui-link', size !== 'body' && `ui-text--${size}`, tone === 'muted' && 'ui-link--muted', className)} {...rest} />;
}
