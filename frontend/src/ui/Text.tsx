import { Children, useLayoutEffect, useRef, useState, type AnchorHTMLAttributes, type ElementType, type HTMLAttributes, type ReactNode } from 'react';
import { cx } from './cx';
import { Tooltip } from './Tooltip';
import { usePhone } from './phone';

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
  // Mono text is an identifier (a model ID, a key, an address): the browser's page translation leaves it as written.
  const keep = mono && rest.translate === undefined ? { translate: 'no' as const } : null;
  return truncate ? <TruncatedText as={Tag} className={classes} title={title} {...keep} {...rest} /> : <Tooltip content={title}><Tag className={classes} {...keep} {...rest} /></Tooltip>;
}
/**
 * Short facts on one line, parted by a middle dot: "Frees 4:05 PM · 5-hour limit used up". Each child is a fact (an
 * empty one is left out). Where they do not fit one line, the break falls between two facts and takes the dot with it:
 * no line begins or ends with a dot, and a fact that fits a line is never cut in two. The dot is part of the text, so
 * a reader, a copy and a test get "A · B". `size` and `tone` as `Text`; `title` is the tooltip.
 */
export function Facts({ children, size = 'support', tone = 'muted', title, className }: { children: ReactNode; size?: TextProps['size']; tone?: TextProps['tone']; title?: string; className?: string }) {
  const facts = Children.toArray(children).filter(fact => fact !== '');
  if (!facts.length) return null;
  return <Text as="span" size={size} tone={tone} title={title} className={cx('ui-facts', className)}>
    <span className="ui-facts__line">{facts.map((fact, index) => <span key={index} className="ui-facts__fact">{index > 0 && <span className="ui-facts__dot"> · </span>}{fact}</span>)}</span>
  </Text>;
}
/**
 * A measured figure in a table cell, or a dash that says why there is none: `missing` is the dash's tooltip and what
 * assistive technology reads in its place. `tone="muted"` for a figure the row only compares against. With `explain`
 * the reason is also written under the dash below 600px, where a tooltip does not open (a touch screen) and a
 * `StackedTable` card has the room.
 *
 * `standIn` marks a figure that stands in for the one its column defines (a Gray benchmark where customer traffic was
 * too thin): muted, with no mark (product owner, 2026-11-13: the dagger was "莫名其妙，太 low 了"), `standIn` saying what
 * it is in its tooltip and to assistive technology, and with `explain` under it on a phone. Inside an element whose own
 * tooltip says it (a directory row's metric), `standInTooltip={false}` leaves the tooltip to that element. `explain`
 * as text writes that shorter line under the figure or the dash on a phone, in place of the whole reason.
 */
export function Measured({ value, format, missing, tone, explain, standIn, standInTooltip = true }: {
  value: number | null | undefined; format: (value: number) => string; missing: string; tone?: 'muted'; explain?: boolean | string;
  standIn?: string; standInTooltip?: boolean;
}) {
  if (value != null && standIn) {
    const figure = <span className="ui-measured">
      <Text as="span" numeric tone="muted">{format(value)}</Text>
      <VisuallyHidden>{` (${standIn})`}</VisuallyHidden>
    </span>;
    return <>{standInTooltip ? <Tooltip content={standIn}>{figure}</Tooltip> : figure}{explain && <MissingReason>{typeof explain === 'string' ? explain : standIn}</MissingReason>}</>;
  }
  if (value != null) return <Text as="span" numeric tone={tone}>{format(value)}</Text>;
  return <><Text as="span" tone="muted" title={missing} aria-label={missing}>—</Text>{explain && <MissingReason>{typeof explain === 'string' ? explain : missing}</MissingReason>}</>;
}
/** The reason under a dash, on a phone only (`usePhone`). The dash already says it to assistive technology. */
function MissingReason({ children }: { children: string }) {
  const phone = usePhone();
  return phone ? <Text as="div" size="meta" tone="muted" aria-hidden="true">{children}</Text> : null;
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

/** An identifier or short code inside running text. The browser's page translation leaves it as written. */
export function InlineCode({ children }: { children: ReactNode }) {
  return <code className="ui-inline-code" translate="no">{children}</code>;
}

/** A proper name inside running text or a label: a product, vendor, protocol or header name ("Gray", "Anthropic
 *  Messages", "Authorization: Bearer"). It looks like the text around it; the browser's page translation leaves it as
 *  written instead of translating it word by word. */
export function Name({ children }: { children: ReactNode }) {
  return <span translate="no">{children}</span>;
}

/** Text for screen readers only. */
export function VisuallyHidden({ as: Tag = 'span', children }: { as?: ElementType; children: ReactNode }) {
  return <Tag className="ui-sr-only">{children}</Tag>;
}

/** A standalone text link, e.g. "View usage in Activity". Links inside
 *  running text can stay plain anchors; they inherit the prose style. */
export function TextLink({ size = 'support', tone = 'default', quiet, className, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & {
  size?: TextProps['size']; tone?: 'default' | 'muted';
  /** A row's title in a table: ink in medium weight, underlined only under the pointer or the focus, so a list of them
   *  reads as names and not as a column of underlines. */
  quiet?: boolean;
}) {
  return <a className={cx('ui-link', size !== 'body' && `ui-text--${size}`, tone === 'muted' && 'ui-link--muted', quiet && 'ui-link--quiet', className)} {...rest} />;
}
