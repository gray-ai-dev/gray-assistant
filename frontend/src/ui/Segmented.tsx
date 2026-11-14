import { useCallback, useLayoutEffect, useRef, type ReactNode } from 'react';
import { ToggleGroup } from '@cloudflare/kumo/primitives/toggle-group';
import { Toggle } from '@cloudflare/kumo/primitives/toggle';
import { ScrollArea } from '@cloudflare/kumo/primitives/scroll-area';
import { cx } from './cx';

/** One pressed value out of a Base UI toggle group: pressing another value picks it, pressing the current one keeps it. */
function pick<T extends string>(current: T, next: readonly string[], change: ((value: T) => void) | undefined) {
  const value = next.find(item => item !== current);
  if (value !== undefined) change?.(value as T);
}

export type SegmentOption<T extends string> = { value: T; label: ReactNode; icon?: ReactNode; disabled?: boolean; 'aria-label'?: string };

/** A small set of mutually exclusive views or modes, shown as one pill. Base UI ToggleGroup (through Kumo) owns the
 *  pressed state (`aria-pressed`), one tab stop for the group and the arrow keys between segments. */
export function SegmentedControl<T extends string>({ options, value, onValueChange, size = 'md', disabled, className, ...aria }: {
  options: readonly SegmentOption<T>[];
  value: T;
  onValueChange: (value: T) => void;
  size?: 'sm' | 'md';
  disabled?: boolean;
  className?: string;
  'aria-label': string;
}) {
  // More segments than a phone is wide: the pill scrolls sideways, and the pressed segment is brought whole into
  // view whenever it changes (the page itself is not scrolled). Without it a page opened on its last segment showed
  // the first ones and cut the pressed one off (Settings › API tokens on a phone, review of 2026-11-14).
  const pill = useRef<HTMLElement | null>(null);
  const holdPill = useCallback((node: HTMLElement | null) => { pill.current = node; }, []);
  useLayoutEffect(() => {
    const box = pill.current, current = box?.querySelector<HTMLElement>('[data-pressed], [aria-pressed="true"]');
    if (!box || !current) return;
    const left = current.getBoundingClientRect().left - box.getBoundingClientRect().left + box.scrollLeft, right = left + current.offsetWidth;
    if (box.scrollLeft > left) box.scrollLeft = left;
    else if (box.scrollLeft < right - box.clientWidth) box.scrollLeft = right - box.clientWidth;
  }, [value, options.length]);
  return <ToggleGroup ref={holdPill} className={cx('ui-segmented', size === 'sm' && 'ui-segmented--sm', className)} value={[value]} disabled={disabled}
    onValueChange={next => pick(value, next, onValueChange)} {...aria}>
    {options.map(option => <Toggle key={option.value} value={option.value} className="ui-segmented__item" aria-label={option['aria-label']}
      disabled={option.disabled}>{option.icon}{option.label}</Toggle>)}
  </ToggleGroup>;
}

export type TabItem<T extends string> = { value: T; label: ReactNode; count?: ReactNode; href?: string; disabled?: boolean };

/** Underlined tabs across the top of a page or panel. Items with an `href` are page navigation: links in a `nav`,
 *  the current one marked `aria-current="page"`. Items without one switch a view in place: a Base UI toggle group,
 *  like `SegmentedControl` with the tab look. When the strip is wider than its space (many tabs on a phone) it is a
 *  Base UI ScrollArea viewport, as Base UI's Tabs docs combine them: it scrolls sideways, an edge with more tabs past
 *  it fades out (the viewport's overflow variables drive a mask), and the current tab is kept whole in view clear of
 *  that fade, whenever it changes and whenever the strip or a tab changes size (a rotation, a web font arriving). The
 *  page itself is not scrolled. */
export function Tabs<T extends string>({ items, value, onValueChange, className, ...aria }: {
  items: readonly TabItem<T>[];
  value: T;
  onValueChange?: (value: T) => void;
  className?: string;
  'aria-label': string;
}) {
  const strip = useRef<HTMLElement | null>(null);
  const holdStrip = useCallback((node: HTMLElement | null) => { strip.current = node; }, []);
  // What moves a tab inside the strip: the tabs themselves and their counts, which arrive after the first render.
  const layout = items.map(item => `${item.value}:${typeof item.count === 'number' || typeof item.count === 'string' ? item.count : item.count != null}`).join('|');
  useLayoutEffect(() => {
    const box = strip.current;
    if (!box) return;
    const reveal = () => {
      const current = box.querySelector<HTMLElement>('[aria-current="page"], [data-pressed]');
      if (!current) return;
      // The tab's place in the strip's scroll coordinates, and the scroll positions that show it with the fade's width
      // to spare on each side (the first and last tabs reach the ends, where there is no fade).
      const fade = parseFloat(getComputedStyle(box).getPropertyValue('--ui-tabs-fade')) || 0;
      const left = current.getBoundingClientRect().left - box.getBoundingClientRect().left + box.scrollLeft, right = left + current.offsetWidth;
      const least = right + fade - box.clientWidth, most = left - fade;
      if (box.scrollLeft > most) box.scrollLeft = Math.max(0, most);
      else if (box.scrollLeft < least) box.scrollLeft = least;
    };
    reveal();
    const observer = new ResizeObserver(reveal);
    observer.observe(box);
    for (const tab of box.children) observer.observe(tab);
    return () => observer.disconnect();
  }, [value, layout]);
  const content = (item: TabItem<T>) => <>{item.label}{item.count != null && <span className="ui-tabs__count">{item.count}</span>}</>;
  // The strip is the viewport; its own role (navigation, or the toggle group's group) is passed last, over the
  // viewport's presentation role, as Base UI's docs pass Tabs.List's.
  return <ScrollArea.Root className={cx('ui-tabs-area', className)}>
    {items.some(item => item.href)
      ? <ScrollArea.Viewport ref={holdStrip} className="ui-tabs" render={<nav />} role="navigation" {...aria}>
        {items.map(item => <a key={item.value} className="ui-tabs__item" href={item.href} aria-current={item.value === value ? 'page' : undefined}
          onClick={() => onValueChange?.(item.value)}>{content(item)}</a>)}
      </ScrollArea.Viewport>
      : <ToggleGroup ref={holdStrip} className="ui-tabs" render={<ScrollArea.Viewport />} value={[value]} onValueChange={next => pick(value, next, onValueChange)} {...aria}>
        {items.map(item => <Toggle key={item.value} value={item.value} className="ui-tabs__item" disabled={item.disabled}>{content(item)}</Toggle>)}
      </ToggleGroup>}
  </ScrollArea.Root>;
}
