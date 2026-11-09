import { useLayoutEffect, useRef, useState } from 'react';
import { Menu as BaseMenu } from '@cloudflare/kumo/primitives/menu';
import { CaretDown, Check } from '../components/icons';
import { cx } from './cx';
import { usePopupPositionMethod } from './popup';
import './overflow-nav.css';

export type NavLink = { key: string; label: string; href: string; current?: boolean };

/**
 * A row of navigation links that keeps to one line: the links that do not fit go, in their order, into a "More" menu
 * at the row's end, a Base UI Menu of link items (focus, arrow keys, typeahead and Escape are Base UI's). The row is
 * fitted from a hidden copy of every link, before it paints and again whenever its room or its text changes (a window
 * resize, enlarged text, a web font arriving). When the current page is in the menu, the trigger carries the
 * current-page look and the item its check.
 */
export function OverflowNav({ links, label, moreLabel = 'More', className }: {
  links: readonly NavLink[];
  /** Names the `nav` landmark, e.g. "Main navigation". */
  label: string;
  moreLabel?: string;
  className?: string;
}) {
  const row = useRef<HTMLElement>(null), copy = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState(links.length);
  const positionMethod = usePopupPositionMethod();
  const texts = links.map(link => link.label).join('\n');
  useLayoutEffect(() => {
    const nav = row.current, measure = copy.current;
    if (!nav || !measure) return;
    const fit = () => {
      const parts = [...measure.children] as HTMLElement[];
      const more = parts.pop()!.getBoundingClientRect().width;
      const widths = parts.map(part => part.getBoundingClientRect().width);
      const gap = parseFloat(getComputedStyle(measure).columnGap) || 0, room = nav.clientWidth;
      let count = widths.length, used = widths.reduce((sum, width, index) => sum + width + (index ? gap : 0), 0);
      // Every link fits, or as many as leave room for the menu's trigger after them.
      if (used > room) while (count > 0 && used + gap + more > room) { count--; used -= widths[count] + (count ? gap : 0); }
      setShown(count);
    };
    fit();
    const observer = new ResizeObserver(fit);
    observer.observe(nav);
    observer.observe(measure);
    return () => observer.disconnect();
  }, [texts, moreLabel]);
  const rest = links.slice(shown);
  return <nav ref={row} className={cx('ui-overflow-nav', className)} aria-label={label}>
    {links.slice(0, shown).map(link => <a key={link.key} className="ui-nav-link" href={link.href} aria-current={link.current ? 'page' : undefined}>{link.label}</a>)}
    {rest.length > 0 && <BaseMenu.Root>
      <BaseMenu.Trigger className="ui-nav-link ui-overflow-nav__more" data-current={rest.some(link => link.current) || undefined}>
        {moreLabel}<CaretDown size={14} aria-hidden="true" />
      </BaseMenu.Trigger>
      <BaseMenu.Portal>
        <BaseMenu.Positioner className="ui-menu-positioner" positionMethod={positionMethod} sideOffset={4} align="start" collisionPadding={8}>
          <BaseMenu.Popup className="ui-menu">
            {rest.map(link => <BaseMenu.LinkItem key={link.key} className="ui-menu__item ui-overflow-nav__item" href={link.href} closeOnClick
              aria-current={link.current ? 'page' : undefined}>
              {link.label}{link.current && <Check size={14} aria-hidden="true" />}
            </BaseMenu.LinkItem>)}
          </BaseMenu.Popup>
        </BaseMenu.Positioner>
      </BaseMenu.Portal>
    </BaseMenu.Root>}
    {/* The copy the row is fitted from: every link and the trigger, laid out alike, never seen or reached. */}
    <div ref={copy} className="ui-overflow-nav__copy" aria-hidden="true" inert>
      {links.map(link => <span key={link.key} className="ui-nav-link">{link.label}</span>)}
      <span className="ui-nav-link ui-overflow-nav__more">{moreLabel}<CaretDown size={14} aria-hidden="true" /></span>
    </div>
  </nav>;
}
