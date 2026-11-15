import type { ReactNode } from 'react';
import { Stack } from './Layout';
import { opensHere } from './Segmented';
import './overflow-nav.css';

export type SideNavItem<T extends string> = { value: T; label: ReactNode; href: string };

/**
 * The sections of one long page as a column of links, the one in view marked (`aria-current="location"`), for a page
 * that sets its sections out one under another instead of in tabs. Each link has the section's own address, so it can
 * be opened and shared; `onSelect` runs on a click as well, for the page to bring the section into view when the
 * address did not change; not on one that opens the link elsewhere (a new tab or window: a modifier key, or another
 * button than the main one), which leaves this page as it is. The page says which section is in view (`value`) and
 * where the list sits (a sticky side column, in a `FixedLayer`). The links are the app bar's (`OverflowNav`), in a
 * column.
 */
export function SideNav<T extends string>({ label, items, value, onSelect, className }: {
  /** Names the landmark, e.g. "Model sections". */
  label: string;
  items: readonly SideNavItem<T>[];
  value: T;
  onSelect?(value: T): void;
  className?: string;
}) {
  return <Stack as="nav" gap={1} aria-label={label} className={className}>
    {items.map(item => <a key={item.value} href={item.href} className="ui-nav-link" aria-current={item.value === value ? 'location' : undefined}
      data-current={item.value === value ? '' : undefined} onClick={event => { if (opensHere(event)) onSelect?.(item.value); }}>{item.label}</a>)}
  </Stack>;
}
