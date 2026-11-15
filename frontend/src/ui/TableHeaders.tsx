import type { ReactNode, ThHTMLAttributes } from 'react';
import { ArrowDown, ArrowUp, ArrowsDownUp } from '../components/icons';
import { cx } from './cx';
import { HeaderCell } from './Data';
import { Tooltip } from './Tooltip';
import './table-headers.css';

export type SortDirection = 'ascending' | 'descending' | 'none';

/** A column header that sorts its table. The cell carries `aria-sort`; the
 *  header text is a button with an arrow showing the current direction. Its
 *  tooltip is `title` (what the column measures), then `sortHint`. */
export function SortableHeaderCell({ label, direction, onSort, title, sortHint, kind, nowrap, className }: {
  label: ReactNode;
  direction: SortDirection;
  onSort(): void;
  /** What the column measures: the tooltip, and in a `StackedTable` what each card's label of the column opens on a phone. */
  title?: string;
  /** How the column sorts, after `title` in the tooltip ("Sort: lowest input price."); not on a phone's cards, which sort with a select. */
  sortHint?: string;
  kind?: 'text' | 'numeric';
  /** Keep the label on one line (a short phrase such as "Requests, 24 h" that reads wrong broken). */
  nowrap?: boolean;
  className?: string;
}) {
  const Arrow = direction === 'descending' ? ArrowDown : direction === 'ascending' ? ArrowUp : ArrowsDownUp;
  const tooltip = [title, sortHint].filter(Boolean).join(' ');
  return <HeaderCell kind={kind} nowrap={nowrap} aria-sort={direction} className={className} definition={title}>
    {/* Numeric columns put the arrow first so the label ends on the numbers' edge. */}
    <Tooltip content={tooltip} describes>
      <button type="button" className="ui-sort-button" onClick={onSort}>{kind === 'numeric' && <Arrow size={14} aria-hidden="true" />}{label}{kind !== 'numeric' && <Arrow size={14} aria-hidden="true" />}</button>
    </Tooltip>
  </HeaderCell>;
}

/** The first cell of a body row that names the row (`th scope="row"`), e.g. a
 *  provider or a term. It reads as data, not as a column header. */
export function RowHeaderCell({ className, ...rest }: Omit<ThHTMLAttributes<HTMLTableCellElement>, 'scope'>) {
  return <th scope="row" className={cx('ui-row-header', className)} {...rest} />;
}
