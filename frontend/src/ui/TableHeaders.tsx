import type { ReactNode, ThHTMLAttributes } from 'react';
import { ArrowDown, ArrowUp, ArrowsDownUp } from '../components/icons';
import { cx } from './cx';
import { TableHeaderCell } from './Data';
import { Tooltip } from './Tooltip';
import './table-headers.css';

export type SortDirection = 'ascending' | 'descending' | 'none';

/** A column header that sorts its table. The cell carries `aria-sort`; the
 *  header text is a button with an arrow showing the current direction. */
export function SortableHeaderCell({ label, direction, onSort, title, kind, nowrap, className }: {
  label: ReactNode;
  direction: SortDirection;
  onSort(): void;
  /** Tooltip, e.g. what the column measures. */
  title?: string;
  kind?: 'text' | 'numeric';
  /** Keep the label on one line (a short phrase such as "Requests, 24 h" that reads wrong broken). */
  nowrap?: boolean;
  className?: string;
}) {
  const Arrow = direction === 'descending' ? ArrowDown : direction === 'ascending' ? ArrowUp : ArrowsDownUp;
  return <TableHeaderCell kind={kind} nowrap={nowrap} aria-sort={direction} className={className}>
    {/* Numeric columns put the arrow first so the label ends on the numbers' edge. */}
    <Tooltip content={title} describes>
      <button type="button" className="ui-sort-button" onClick={onSort}>{kind === 'numeric' && <Arrow size={14} aria-hidden="true" />}{label}{kind !== 'numeric' && <Arrow size={14} aria-hidden="true" />}</button>
    </Tooltip>
  </TableHeaderCell>;
}

/** The first cell of a body row that names the row (`th scope="row"`), e.g. a
 *  provider or a term. It reads as data, not as a column header. */
export function RowHeaderCell({ className, ...rest }: Omit<ThHTMLAttributes<HTMLTableCellElement>, 'scope'>) {
  return <th scope="row" className={cx('ui-row-header', className)} {...rest} />;
}
