import type { ComponentProps } from 'react';
import { cx } from './cx';
import { Table } from './Data';
import { StackedColumnsProvider } from './StackedColumns';
import './stacked-table.css';

/** A `Table` whose rows become labelled cards on phones instead of scrolling
 *  sideways, so every column of a row stays in view. Give each `TableCell` a
 *  `data-label` with its column name; the first cell and an `actions` cell take
 *  the full card width, a `menu` cell sits in the card's top corner. Do not set `minWidth`.
 *  A column whose header defines it (`title` on `TableHeaderCell` or `SortableHeaderCell`)
 *  has each card's label open the same definition (an `InfoTip`), so the definition is
 *  written once, in the header. One header row, a cell per column. */
export function StackedTable({ className, ...rest }: Omit<ComponentProps<typeof Table>, 'minWidth'>) {
  return <StackedColumnsProvider><Table className={cx('ui-table--stack', className)} {...rest} /></StackedColumnsProvider>;
}
