// A StackedTable's column definitions (StackedTable.tsx): each header cell with a definition gives it to its column,
// and on a phone, where the headers are hidden and each row is a card, a cell of that column labels itself with the
// same definition behind its label, so it is written once, in the header.
import { createContext, useCallback, useContext, useId, useLayoutEffect, useMemo, useState, type ReactNode, type RefObject } from 'react';
import { usePhone } from './phone';
import { columnsProblem } from './stacked-columns';

type Entry = { column: number; definition: string };
type Columns = {
  /** Sets (or, with a null column or definition, clears) what header cell `id` defines. */
  define(id: string, column: number | null, definition: string | null): void;
  /** Each defined column's definition, by the column's index. */
  definitions: ReadonlyMap<number, string>;
  /** Whether the table is cards now. */
  phone: boolean;
};
const StackedColumns = createContext<Columns | null>(null);

let warned = false;
/**
 * In development, says once when a cell of a StackedTable with definitions is not where its column's header is (a span,
 * a second header row): its card's label could open another column's definition. Nothing in a production build.
 */
function warnIfMisplaced(cell: HTMLTableCellElement | null) {
  if (!import.meta.env.DEV || warned || !cell) return;
  const problem = columnsProblem({ colSpan: cell.colSpan, rowSpan: cell.rowSpan, headerRows: cell.closest('thead')?.rows.length });
  if (!problem) return;
  warned = true;
  console.warn(`StackedTable: ${problem}, so a card's label may open another column's definition. Give the table one header row and a cell per column.`, cell);
}

/** Holds a StackedTable's column definitions for its cells. `cards`: the table is cards at any width (`StackedTable`). */
export function StackedColumnsProvider({ children, cards = false }: { children: ReactNode; cards?: boolean }) {
  const [entries, setEntries] = useState<ReadonlyMap<string, Entry>>(new Map());
  const define = useCallback((id: string, column: number | null, definition: string | null) => setEntries(current => {
    const now = current.get(id);
    if (column == null || column < 0 || !definition) {
      if (!now) return current;
      const next = new Map(current);
      next.delete(id);
      return next;
    }
    // Unchanged, the same map: nothing renders again.
    return now?.column === column && now.definition === definition ? current : new Map(current).set(id, { column, definition });
  }), []);
  const phone = usePhone() || cards;
  const definitions = useMemo(() => new Map([...entries.values()].map(entry => [entry.column, entry.definition])), [entries]);
  const value = useMemo(() => ({ define, definitions, phone }), [define, definitions, phone]);
  return <StackedColumns.Provider value={value}>{children}</StackedColumns.Provider>;
}

/**
 * Gives the column of the header cell `ref` points at its `definition`, inside a StackedTable; nothing elsewhere. The
 * column is the cell's place in its row, read after each render, so a column shown or left out before it moves it.
 */
export function useColumnDefinition(ref: RefObject<HTMLTableCellElement | null>, definition: string | undefined) {
  const define = useContext(StackedColumns)?.define, id = useId();
  useLayoutEffect(() => {
    if (definition) warnIfMisplaced(ref.current);
    define?.(id, ref.current?.cellIndex ?? null, definition ?? null);
  });
  useLayoutEffect(() => () => define?.(id, null, null), [define, id]);
}

/**
 * The definition of the column of the body cell `ref` points at, while its StackedTable is cards and the column's
 * header has one: what the cell's label opens on a phone. Undefined otherwise, and outside a StackedTable.
 */
export function useCellDefinition(ref: RefObject<HTMLTableCellElement | null>): string | undefined {
  const columns = useContext(StackedColumns);
  const [column, setColumn] = useState<number | null>(null);
  const active = !!columns?.phone && columns.definitions.size > 0;
  useLayoutEffect(() => {
    if (columns && columns.definitions.size > 0) warnIfMisplaced(ref.current);
    if (!active) return;
    const index = ref.current?.cellIndex ?? null;
    if (index !== column) setColumn(index);
  });
  return active && column != null ? columns!.definitions.get(column) : undefined;
}
