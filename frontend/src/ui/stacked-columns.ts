// Whether a StackedTable's cells can be matched to their header by their place in the row (StackedColumns.tsx): pure,
// so `node --test` loads it directly.

/**
 * Why a cell's place in its row does not say its column, or null: a cell spanning columns or rows, or a header of more
 * than one row (`headerRows`, for a header cell). A card's label could then open another column's definition.
 */
export function columnsProblem({ colSpan, rowSpan, headerRows }: { colSpan: number; rowSpan: number; headerRows?: number }): string | null {
  if (colSpan > 1) return `a cell spans ${colSpan} columns`;
  if (rowSpan > 1) return `a cell spans ${rowSpan} rows`;
  if (headerRows != null && headerRows > 1) return `the header has ${headerRows} rows`;
  return null;
}
