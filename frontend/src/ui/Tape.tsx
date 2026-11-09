import { Toolbar } from '@cloudflare/kumo/primitives/toolbar';
import { cx } from './cx';
import { Tooltip } from './Tooltip';
import './tape.css';

/** `neutral` for the usual case, `muted` for a quiet one (cancelled), `warning` and `danger` for what went wrong. */
export type TapeTone = 'neutral' | 'muted' | 'warning' | 'danger';
/** One event: `label` names it ("Request 3 · Failed · 2:14:03 PM"); `dim` marks one that is not on the page yet. */
export type TapeCell = { key: string; tone: TapeTone; label: string; dim?: boolean };

/**
 * A run of events in order, one small cell each, coloured by tone: a session's requests by outcome. `danger` cells
 * stand taller as well as red and `warning` ones a little taller, so problems show without colour too.
 *
 * Static unless `onSelect` is given: one image whose `label` says what the cells add up to ("14 requests: 12
 * completed, 1 failed, 1 cancelled"). With `onSelect` each cell is a button in a Base UI Toolbar, which owns the one
 * tab stop and the arrow keys between cells; a cell's `label` is its name and its tooltip. `max` keeps the latest
 * cells and counts the earlier ones in front ("+140"); the label should still describe all of them.
 */
export function Tape({ cells, label, size = 'md', max, onSelect, className }: {
  cells: readonly TapeCell[];
  label: string;
  /** `sm` for a row of a list, `md` for a page's own tape. */
  size?: 'sm' | 'md';
  max?: number;
  onSelect?(key: string): void;
  className?: string;
}) {
  const shown = max != null && cells.length > max ? cells.slice(-max) : cells;
  const earlier = cells.length - shown.length;
  const classes = cx('ui-tape', `ui-tape--${size}`, className);
  if (!onSelect) return <span role="img" aria-label={label} className={classes}>
    {earlier > 0 && <span className="ui-tape__earlier" aria-hidden="true">+{earlier}</span>}
    {shown.map(cell => <span key={cell.key} className="ui-tape__cell" data-tone={cell.tone} data-dim={cell.dim || undefined} />)}
  </span>;
  return <Toolbar.Root aria-label={label} className={classes}>
    {earlier > 0 && <span className="ui-tape__earlier" aria-hidden="true">+{earlier}</span>}
    {shown.map(cell => <Tooltip key={cell.key} content={cell.label} delay={0}>
      <Toolbar.Button className="ui-tape__cell" data-tone={cell.tone} data-dim={cell.dim || undefined} aria-label={cell.label} onClick={() => onSelect(cell.key)} />
    </Tooltip>)}
  </Toolbar.Root>;
}
