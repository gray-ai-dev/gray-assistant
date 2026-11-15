import { useId, useMemo, type CSSProperties, type ReactNode } from 'react';
import { Toolbar } from '@cloudflare/kumo/primitives/toolbar';
import { Tooltip } from '@cloudflare/kumo/primitives/tooltip';
import { cx } from './cx';
import { usePopupPositionMethod } from './popup';
import './status-strip.css';

/** How long a pointer rests on a cell before its popup opens: at once to the eye, but not for a pointer crossing the strip. */
const HOVER_REST_MS = 50;

/** A result as a colour: `ok` passed, `warn` suspected, `bad` failed outright, `none` not checked. */
export type StatusTone = 'ok' | 'warn' | 'bad' | 'none';
/**
 * One period of a strip, e.g. an hour. `label` says it in words, as the cell's name: the popup it opens is a picture
 * of the same, kept from screen readers. `detail` is what opens from the cell (`StripDetail`).
 */
export type StatusStripCell = { key: string; tone: StatusTone; label: string; detail?: ReactNode };

/**
 * A run of periods in order, oldest first, as a status page draws them: a thin bar per period, all of one height, in
 * its result's colour (green passed, amber suspected, red failed), and a hairline on the baseline for a period nothing
 * checked, so gray means no data and nothing else. The period still running is drawn as the others. The bars rise in
 * order the first time the strip shows; with reduced motion they stand still.
 *
 * Base UI Toolbar owns the one tab stop and the arrow keys between cells. A cell's `detail` is a Base UI Tooltip: it
 * opens when the pointer rests on the cell, when the keyboard focus lands on it (so it follows the arrow keys), and on
 * a click or a tap (`closeOnClick` off, so touch has it too). It never takes the focus, so Tab leaves the strip in one
 * press, and it closes when the focus leaves the cell, on Escape or on a press elsewhere. `label` says what the cells
 * add up to ("Model check, last 24 hours, one cell per hour: 22 healthy, …"); `axis` names the strip's two ends under
 * it ("24h ago", "Now"). Strips listed one under another leave it out and name their ends once, under the last, with
 * `StatusAxis`.
 *
 * A strip with nothing to show yet takes a `state`: `loading` before its data first arrives (pale bars that pulse in
 * place, unless motion is reduced), `unavailable` when that read failed (hollow bars, so it never reads as periods
 * nothing checked). Its cells then open nothing, and `label` says so ("Model check, last 24 hours: loading").
 */
export function StatusStrip({ cells, label, axis, state, className }: {
  cells: readonly StatusStripCell[];
  label: string;
  axis?: readonly [ReactNode, ReactNode];
  state?: 'loading' | 'unavailable';
  className?: string;
}) {
  const handle = useMemo(() => Tooltip.createHandle<number>(), []);
  const id = useId();
  const positionMethod = usePopupPositionMethod();
  const times = axis && <StripTimes axis={axis} />;
  if (state) return <div className={cx('ui-strip', className)} style={{ '--ui-strip-cells': cells.length } as CSSProperties}>
    <div role="img" aria-label={label} aria-busy={state === 'loading' || undefined} className="ui-strip__cells" data-state={state}>
      {cells.map(cell => <span key={cell.key} className="ui-strip__cell" />)}
    </div>
    {times}
  </div>;
  return <div className={cx('ui-strip', className)} style={{ '--ui-strip-cells': cells.length } as CSSProperties}>
    <Toolbar.Root aria-label={label} className="ui-strip__cells">
      {cells.map((cell, index) => <Tooltip.Trigger key={cell.key} handle={handle} id={`${id}-${index}`} payload={index} delay={HOVER_REST_MS} closeOnClick={false}
        render={<Toolbar.Button className="ui-strip__cell" data-tone={cell.tone} aria-label={cell.label}
          style={{ '--ui-strip-index': index } as CSSProperties} onClick={event => handle.open(event.currentTarget.id)} />} />)}
    </Toolbar.Root>
    {times}
    <Tooltip.Root handle={handle}>{({ payload }) => {
      const cell = payload === undefined ? undefined : cells[payload];
      return cell?.detail == null ? null : <Tooltip.Portal>
        <Tooltip.Positioner className="ui-strip-positioner" positionMethod={positionMethod} side="bottom" sideOffset={8} collisionPadding={8}>
          <Tooltip.Popup className="ui-strip__popup" aria-hidden="true">{cell.detail}</Tooltip.Popup>
        </Tooltip.Positioner>
      </Tooltip.Portal>;
    }}</Tooltip.Root>
  </div>;
}

/** A strip's two ends under it, in the text face: where it starts and where it ends. */
function StripTimes({ axis }: { axis: readonly [ReactNode, ReactNode] }) {
  return <div className="ui-strip__axis" aria-hidden="true"><span>{axis[0]}</span><span>{axis[1]}</span></div>;
}

/**
 * A strip's two ends on their own, as `StatusStrip` names them under its bars: for a list of strips that line up,
 * each without its `axis`, so the ends are named once, under the last, as a status page does. A picture of the times,
 * hidden from screen readers: each strip's cells say theirs.
 */
export function StatusAxis({ axis, className }: { axis: readonly [ReactNode, ReactNode]; className?: string }) {
  return <div className={cx('ui-strip', className)}><StripTimes axis={axis} /></div>;
}

/**
 * What a period of a strip held, as its popup shows it, one look for every strip: its times with its result beside
 * them (`status`, the `Badge` the page names that result with elsewhere), then a few short lines (`lines`), e.g. a
 * line per round with its own result, and what the period changed.
 */
export function StripDetail({ title, status, lines }: { title: ReactNode; status?: ReactNode; lines: readonly ReactNode[] }) {
  return <div className="ui-strip-detail">
    <div className="ui-strip-detail__head"><span className="ui-strip-detail__title">{title}</span>{status}</div>
    {lines.map((line, index) => <div key={index} className="ui-strip-detail__line">{line}</div>)}
  </div>;
}
