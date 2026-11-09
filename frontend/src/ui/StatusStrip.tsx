import { useId, useMemo, type CSSProperties, type ReactNode } from 'react';
import { Toolbar } from '@cloudflare/kumo/primitives/toolbar';
import { Tooltip } from '@cloudflare/kumo/primitives/tooltip';
import { cx } from './cx';
import { Meter } from './Meter';
import { usePopupPositionMethod } from './popup';
import './status-strip.css';

/** How long a pointer rests on a cell before its popup opens: at once to the eye, but not for a pointer crossing the strip. */
const HOVER_REST_MS = 50;

/** A result as a colour: `ok` passed, `warn` suspected, `bad` failed outright, `none` not checked. */
export type StatusTone = 'ok' | 'warn' | 'bad' | 'none';
/**
 * One period of a strip, e.g. an hour. `label` says it in words, as the cell's name: the popup it opens is a picture
 * of the same, kept from screen readers. `live` marks the period still running; `detail` is what opens from the cell.
 */
export type StatusStripCell = { key: string; tone: StatusTone; label: string; live?: boolean; detail?: ReactNode };

/**
 * A run of periods in order, oldest first, one cell each coloured by its result, like a status page: a day of hourly
 * checks, the current hour outlined and breathing while it runs. The cells rise in order the first time the strip
 * shows; with reduced motion they stand still.
 *
 * Base UI Toolbar owns the one tab stop and the arrow keys between cells. A cell's `detail` is a Base UI Tooltip: it
 * opens when the pointer rests on the cell, when the keyboard focus lands on it (so it follows the arrow keys), and on
 * a click or a tap (`closeOnClick` off, so touch has it too). It never takes the focus, so Tab leaves the strip in one
 * press, and it closes when the focus leaves the cell, on Escape or on a press elsewhere. `label` says what the cells
 * add up to ("Model check, last 24 hours, one cell per hour: 22 healthy, …"); `axis` writes three times under the
 * strip: at the first cell, the middle one and the last.
 *
 * A strip with nothing to show yet takes a `state`: `loading` before its data first arrives (its cells pulse, unless
 * motion is reduced), `unavailable` when that read failed. Its cells then open nothing, and `label` says so
 * ("Model check, last 24 hours: loading").
 */
export function StatusStrip({ cells, label, axis, state, className }: {
  cells: readonly StatusStripCell[];
  label: string;
  axis?: readonly [ReactNode, ReactNode, ReactNode];
  state?: 'loading' | 'unavailable';
  className?: string;
}) {
  const handle = useMemo(() => Tooltip.createHandle<number>(), []);
  const id = useId();
  const positionMethod = usePopupPositionMethod();
  const times = axis && <div className="ui-strip__axis" aria-hidden="true">
    <span>{axis[0]}</span>
    <span style={{ gridColumnStart: Math.floor(cells.length / 2) + 1 }}>{axis[1]}</span>
    <span>{axis[2]}</span>
  </div>;
  if (state) return <div className={cx('ui-strip', className)} style={{ '--ui-strip-cells': cells.length } as CSSProperties}>
    <div role="img" aria-label={label} aria-busy={state === 'loading' || undefined} className="ui-strip__cells" data-state={state}>
      {cells.map(cell => <span key={cell.key} className="ui-strip__cell" data-tone="none" />)}
    </div>
    {times}
  </div>;
  return <div className={cx('ui-strip', className)} style={{ '--ui-strip-cells': cells.length } as CSSProperties}>
    <Toolbar.Root aria-label={label} className="ui-strip__cells">
      {cells.map((cell, index) => <Tooltip.Trigger key={cell.key} handle={handle} id={`${id}-${index}`} payload={index} delay={HOVER_REST_MS} closeOnClick={false}
        render={<Toolbar.Button className="ui-strip__cell" data-tone={cell.tone} data-live={cell.live || undefined} aria-label={cell.label}
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

/**
 * What a strip's colours mean, a swatch beside each name (a small cell, shaped as the strip's are); `marks` what the
 * marks of an opened period mean, each drawn as `RoundTiles` draws it. In a strip's popup, `marks` alone are one line
 * at the bottom, set closer.
 */
export function StatusLegend({ items = [], marks = [], label = 'Legend' }: {
  items?: readonly { tone: StatusTone; label: string }[];
  marks?: readonly { mark: RoundMark; label: string }[];
  label?: string;
}) {
  return <ul className="ui-strip-legend" aria-label={label}>
    {items.map(item => <li key={item.tone}><span className="ui-strip-legend__swatch" data-tone={item.tone} aria-hidden="true" />{item.label}</li>)}
    {marks.map(item => <li key={item.mark}><span className="ui-round-tiles__mark" data-mark={item.mark} aria-hidden="true" />{item.label}</li>)}
  </ul>;
}

/** A round's answer as a mark: like the declared model, unlike it, or not usable (counted as unlike it). */
export type RoundMark = 'declared' | 'unlike' | 'unusable';

/**
 * The rounds of a period as tiles, one per round, a mark per answer: a green dot like the declared model, a red dot
 * unlike it, a red ring for an answer that was not usable (a refusal, a tool call, garbage), which counts as unlike it.
 * An alarmed round (no answer like it) is outlined in red, so a round of three refusals reads red; `slots` pads the
 * period with empty tiles for the rounds it has still to run. A picture only (hidden from screen readers): the words
 * are the cell's name.
 */
export function RoundTiles({ rounds, slots = 0 }: {
  rounds: readonly { key: string; answers: readonly RoundMark[]; alarm?: boolean }[];
  slots?: number;
}) {
  const empty = Math.max(0, slots - rounds.length);
  return <div className="ui-round-tiles" aria-hidden="true">
    {rounds.map((round, index) => <span key={round.key} className="ui-round-tiles__tile" data-alarm={round.alarm || undefined} style={{ '--ui-round-index': index } as CSSProperties}>
      {round.answers.map((mark, answer) => <span key={answer} className="ui-round-tiles__mark" data-mark={mark} />)}
    </span>)}
    {Array.from({ length: empty }, (_, index) => <span key={`empty-${index}`} className="ui-round-tiles__tile" data-empty="" />)}
  </div>;
}

const MARKS: Record<StatusTone, string> = { ok: 'M7.5 12.4l3 3 6-6.6', warn: 'M12 7v6M12 16.9v.1', bad: 'M8.8 8.8l6.4 6.4M15.2 8.8l-6.4 6.4', none: 'M8.5 12h7' };
const RING = 2 * Math.PI * 9;

/**
 * A result as a glyph, set beside the words that name it (it is hidden from screen readers): `ok` a check, `warn` an
 * exclamation, `bad` a cross, `none` a dash in an open circle. With `progress` (0 to 1) it is a ring filling toward a
 * first result; it fills in when it appears and moves on as the share grows. At 0 it is the empty ring alone, e.g. a
 * check whose first round is still to come.
 */
export function StatusGlyph({ tone = 'none', progress }: { tone?: StatusTone; progress?: number }) {
  if (progress !== undefined) {
    const share = Math.min(1, Math.max(0, progress));
    return <svg className="ui-glyph" viewBox="0 0 24 24" aria-hidden="true" style={{ '--ui-glyph-ring': RING } as CSSProperties}>
      <circle className="ui-glyph__track" cx="12" cy="12" r="9" />
      {/* No arc at 0: a dash of no length would still draw its round cap, a dot at the top. */}
      {share > 0 && <circle className="ui-glyph__arc" cx="12" cy="12" r="9" transform="rotate(-90 12 12)" style={{ strokeDasharray: `${RING} ${RING}`, strokeDashoffset: RING * (1 - share) }} />}
    </svg>;
  }
  return <svg className="ui-glyph" data-tone={tone} viewBox="0 0 24 24" aria-hidden="true">
    <circle className="ui-glyph__disc" cx="12" cy="12" r={tone === 'none' ? 9.25 : 10} />
    <path className="ui-glyph__mark" d={MARKS[tone]} />
  </svg>;
}

/**
 * A multiplier from its floor up to 1 as a bar with its value under it, e.g. the ranking weight a provider has now or
 * had after an hour. Base UI Meter carries the value to screen readers (`label` names it, `text` says it: "×0.25"); the
 * bar moves to a new value instead of jumping.
 */
export function WeightBar({ value, text, label = 'Ranking weight', className }: { value: number; text: string; label?: string; className?: string }) {
  return <span className={cx('ui-weight', className)}>
    <Meter value={value} max={1} label={label} valueText={text} size="md" tone="strong" />
    <span className="ui-weight__text" aria-hidden="true">{text}</span>
  </span>;
}
