import { lazy, Suspense, useId } from 'react';
import { cx } from './cx';
import './chart.css';

/** One series of a chart. `tone` colours it: `primary` (ink) first, `secondary` and `tertiary` grays after it, `danger`
 *  for failures; the legend and the data table say what it is. */
export type ChartSeries = { key: string; label: string; tone?: 'primary' | 'secondary' | 'tertiary' | 'danger' | 'neutral' };
/** One point on the time axis: its label (an hour, a day) and a value per series key. */
export type ChartPoint = { key: string; label: string; values: Record<string, number> };

const ChartPlot = lazy(() => import('./ChartPlot'));
const compact = new Intl.NumberFormat('en-US', { notation: 'compact', maximumSignificantDigits: 3 });

/**
 * A chart of values over time: bars (counts per hour or day, stacked by series), an area (a running total such as
 * spend) or lines (a measure such as latency). Recharts draws the plot, its axes and the readout under the pointer,
 * loaded with the first chart a page shows; the design system supplies the heading, the legend and the colours. For
 * assistive technology the plot is one image with a summary, and the same numbers are in a visually hidden table.
 */
export function TimeChart({ label, summary, series, points, kind = 'bar', stacked = true, format = n => n.toLocaleString('en-US'), axisFormat = n => compact.format(n), height = 200, className, actions }: {
  /** What the chart shows, e.g. "Requests per hour". Names the figure and its table. */
  label: string;
  /** One sentence for screen readers, e.g. the totals. */
  summary: string;
  series: readonly ChartSeries[];
  points: readonly ChartPoint[];
  kind?: 'bar' | 'area' | 'line';
  /** Stack the series (bars and areas); lines never stack. */
  stacked?: boolean;
  /** Exact values in the readout and the table, e.g. dollars. */
  format?: (value: number) => string;
  /** Short values on the value axis, e.g. "1.2K" or "$40". */
  axisFormat?: (value: number) => string;
  height?: number;
  className?: string;
  /** Controls at the end of the heading row, e.g. a metric switch. */
  actions?: React.ReactNode;
}) {
  const id = useId();
  return <figure className={cx('ui-chart', className)} aria-labelledby={`${id}-label`}>
    <figcaption className="ui-chart__head">
      <span id={`${id}-label`} className="ui-chart__label">{label}</span>
      <span className="ui-chart__legend">{series.length > 1 && series.map(s => <span key={s.key} className="ui-chart__key"><span className="ui-chart__swatch" data-tone={s.tone ?? 'primary'} data-kind={kind} aria-hidden="true" />{s.label}</span>)}{actions}</span>
    </figcaption>
    <div className="ui-chart__plot" role="img" aria-label={`${label}. ${summary}`} style={{ height }}>
      <Suspense fallback={null}><ChartPlot kind={kind} stacked={stacked} series={series} points={points} format={format} axisFormat={axisFormat} /></Suspense>
    </div>
    <table className="ui-sr-only">
      <caption>{label}</caption>
      <thead><tr><th scope="col">Time</th>{series.map(s => <th key={s.key} scope="col">{s.label}</th>)}</tr></thead>
      <tbody>{points.map(point => <tr key={point.key}><th scope="row">{point.label}</th>{series.map(s => <td key={s.key}>{format(point.values[s.key] ?? 0)}</td>)}</tr>)}</tbody>
    </table>
  </figure>;
}
