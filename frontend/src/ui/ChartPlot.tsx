import { Area, AreaChart, Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { ChartPoint, ChartSeries } from './Chart';

const tick = { fill: 'var(--muted)', fontSize: 12 };
export const toneColor = (tone: ChartSeries['tone']) => tone === 'danger' ? 'var(--red)' : tone === 'secondary' ? 'var(--chart-2)' : tone === 'tertiary' ? 'var(--chart-3)' : 'var(--chart-1)';

type Hovered = { active?: boolean; label?: string | number; payload?: ReadonlyArray<{ dataKey?: unknown; value?: unknown }> };

/** What the pointer is over: the point's axis label, then one line per series with its exact value. */
function Readout({ active, label, payload, series, format }: Hovered & { series: readonly ChartSeries[]; format(value: number): string }) {
  if (!active || !payload?.length) return null;
  return <div className="ui-chart__readout">
    <span className="ui-chart__readout-title">{label}</span>
    {series.map(s => <span key={s.key} className="ui-chart__key"><span className="ui-chart__swatch" data-tone={s.tone ?? 'primary'} aria-hidden="true" />{s.label}
      <span className="ui-chart__readout-value">{format(Number(payload.find(item => item.dataKey === s.key)?.value ?? 0))}</span></span>)}
  </div>;
}

/** The plot of `TimeChart`, drawn by Recharts: a time axis that keeps its first and last label, a value axis in short
 *  figures, a dashed grid and a readout that follows the pointer. */
export default function ChartPlot({ kind, stacked, series, points, format, axisFormat }: {
  kind: 'bar' | 'area' | 'line'; stacked: boolean; series: readonly ChartSeries[]; points: readonly ChartPoint[];
  format(value: number): string; axisFormat(value: number): string;
}) {
  const still = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const data = points.map(point => ({ label: point.label, ...point.values }));
  const common = <>
    <CartesianGrid vertical={false} stroke="var(--chart-grid)" strokeDasharray="3 3" />
    <XAxis dataKey="label" tickLine={false} axisLine={{ stroke: 'var(--strong-border)' }} interval="equidistantPreserveStart" minTickGap={24} tick={tick} />
    <YAxis width={48} tickLine={false} axisLine={false} tickCount={4} tickFormatter={(value: number) => axisFormat(value)} tick={tick} />
    <Tooltip cursor={kind === 'bar' ? { fill: 'var(--muted-surface)' } : { stroke: 'var(--strong-border)' }} isAnimationActive={false} content={(hovered: Hovered) => <Readout {...hovered} series={series} format={format} />} />
  </>;
  const motion = { isAnimationActive: !still, animationDuration: 300 };
  const margin = { top: 8, right: 4, bottom: 0, left: 0 };
  return <ResponsiveContainer width="100%" height="100%">
    {kind === 'line' ? <LineChart data={data} margin={margin} accessibilityLayer={false}>
      {common}
      {series.map(s => <Line key={s.key} type="monotone" dataKey={s.key} name={s.label} stroke={toneColor(s.tone)} strokeWidth={2} dot={false} activeDot={{ r: 4 }} connectNulls {...motion} />)}
    </LineChart> : kind === 'area' ? <AreaChart data={data} margin={margin} accessibilityLayer={false}>
      <defs>{series.map(s => <linearGradient key={s.key} id={`ui-area-${s.key}`} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stopColor={toneColor(s.tone)} stopOpacity={0.22} /><stop offset="100%" stopColor={toneColor(s.tone)} stopOpacity={0.02} />
      </linearGradient>)}</defs>
      {common}
      {series.map(s => <Area key={s.key} type="monotone" dataKey={s.key} name={s.label} stackId={stacked ? 'total' : undefined} stroke={toneColor(s.tone)} strokeWidth={2} fill={`url(#ui-area-${s.key})`} {...motion} />)}
    </AreaChart> : <BarChart data={data} margin={margin} barCategoryGap={points.length > 40 ? 1 : 3} accessibilityLayer={false}>
      {common}
      {series.map((s, index) => <Bar key={s.key} dataKey={s.key} name={s.label} stackId={stacked ? 'total' : undefined} fill={toneColor(s.tone)}
        radius={stacked && index < series.length - 1 ? 0 : [2, 2, 0, 0]} {...motion} />)}
    </BarChart>}
  </ResponsiveContainer>;
}
