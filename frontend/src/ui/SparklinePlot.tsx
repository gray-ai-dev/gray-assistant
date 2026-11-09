import { Area, AreaChart, ResponsiveContainer, YAxis } from 'recharts';
import { toneColor } from './ChartPlot';
import type { ChartSeries } from './Chart';

/** The drawing of `Sparkline`: a filled curve with no axes, scaled from zero. */
export default function SparklinePlot({ values, tone }: { values: readonly number[]; tone: ChartSeries['tone'] }) {
  const id = `ui-spark-${tone ?? 'primary'}`;
  return <ResponsiveContainer width="100%" height="100%">
    <AreaChart data={values.map((value, index) => ({ index, value }))} margin={{ top: 2, right: 0, bottom: 0, left: 0 }} accessibilityLayer={false}>
      <defs><linearGradient id={id} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={toneColor(tone)} stopOpacity={0.18} /><stop offset="100%" stopColor={toneColor(tone)} stopOpacity={0} /></linearGradient></defs>
      <YAxis hide domain={[0, 'dataMax']} />
      <Area type="monotone" dataKey="value" stroke={toneColor(tone)} strokeWidth={1.5} fill={`url(#${id})`} isAnimationActive={false} dot={false} />
    </AreaChart>
  </ResponsiveContainer>;
}
