import { lazy, Suspense } from 'react';
import type { ChartSeries } from './Chart';

const SparklinePlot = lazy(() => import('./SparklinePlot'));

/** A small curve of a measure over a period, beside the figure that states it; decoration for sighted readers (the
 *  figure and its change carry the meaning). Drawn by Recharts with the charts. */
export function Sparkline({ values, tone = 'primary', className }: { values: readonly number[]; tone?: ChartSeries['tone']; className?: string }) {
  return <div className={className} aria-hidden="true"><Suspense fallback={null}><SparklinePlot values={values} tone={tone} /></Suspense></div>;
}
