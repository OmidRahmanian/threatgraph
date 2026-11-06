"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ReferenceDot,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { pct, ratio, score as fmtScore } from "@/lib/format";
import type { ThresholdMetrics } from "@/lib/threshold";
import type { ScoreRow, SplitMetrics } from "@/lib/types";

const AXIS = { stroke: "var(--line)", tick: { fill: "var(--ink-3)", fontSize: 12 }, tickLine: false };

function TooltipBox({ children }: { children: React.ReactNode }) {
  return <div className="rounded-md border border-line bg-panel px-3 py-2 text-xs text-ink-2 shadow-lg">{children}</div>;
}

export function PRCurve({ metrics, op }: { metrics: SplitMetrics; op: ThresholdMetrics }) {
  const pts = [...metrics.pr_curve].sort((a, b) => b.threshold - a.threshold);
  if (!metrics.average_precision_estimable || pts.length === 0) {
    return (
      <p className="rounded-lg border border-line bg-panel-2 p-4 text-sm text-ink-2">
        Not estimable: this split has no known red-team windows, so precision/recall cannot be computed.
      </p>
    );
  }
  return (
    <figure>
      <div className="mb-2 text-xs text-ink-3" aria-hidden>
        ↑ Precision (lower bound) · → Known-label recall
      </div>
      <div className="h-64 w-full" role="img" aria-label={`Precision-recall curve, average precision ${ratio(metrics.average_precision)}`}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={pts} margin={{ top: 8, right: 12, bottom: 22, left: 0 }}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis
              {...AXIS}
              type="number"
              dataKey="recall"
              domain={[0, 1]}
              ticks={[0, 0.25, 0.5, 0.75, 1]}
              label={{ value: "Known-label recall", position: "insideBottom", offset: -14, fill: "var(--ink-3)", fontSize: 12 }}
            />
            <YAxis
              {...AXIS}
              type="number"
              domain={[0, 1]}
              ticks={[0, 0.25, 0.5, 0.75, 1]}
              width={40}
            />
            {metrics.random_ranking_average_precision !== null ? (
              <ReferenceLine y={metrics.random_ranking_average_precision} stroke="var(--ink-3)" />
            ) : null}
            <Line type="linear" dataKey="precision" stroke="var(--model)" strokeWidth={2} dot={false} isAnimationActive={false} />
            {op.precisionLowerBound !== null && op.knownLabelRecall !== null ? (
              <ReferenceDot x={op.knownLabelRecall} y={op.precisionLowerBound} r={5} fill="var(--ink)" stroke="var(--panel)" strokeWidth={2} />
            ) : null}
            <Tooltip
              cursor={{ stroke: "var(--ink-3)" }}
              content={({ active, payload }) =>
                active && payload?.length ? (
                  <TooltipBox>
                    <div>Threshold {fmtScore(payload[0].payload.threshold)}</div>
                    <div>Recall {ratio(payload[0].payload.recall)}</div>
                    <div>Precision {ratio(payload[0].payload.precision)}</div>
                  </TooltipBox>
                ) : null
              }
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="mt-2 text-xs text-ink-3">
        Curve from stored held-out scores. Dark dot = current threshold. Grey horizontal line = precision of a random ranking (
        {ratio(metrics.random_ranking_average_precision)}). AP {ratio(metrics.average_precision)}.
      </figcaption>
    </figure>
  );
}

interface Bin {
  key: string;
  lo: number;
  hi: number;
  unlabeled: number;
  known: number;
  unlabeledShare: number;
  knownShare: number;
}

export function binScores(rows: readonly ScoreRow[], nBins = 30): Bin[] {
  if (rows.length === 0) return [];
  let min = Infinity;
  let max = -Infinity;
  for (const r of rows) {
    min = Math.min(min, r[1]);
    max = Math.max(max, r[1]);
  }
  const width = max > min ? (max - min) / nBins : 1;
  const bins: Bin[] = Array.from({ length: nBins }, (_, i) => ({
    key: String(i),
    lo: min + i * width,
    hi: min + (i + 1) * width,
    unlabeled: 0,
    known: 0,
    unlabeledShare: 0,
    knownShare: 0,
  }));
  let nKnown = 0;
  let nUnl = 0;
  for (const [, s, label] of rows) {
    const i = Math.min(nBins - 1, Math.floor((s - min) / width));
    if (label === 1) {
      bins[i].known += 1;
      nKnown += 1;
    } else {
      bins[i].unlabeled += 1;
      nUnl += 1;
    }
  }
  for (const b of bins) {
    b.unlabeledShare = nUnl ? b.unlabeled / nUnl : 0;
    b.knownShare = nKnown ? b.known / nKnown : 0;
  }
  return bins;
}

export function ScoreDistribution({ rows, threshold }: { rows: readonly ScoreRow[]; threshold: number }) {
  const bins = binScores(rows);
  const tBin = bins.find((b, i) => threshold >= b.lo && (threshold < b.hi || i === bins.length - 1));
  return (
    <figure>
      <div className="mb-2 flex flex-wrap gap-4 text-xs text-ink-2" aria-hidden>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: "var(--model)" }} /> Unlabeled windows
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rotate-45 rounded-[1px]" style={{ background: "var(--redteam)" }} /> Known red-team windows
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-3 w-0.5" style={{ background: "var(--ink)" }} /> Threshold
        </span>
      </div>
      <div className="h-56 w-full" role="img" aria-label="Score distribution by label class, as share of each class">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={bins} margin={{ top: 8, right: 12, bottom: 22, left: 0 }} barGap={2} barCategoryGap={2}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis
              {...AXIS}
              dataKey="key"
              interval={4}
              tickFormatter={(k: string) => fmtScore(bins[Number(k)]?.lo ?? 0)}
              label={{ value: "Anomaly score (higher = more unusual)", position: "insideBottom", offset: -14, fill: "var(--ink-3)", fontSize: 12 }}
            />
            <YAxis {...AXIS} width={40} tickFormatter={(v: number) => `${Math.round(v * 100)}%`} />
            <Bar dataKey="unlabeledShare" fill="var(--model)" radius={[2, 2, 0, 0]} maxBarSize={24} isAnimationActive={false} />
            <Bar dataKey="knownShare" fill="var(--redteam)" radius={[2, 2, 0, 0]} maxBarSize={24} isAnimationActive={false} />
            {tBin ? <ReferenceLine x={tBin.key} stroke="var(--ink)" strokeWidth={1.5} /> : null}
            <Tooltip
              cursor={{ fill: "var(--panel-2)" }}
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const b = payload[0].payload as Bin;
                return (
                  <TooltipBox>
                    <div className="text-ink">
                      Score {fmtScore(b.lo)} – {fmtScore(b.hi)}
                    </div>
                    <div>
                      Unlabeled: {b.unlabeled} ({pct(b.unlabeledShare)})
                    </div>
                    <div>
                      Known red-team: {b.known} ({pct(b.knownShare)})
                    </div>
                  </TooltipBox>
                );
              }}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="mt-2 text-xs text-ink-3">
        Bars show the share of each class in each score bin, so the few known red-team windows stay visible next to thousands of
        unlabeled ones.
      </figcaption>
      <details className="mt-2 text-xs text-ink-2">
        <summary className="cursor-pointer">Data table</summary>
        <div className="mt-2 max-h-48 overflow-auto">
          <table className="w-full text-left tabular-nums">
            <thead className="text-ink-3">
              <tr>
                <th className="pr-3 font-normal">Score bin</th>
                <th className="pr-3 font-normal">Unlabeled</th>
                <th className="font-normal">Known red-team</th>
              </tr>
            </thead>
            <tbody>
              {bins
                .filter((b) => b.unlabeled || b.known)
                .map((b) => (
                  <tr key={b.key} className="border-t border-line">
                    <td className="pr-3">
                      {fmtScore(b.lo)} – {fmtScore(b.hi)}
                    </td>
                    <td className="pr-3">{b.unlabeled}</td>
                    <td>{b.known}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}
