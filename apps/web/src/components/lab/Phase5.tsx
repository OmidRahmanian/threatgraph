"use client";

import { api, useLoad } from "@/lib/data";
import { pct } from "@/lib/format";
import type { Drift, ModelInfo, ModelMetrics, SupervisedDecision } from "@/lib/types";
import { Callout, ErrorBlock, LoadingBlock, Panel, ProvenanceBadge, SectionTitle } from "../ui";

/** Deletion test: does the explanation point at what drives the score? */
export function FaithfulnessPanel({ metrics }: { metrics: ModelMetrics }) {
  const f = metrics.explanation_faithfulness;
  if (!f) return null;
  if (!f.estimable) {
    return (
      <Panel id="faithfulness">
        <SectionTitle title="Explanation faithfulness" subtitle="Not estimable for this model." />
        <p className="text-sm text-ink-2" data-testid="faithfulness-not-estimable">
          {f.note}
        </p>
      </Panel>
    );
  }
  return (
    <Panel id="faithfulness">
      <SectionTitle
        title="Explanation faithfulness"
        subtitle={`Deletion test on the ${f.n_alerts} test alerts: reset the k features the explanation ranks highest to their training medians and re-score, versus resetting k random features (${f.n_random_draws} draws).`}
      />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[620px] text-left text-sm tabular-nums" data-testid="faithfulness-table">
          <thead className="text-xs text-ink-3">
            <tr>
              <th className="py-1 pr-3 font-normal">k</th>
              <th className="py-1 pr-3 text-right font-normal">Mean score drop, explanation&apos;s top k</th>
              <th className="py-1 pr-3 text-right font-normal">Mean score drop, random k</th>
              <th className="py-1 pr-3 text-right font-normal">Falls below threshold, top k</th>
              <th className="py-1 pr-3 text-right font-normal">Falls below threshold, random k</th>
              <th className="py-1 text-right font-normal">Top k beats random</th>
            </tr>
          </thead>
          <tbody>
            {f.results.map((r) => (
              <tr key={r.k} className="border-t border-line">
                <td className="py-1 pr-3">{r.k}</td>
                <td className="py-1 pr-3 text-right">{r.mean_score_drop_top.toFixed(4)}</td>
                <td className="py-1 pr-3 text-right">{r.mean_score_drop_random.toFixed(4)}</td>
                <td className="py-1 pr-3 text-right">{pct(r.below_threshold_share_top, 0)}</td>
                <td className="py-1 pr-3 text-right">{pct(r.below_threshold_share_random, 0)}</td>
                <td className="py-1 text-right">{pct(r.top_beats_random_share, 0)} of alerts</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-xs text-ink-3">
        A faithful explanation lowers the score more than random features do. This tests whether the ranking is useful, not that it
        is the model&apos;s internal reasoning. Resetting to the median is itself a choice of baseline.
      </p>
    </Panel>
  );
}

export function SupervisedNote({ decision }: { decision: SupervisedDecision }) {
  return (
    <Callout title={decision.trained ? "Supervised model" : "Supervised model (M2): not trained"}>
      <p data-testid="supervised-note">{decision.reason}</p>
      <p>The rule is fixed in configs/models.yaml before looking at results, so the decision cannot be tuned to the outcome.</p>
    </Callout>
  );
}

function psiBucket(v: number | null, t: Drift["thresholds"]): { fill: string; label: string } {
  if (v === null) return { fill: "transparent", label: "n/a" };
  if (v < t.stable) return { fill: "transparent", label: "stable" };
  if (v < t.major) return { fill: "var(--model-soft)", label: "moderate" };
  return { fill: "color-mix(in oklab, var(--model) 45%, var(--panel))", label: "major" };
}

export function DriftPanel({ models }: { models: ModelInfo[] }) {
  const state = useLoad(api.drift, "drift");
  if (state.status === "loading") return <LoadingBlock label="Loading drift monitor…" />;
  if (state.status === "error") return <ErrorBlock error={state.error} />;
  const d = state.data;
  const name = (id: string) => models.find((m) => m.model_id === id)?.display_name.split(" · ")[0] ?? id;
  const rows: { key: string; label: string; get: (day: Drift["days"][number]) => number | null; note?: string }[] = [
    ...d.models.map((m) => ({ key: `score-${m}`, label: `${name(m)} score`, get: (day: Drift["days"][number]) => day.score_psi[m] ?? null })),
    ...d.features.map((f) => ({ key: f, label: f, get: (day: Drift["days"][number]) => day.feature_psi[f] ?? null, note: d.expected_drift[f] })),
  ];
  const bucketCell = (key: string, v: number | null) => {
    const b = psiBucket(v, d.thresholds);
    return (
      <td key={key} className="border border-line px-1 py-0.5 text-right" style={{ background: b.fill }} title={`PSI ${v === null ? "n/a" : v.toFixed(3)} (${b.label})`}>
        {v === null ? "N/A" : v.toFixed(2)}
      </td>
    );
  };
  return (
    <Panel id="drift">
      <SectionTitle
        title="Drift monitor"
        subtitle={`Population stability index of each day's windows against the ${d.reference} (${d.bins} quantile bins), and the daily alert rate against the ${pct(d.alert_budget, 0)} budget the thresholds were set for.`}
        right={<ProvenanceBadge provenance={d.provenance} />}
      />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left text-[11px] tabular-nums" data-testid="drift-table">
          <thead className="text-ink-3">
            <tr>
              <th className="py-1 pr-2 font-normal">PSI by day</th>
              {d.days.map((day) => (
                <th key={day.day} className="px-1 py-1 text-right font-normal">
                  D{day.day}
                  <div className="text-[10px]">{day.split.slice(0, 5)}</div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key}>
                <th scope="row" className="py-0.5 pr-2 text-left font-mono font-normal text-ink-2" title={r.note}>
                  {r.label}
                  {r.note ? <span className="ml-1 font-sans text-ink-3">(drifts by design)</span> : null}
                </th>
                {d.days.map((day) => bucketCell(`${r.key}-${day.day}`, r.get(day)))}
              </tr>
            ))}
            {d.models.map((m) => (
              <tr key={`alerts-${m}`} className="border-t-2 border-line">
                <th scope="row" className="py-0.5 pr-2 text-left font-normal text-ink-2">
                  {name(m)} alert rate
                </th>
                {d.days.map((day) => {
                  const rate = day.alert_rate[m];
                  const over = rate > 2 * d.alert_budget;
                  return (
                    <td key={day.day} className={`border border-line px-1 py-0.5 text-right ${over ? "font-semibold text-ink" : "text-ink-2"}`}>
                      {(rate * 100).toFixed(1)}%
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-ink-2" aria-label="Drift legend">
        <li className="flex items-center gap-1.5">
          <span className="inline-block h-3 w-5 border border-line" /> stable (&lt; {d.thresholds.stable})
        </li>
        <li className="flex items-center gap-1.5">
          <span className="inline-block h-3 w-5 border border-line" style={{ background: "var(--model-soft)" }} /> moderate ({d.thresholds.stable}–{d.thresholds.major})
        </li>
        <li className="flex items-center gap-1.5">
          <span className="inline-block h-3 w-5 border border-line" style={{ background: "color-mix(in oklab, var(--model) 45%, var(--panel))" }} /> major (&gt; {d.thresholds.major})
        </li>
        <li>Bold alert rate: more than twice the budget.</li>
      </ul>
      <p className="mt-2 text-xs text-ink-3">
        {d.semantics}
        {Object.entries(d.expected_drift).map(([f, why]) => ` ${f} ${why}`)}
      </p>
    </Panel>
  );
}
