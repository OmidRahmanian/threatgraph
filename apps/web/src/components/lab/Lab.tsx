"use client";

import { useMemo, useState } from "react";
import { api, useLoad } from "@/lib/data";
import { duration, int, ratio, relTime, score as fmtScore } from "@/lib/format";
import { rankRows, thresholdLadder, thresholdMetrics } from "@/lib/threshold";
import type { Ablation, EvalSplit, Metadata, ModelInfo, ModelMetrics, ScoreRow, ScoreTable } from "@/lib/types";
import {
  AlertBadge,
  Callout,
  ErrorBlock,
  KnownRedteamBadge,
  LoadingBlock,
  Panel,
  ProvenanceBadge,
  SectionTitle,
  Segmented,
  UnlabeledBadge,
} from "../ui";
import { PRCurve, ScoreDistribution } from "./Charts";
import { ExplanationView } from "./ExplanationView";
import { ThresholdPanel } from "./ThresholdPanel";

const SPLITS: { value: EvalSplit; label: string }[] = [
  { value: "test", label: "Test (held out)" },
  { value: "validation", label: "Validation" },
];

export function parseWindowId(id: string): { principal: string; start: number } {
  const rest = id.slice(2);
  const cut = rest.lastIndexOf(":");
  return { principal: rest.slice(0, cut), start: Number(rest.slice(cut + 1)) };
}

export function Lab() {
  const base = useLoad(() => Promise.all([api.models(), api.metadata()]), "lab-base");
  const [modelId, setModelId] = useState<string | null>(null);
  if (base.status === "loading") return <LoadingBlock label="Loading models…" />;
  if (base.status === "error") return <ErrorBlock error={base.error} />;
  const [models, meta] = base.data;
  const active = modelId ?? models.models.at(-1)?.model_id ?? "";
  const model = models.models.find((m) => m.model_id === active)!;

  return (
    <div className="space-y-6 fade-in">
      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">ML Experiment Lab</h1>
          <ProvenanceBadge provenance={models.provenance} />
        </div>
        <p className="max-w-3xl text-sm leading-relaxed text-ink-2">
          Every number here is recomputed in your browser from the persisted held-out score table of the selected model — nothing
          is retrained and nothing is typed in by hand. Scores rank how unusual an account-hour is; they are not probabilities of
          compromise.
        </p>
      </header>

      <Panel>
        <SectionTitle
          title="Model comparison"
          subtitle="Stored metrics at each model's validation-calibrated threshold (top 1% of validation windows alerted)."
        />
        <ComparisonTable models={models.models} />
      </Panel>

      {models.ablations.map((a) => (
        <AblationPanel key={a.ablation_id} ablation={a} models={models.models} />
      ))}

      <div className="flex flex-wrap items-center gap-3">
        <Segmented
          label="Model"
          value={active}
          onChange={setModelId}
          options={models.models.map((m) => ({ value: m.model_id, label: m.display_name }))}
        />
      </div>

      <ModelWorkspace key={active} model={model} meta={meta} />
    </div>
  );
}

function ComparisonTable({ models }: { models: ModelInfo[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-sm" data-testid="comparison-table">
        <thead className="text-xs text-ink-3">
          <tr>
            <th className="py-1.5 pr-3 font-normal">Model</th>
            <th className="py-1.5 pr-3 font-normal">Split</th>
            <th className="py-1.5 pr-3 text-right font-normal">Average precision</th>
            <th className="py-1.5 pr-3 text-right font-normal">Random-ranking AP</th>
            <th className="py-1.5 pr-3 text-right font-normal">Precision@10</th>
            <th className="py-1.5 pr-3 text-right font-normal">Alerts</th>
            <th className="py-1.5 pr-3 text-right font-normal">Known-label recall</th>
            <th className="py-1.5 text-right font-normal">Precision (lower bound)</th>
          </tr>
        </thead>
        <tbody className="tabular-nums">
          {models.flatMap((m) =>
            m.headline.map((h, i) => (
              <tr key={`${m.model_id}-${h.split}`} className={i === 0 ? "border-t border-line" : ""}>
                <td className="py-1.5 pr-3 text-ink">{i === 0 ? m.display_name : ""}</td>
                <td className="py-1.5 pr-3 text-ink-2">{h.split}</td>
                <td className="py-1.5 pr-3 text-right">{ratio(h.average_precision)}</td>
                <td className="py-1.5 pr-3 text-right text-ink-3">{ratio(h.random_ranking_average_precision)}</td>
                <td className="py-1.5 pr-3 text-right">{ratio(h.precision_at_10, 2)}</td>
                <td className="py-1.5 pr-3 text-right">{int(h.alerts)}</td>
                <td className="py-1.5 pr-3 text-right">{ratio(h.known_label_recall)}</td>
                <td className="py-1.5 text-right">{ratio(h.precision_lower_bound)}</td>
              </tr>
            )),
          )}
        </tbody>
      </table>
      <p className="mt-2 text-xs text-ink-3">
        n/e = not estimable (no known positives). With a handful of known red-team windows per split, differences between models
        carry large uncertainty; no confidence intervals are computed yet.
      </p>
    </div>
  );
}

function AblationPanel({ ablation: a, models }: { ablation: Ablation; models: ModelInfo[] }) {
  const name = (id: string) => models.find((m) => m.model_id === id)?.display_name ?? id;
  return (
    <Panel id="ablation">
      <SectionTitle
        title={a.title}
        subtitle={
          <>
            {name(a.candidate)} adds {a.added_features.map((f) => <code key={f} className="mr-1 font-mono text-xs">{f}</code>)}
            to {name(a.baseline)}; everything else (hyperparameters, seed, threshold policy) is the same.
          </>
        }
      />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[600px] text-left text-sm tabular-nums" data-testid="ablation-table">
          <thead className="text-xs text-ink-3">
            <tr>
              <th className="py-1.5 pr-3 font-normal">Split</th>
              <th className="py-1.5 pr-3 text-right font-normal">Known red-team windows</th>
              <th className="py-1.5 pr-3 text-right font-normal">AP without graph features</th>
              <th className="py-1.5 pr-3 text-right font-normal">AP with graph features</th>
              <th className="py-1.5 pr-3 text-right font-normal">Change in AP</th>
              <th className="py-1.5 pr-3 text-right font-normal">Recall without</th>
              <th className="py-1.5 text-right font-normal">Recall with</th>
            </tr>
          </thead>
          <tbody>
            {a.splits.map((s) => (
              <tr key={s.split} className="border-t border-line">
                <td className="py-1.5 pr-3 text-ink-2">{s.split}</td>
                <td className="py-1.5 pr-3 text-right">{s.n_positive_windows}</td>
                <td className="py-1.5 pr-3 text-right">{ratio(s.baseline.average_precision)}</td>
                <td className="py-1.5 pr-3 text-right">{ratio(s.candidate.average_precision)}</td>
                <td className="py-1.5 pr-3 text-right">
                  {s.average_precision_delta === null ? "n/e" : `${s.average_precision_delta >= 0 ? "+" : "−"}${Math.abs(s.average_precision_delta).toFixed(3)}`}
                </td>
                <td className="py-1.5 pr-3 text-right">{ratio(s.baseline.known_label_recall)}</td>
                <td className="py-1.5 text-right">{ratio(s.candidate.known_label_recall)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-sm text-ink-2">{a.note}</p>
    </Panel>
  );
}

function ModelWorkspace({ model, meta }: { model: ModelInfo; meta: Metadata }) {
  const [split, setSplit] = useState<EvalSplit>("test");
  const data = useLoad(
    () => Promise.all([api.metrics(model.model_id), api.scores(model.model_id, split), api.explanationsAvailable(model.model_id, split)]),
    `${model.model_id}|${split}`,
  );
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented label="Evaluation split" value={split} onChange={setSplit} options={SPLITS} />
        {split === "validation" ? (
          <span className="text-xs text-ink-3">The threshold was calibrated on this split — treat its numbers as optimistic.</span>
        ) : null}
      </div>
      {data.status === "loading" ? <LoadingBlock label="Loading held-out scores…" /> : null}
      {data.status === "error" ? <ErrorBlock error={data.error} /> : null}
      {data.status === "ready" ? (
        <SplitWorkspace
          key={split}
          model={model}
          meta={meta}
          split={split}
          metrics={data.data[0]}
          table={data.data[1]}
          explained={data.data[2]}
        />
      ) : null}
    </div>
  );
}

function SplitWorkspace({
  model,
  meta,
  split,
  metrics,
  table,
  explained,
}: {
  model: ModelInfo;
  meta: Metadata;
  split: EvalSplit;
  metrics: ModelMetrics;
  table: ScoreTable;
  explained: Set<string> | "all";
}) {
  const ladder = useMemo(() => thresholdLadder(table.rows), [table]);
  // A truncated table is exact only above its cutoff; if the calibrated threshold lies below
  // it, start at the lowest exact threshold instead (the stored metrics stay in the table above).
  const calibratedExact = !table.truncated || table.exact_above === null || table.calibrated_threshold > table.exact_above;
  const start = calibratedExact ? table.calibrated_threshold : (ladder.at(-1) ?? table.calibrated_threshold);
  const [threshold, setThreshold] = useState(start);
  const [selected, setSelected] = useState<string | null>(null);
  const ranked = useMemo(() => rankRows(table.rows), [table]);
  const totals = useMemo(() => ({ rows: table.n_rows_total, knownPositives: table.n_known_positive_total }), [table]);
  const m = useMemo(() => thresholdMetrics(table.rows, threshold, table.n_days, totals), [table, threshold, totals]);
  const sm = metrics.splits[split];

  return (
    <div className="space-y-6">
      <Panel>
        <SectionTitle
          title="Threshold explorer"
          subtitle={`${int(table.n_rows_total)} ${split} windows · ${int(m.knownPositives)} known red-team · ${table.n_days} days`}
          right={<ProvenanceBadge provenance={table.provenance} />}
        />
        {table.truncated ? (
          <p className="mb-4 text-xs text-ink-3" data-testid="score-table-truncated">
            This split has {int(table.n_rows_total)} windows; the exported table holds the {int(table.rows.length)} highest scores
            (all above {fmtScore(table.exact_above ?? 0)}). Every count below is exact, because the slider only reaches thresholds
            above that cutoff.
            {calibratedExact ? null : " The calibrated threshold lies below it; its stored metrics are in the comparison table."}
          </p>
        ) : null}
        <ThresholdPanel ladder={ladder} threshold={threshold} calibrated={start} m={m} onChange={setThreshold} />
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel>
          <SectionTitle title="Precision–recall" right={<ProvenanceBadge provenance={metrics.provenance} />} />
          <PRCurve metrics={sm} op={m} />
        </Panel>
        <Panel>
          <SectionTitle title="Score distribution" right={<ProvenanceBadge provenance={table.provenance} />} />
          <ScoreDistribution rows={table.rows} threshold={threshold} />
        </Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <Panel className="lg:col-span-2">
          <SectionTitle title="Ranked windows" subtitle="Highest scores first. Select one to inspect its evidence." />
          <RankedWindows ranked={ranked} threshold={threshold} explained={explained} selected={selected} onSelect={setSelected} />
        </Panel>
        <Panel className="lg:col-span-3" id="sample-detail">
          <SectionTitle title="Sample detail" subtitle="Input features, deviation from the training period, and the raw events." />
          {selected ? (
            <ExplanationView modelId={model.model_id} split={split} windowId={selected} />
          ) : (
            <p className="text-sm text-ink-3">Select a window from the ranked list.</p>
          )}
        </Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel>
          <SectionTitle title="Precision@K" subtitle="Among the K highest-scored windows, how many are known red-team?" />
          <table className="w-full text-left text-sm tabular-nums">
            <thead className="text-xs text-ink-3">
              <tr>
                <th className="py-1 font-normal">K</th>
                <th className="py-1 text-right font-normal">Known red-team in top K</th>
                <th className="py-1 text-right font-normal">Precision@K</th>
              </tr>
            </thead>
            <tbody>
              {sm.precision_at_k.map((p) => (
                <tr key={p.k} className="border-t border-line">
                  <td className="py-1">{p.k}</td>
                  <td className="py-1 text-right">{p.known_positives}</td>
                  <td className="py-1 text-right">{ratio(p.precision, 2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel>
          <SectionTitle
            title="Detection latency"
            subtitle="Per account with known red-team activity, at the calibrated threshold: first labeled event → end of first alerted labeled window."
          />
          <table className="w-full text-left text-sm tabular-nums">
            <thead className="text-xs text-ink-3">
              <tr>
                <th className="py-1 font-normal">Account</th>
                <th className="py-1 font-normal">First labeled event</th>
                <th className="py-1 text-right font-normal">Windows alerted</th>
                <th className="py-1 text-right font-normal">Latency</th>
              </tr>
            </thead>
            <tbody>
              {sm.detection_latency.map((l) => (
                <tr key={l.principal} className="border-t border-line">
                  <td className="py-1 font-mono text-xs">{l.principal}</td>
                  <td className="py-1 text-xs">{relTime(l.first_labeled_event_seconds)}</td>
                  <td className="py-1 text-right">
                    {l.alerted_known_positive_windows} / {l.known_positive_windows}
                  </td>
                  <td className="py-1 text-right">{l.latency_seconds === null ? "not detected" : duration(l.latency_seconds)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-xs text-ink-3">Alerts are emitted at window end, so latency includes up to one window ({duration(meta.window_seconds)}).</p>
        </Panel>
      </div>

      <ModelCard model={model} meta={meta} metrics={metrics} />

      <Callout title="Evaluation assumptions and limitations">
        <ul className="list-disc space-y-1 pl-5">
          {metrics.evaluation_assumptions.map((a) => (
            <li key={a}>{a}</li>
          ))}
          <li>{meta.label_semantics}</li>
          {metrics.provenance.is_synthetic ? (
            <li>
              Synthetic demo: the fixture&apos;s attack and benign behaviors were designed by the author, so these results show the
              pipeline works end to end. They do not estimate performance on real enterprise data.
            </li>
          ) : null}
        </ul>
      </Callout>
    </div>
  );
}

function RankedWindows({
  ranked,
  threshold,
  explained,
  selected,
  onSelect,
}: {
  ranked: ScoreRow[];
  threshold: number;
  explained: Set<string> | "all";
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const [view, setView] = useState<"top" | "known">("top");
  const rows = useMemo(() => {
    const withRank = ranked.map((r, i) => ({ r, rank: i + 1 }));
    return view === "top" ? withRank.slice(0, 25) : withRank.filter(({ r }) => r[2] === 1);
  }, [ranked, view]);
  return (
    <div className="space-y-3">
      <Segmented
        label="Ranked list view"
        value={view}
        onChange={setView}
        options={[
          { value: "top", label: "Top 25" },
          { value: "known", label: "All known red-team" },
        ]}
      />
      <ul className="max-h-[560px] divide-y divide-line overflow-auto rounded-lg border border-line" data-testid="ranked-list">
        {rows.map(({ r: [id, s, label], rank }) => {
          const { principal, start } = parseWindowId(id);
          const available = explained === "all" || explained.has(id);
          return (
            <li key={id}>
              <button
                disabled={!available}
                onClick={() => onSelect(id)}
                aria-pressed={selected === id}
                title={available ? "Inspect evidence" : "Explanation not included in the static export"}
                className={`flex w-full flex-col gap-1 px-3 py-2 text-left text-sm enabled:hover:bg-panel-2 disabled:opacity-60 ${
                  selected === id ? "bg-panel-2" : ""
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-ink">
                    #{rank} · {principal}
                  </span>
                  <span className="font-mono text-xs text-ink-2">{fmtScore(s)}</span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs text-ink-3">{relTime(start)}</span>
                  <AlertBadge flagged={s >= threshold} />
                  {label === 1 ? <KnownRedteamBadge /> : <UnlabeledBadge />}
                </div>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function ModelCard({ model, meta, metrics }: { model: ModelInfo; meta: Metadata; metrics: ModelMetrics }) {
  const t = model.train_info;
  const bounds = metrics.split_boundaries_seconds;
  const rows: [string, React.ReactNode][] = [
    ["Model", `${model.display_name} (${model.kind})`],
    ["What it does", model.description],
    ["Dataset", `${metrics.provenance.dataset} — ${metrics.provenance.mode_label}`],
    ["Scoring unit", meta.scoring_unit],
    [
      "Chronological split",
      Object.entries(bounds)
        .map(([k, [lo, hi]]) => `${k}: ${relTime(lo)} → ${relTime(hi)}`)
        .join(" · "),
    ],
    ["Training", `${int(Number(t.n_train_rows))} train windows · labels used: ${t.labels_used ? "yes" : "no"} · ${Number(t.train_seconds).toFixed(3)} s · seed ${String(t.seed)}`],
    ["Threshold", `${fmtScore(model.threshold)} — ${String(model.threshold_policy.type)} (alert rate ${String(model.threshold_policy.alert_rate)}) on ${String(model.threshold_policy.calibrated_on)}`],
    ["Inference", `${Number(t.score_ms_per_1000_windows).toFixed(2)} ms per 1,000 windows (single process)`],
    ["Features", model.features.join(", ")],
    ["Hyperparameters", JSON.stringify(model.hyperparameters)],
    ["Explanations", `${model.explanation_method}. ${model.explanation_caveat}`],
    ["Artifact", `sha256 ${model.artifact_sha256.slice(0, 16)}… · config ${metrics.provenance.config_hash}`],
    ["Libraries", Object.entries(model.library_versions).map(([k, v]) => `${k} ${v}`).join(" · ")],
  ];
  return (
    <Panel>
      <SectionTitle title="Model card" right={<ProvenanceBadge provenance={metrics.provenance} />} />
      <dl className="grid grid-cols-[minmax(0,1fr)] gap-x-6 gap-y-2 text-sm sm:grid-cols-[180px_minmax(0,1fr)]" data-testid="model-card">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-ink-3">{k}</dt>
            <dd className="text-ink-2 [overflow-wrap:anywhere]">{v}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  );
}
