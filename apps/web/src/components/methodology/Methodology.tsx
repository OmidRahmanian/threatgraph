"use client";

import { api, downloadUrl, useLoad } from "@/lib/data";
import { bytes, duration, int, relTime } from "@/lib/format";
import type { Benchmarks, Metadata, ModelList, Summary } from "@/lib/types";
import { ErrorBlock, LoadingBlock, Panel, ProvenanceBadge, SectionTitle } from "../ui";

export function Methodology() {
  const state = useLoad(() => Promise.all([api.metadata(), api.models(), api.summary(), api.benchmarks()]), "methodology");
  if (state.status === "loading") return <LoadingBlock label="Loading methodology…" />;
  if (state.status === "error") return <ErrorBlock error={state.error} />;
  const [meta, models, summary, bench] = state.data;
  return (
    <div className="space-y-6 fade-in">
      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">Methodology</h1>
          <ProvenanceBadge provenance={meta.provenance} />
        </div>
        <p className="max-w-3xl text-sm leading-relaxed text-ink-2">
          How the data is processed, what is scored, how models are trained and judged, and what the results can and cannot
          say. Every number on this page is read from the pipeline&apos;s outputs for the dataset shown.
        </p>
        <nav aria-label="On this page" className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
          {SECTIONS.map(([id, label]) => (
            <a key={id} href={`#${id}`} className="text-ink-2 underline decoration-line underline-offset-2 hover:text-ink">
              {label}
            </a>
          ))}
        </nav>
      </header>
      <DataSection meta={meta} summary={summary} />
      <UnitSection meta={meta} />
      <FeatureSection meta={meta} />
      <ModelSection models={models} />
      <EvaluationSection meta={meta} />
      <ResearchSection models={models} />
      <LeakageSection />
      <GraphSection />
      <LimitationsSection />
      <ReproSection bench={bench} models={models} />
      <DownloadSection models={models} />
    </div>
  );
}

const SECTIONS: [string, string][] = [
  ["data", "Data"],
  ["unit", "Scoring unit"],
  ["features", "Features"],
  ["models", "Models"],
  ["evaluation", "Evaluation"],
  ["research", "Uncertainty, drift, explanations"],
  ["leakage", "Leakage controls"],
  ["graph", "Graph"],
  ["limitations", "Limitations"],
  ["reproducibility", "Reproducibility"],
  ["downloads", "Downloads"],
];

function Prose({ children }: { children: React.ReactNode }) {
  return <div className="max-w-3xl space-y-2 text-sm leading-relaxed text-ink-2">{children}</div>;
}

function DataSection({ meta, summary }: { meta: Metadata; summary: Summary }) {
  const p = meta.provenance;
  return (
    <Panel id="data">
      <SectionTitle title="Data and labels" />
      <Prose>
        <p>{p.source}</p>
        {p.source_url ? (
          <p>
            Source: <a className="underline" href={p.source_url}>{p.source_url}</a>. The files are downloaded by the user after LANL&apos;s data-use form and are never
            redistributed; public views use salted aliases instead of account and computer names.
          </p>
        ) : null}
        <p>
          Processed: {int(summary.processed_auth_events)} authentication events ({int(summary.rejected_source_rows)} malformed rows
          rejected and counted in the data-quality report), {int(summary.distinct_principals)} accounts, {int(summary.distinct_computers)} computers, {meta.n_days} days
          from {relTime(meta.time_start_seconds)} to {relTime(meta.time_end_seconds)}.
        </p>
        <p>{meta.time_semantics}</p>
        <p>
          Labels: {int(summary.redteam_records_in_window)} red-team records in the time window, matched to {int(summary.labeled_redteam_events)} authentication
          events on (time, account, source computer, destination computer). {meta.label_semantics}
        </p>
      </Prose>
    </Panel>
  );
}

function UnitSection({ meta }: { meta: Metadata }) {
  return (
    <Panel id="unit">
      <SectionTitle title="Scoring unit and splits" />
      <Prose>
        <p>{meta.scoring_unit} Window length: {duration(meta.window_seconds)}.</p>
        <p>
          Windows are assigned to splits by start time. Warm-up days only provide history (everything is new at the start of a
          log); models are fit on train, the alert threshold is fixed on validation, and test is reported once with that
          threshold.
        </p>
      </Prose>
      <div className="mt-3 overflow-x-auto">
        <table className="w-full min-w-[560px] text-left text-sm tabular-nums" data-testid="split-table">
          <thead className="text-xs text-ink-3">
            <tr>
              <th className="py-1 pr-3 font-normal">Split</th>
              <th className="py-1 pr-3 font-normal">From</th>
              <th className="py-1 pr-3 font-normal">To</th>
              <th className="py-1 pr-3 text-right font-normal">Windows</th>
              <th className="py-1 pr-3 text-right font-normal">Known red-team windows</th>
              <th className="py-1 text-right font-normal">Accounts</th>
            </tr>
          </thead>
          <tbody>
            {meta.splits.map((s) => (
              <tr key={s.split} className="border-t border-line">
                <td className="py-1 pr-3">{s.split}</td>
                <td className="py-1 pr-3">{relTime(s.start_seconds)}</td>
                <td className="py-1 pr-3">{relTime(s.end_seconds)}</td>
                <td className="py-1 pr-3 text-right">{int(s.n_windows)}</td>
                <td className="py-1 pr-3 text-right">{int(s.n_positive_windows)}</td>
                <td className="py-1 text-right">{int(s.n_principals)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function FeatureSection({ meta }: { meta: Metadata }) {
  const groups = [...new Set(meta.features.map((f) => f.group))];
  return (
    <Panel id="features">
      <SectionTitle title={`Features (${meta.feature_set})`} subtitle="Each uses only events before the window ends; per-account baselines use strictly earlier windows." />
      {groups.map((g) => (
        <div key={g} className="mt-3">
          <h3 className="text-sm font-medium capitalize text-ink">{g}</h3>
          <dl className="mt-1 grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[200px_minmax(0,1fr)]">
            {meta.features
              .filter((f) => f.group === g)
              .map((f) => (
                <div key={f.name} className="contents">
                  <dt className="font-mono text-xs text-ink">{f.name}</dt>
                  <dd className="text-ink-2">{f.description}</dd>
                </div>
              ))}
          </dl>
        </div>
      ))}
    </Panel>
  );
}

function ModelSection({ models }: { models: ModelList }) {
  return (
    <Panel id="models">
      <SectionTitle title="Models" subtitle="All are unsupervised: labels are never used for training or for setting thresholds." />
      <div className="space-y-4">
        {models.models.map((m) => (
          <div key={m.model_id} className="text-sm">
            <h3 className="font-medium text-ink">{m.display_name}</h3>
            <p className="mt-1 max-w-3xl text-ink-2">{m.description}</p>
            <p className="mt-1 text-xs text-ink-3">
              {m.features.length} features · threshold {String(m.threshold_policy.type)} at alert rate {String(m.threshold_policy.alert_rate)} on{" "}
              {String(m.threshold_policy.calibrated_on)} · explanations: {m.explanation_method}
            </p>
          </div>
        ))}
        {models.ablations.map((a) => (
          <div key={a.ablation_id} className="rounded-lg border border-line bg-panel-2 p-3 text-sm text-ink-2">
            <div className="font-medium text-ink">{a.title}</div>
            <p className="mt-1">{a.note}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function EvaluationSection({ meta }: { meta: Metadata }) {
  return (
    <Panel id="evaluation">
      <SectionTitle title="Evaluation" />
      <Prose>
        <p>
          Positives are windows containing at least one red-team-matched event; every other window is <em>unlabeled</em>. Because the
          red-team file is incomplete, unlabeled windows are treated as negatives only for computing precision, so precision is a
          lower bound and recall covers documented activity only.
        </p>
        <ul className="list-disc space-y-1 pl-5">
          <li><strong className="text-ink">Average precision</strong>: ranking quality, always shown next to the random-ranking baseline (the prevalence).</li>
          <li><strong className="text-ink">Precision@K</strong>: known red-team windows among the K highest scores.</li>
          <li><strong className="text-ink">Known-label recall, alerts, alerts per day</strong>: at the threshold fixed on validation.</li>
          <li><strong className="text-ink">Detection latency</strong>: first labeled event → end of the first alerted labeled window (alerts exist only at window end, so it includes up to {duration(meta.window_seconds)}).</li>
          <li><strong className="text-ink">Not estimable</strong> is shown when a split has no positives, never 0.</li>
        </ul>
        <p>
          The Lab recomputes threshold metrics in the browser from the stored held-out scores; tests check that this reproduces
          the stored numbers.
        </p>
      </Prose>
    </Panel>
  );
}

function ResearchSection({ models }: { models: ModelList }) {
  const boot = models.bootstrap.test;
  return (
    <Panel id="research">
      <SectionTitle title="Uncertainty, drift and explanation quality" />
      <Prose>
        <p>
          <strong className="text-ink">Confidence intervals.</strong> Windows of one account are correlated and red-team labels come in
          per-account runs, so the bootstrap resamples whole accounts ({boot ? `${boot.n_boot} resamples, seed ${boot.seed}` : "N/A"}).
          Model differences are paired: every model is scored on the same resample. Resamples with no positive account cannot
          estimate AP and are dropped for that metric; the share kept is stored. With {boot?.n_positive_accounts ?? "N/A"} positive
          accounts in the test split, intervals are wide, and that is the honest result.
        </p>
        <p>
          <strong className="text-ink">Drift monitor.</strong> For each scored day, the population stability index of every feature and
          model score against the training split, and the alert rate against the budget. Training days are included to show how
          noisy the measure itself is. Features that grow by design (account history) are labeled as such.
        </p>
        <p>
          <strong className="text-ink">Explanation faithfulness.</strong> A deletion test: reset the k features an explanation ranks
          highest to their training medians and re-score, compared with resetting k random features. M0&apos;s explanation is exact and
          acts as a reference; for Isolation Forest it measures how useful the proxy ranking is.
        </p>
        <p>
          <strong className="text-ink">Supervised model.</strong> {models.supervised_model.reason} The threshold for training one is
          fixed in configuration before results are seen.
        </p>
        <p>
          <strong className="text-ink">Not built:</strong> flow, DNS and process logs (LANL publishes them, but they need the same
          user download, and the synthetic fixture has none) and a graph neural network benchmark (a heavy dependency for a
          comparison that a handful of labeled accounts could not support).
        </p>
      </Prose>
    </Panel>
  );
}

function LeakageSection() {
  return (
    <Panel id="leakage">
      <SectionTitle title="Leakage controls" />
      <Prose>
        <ul className="list-disc space-y-1 pl-5">
          <li>Features are causal: a test recomputes them on data cut at a time and fails if any earlier window changes.</li>
          <li>Features are processed in time chunks with carried state; a test checks the output is identical for any chunk size.</li>
          <li>Scalers, references and models are fit on train only; thresholds come from validation only; test is never used to choose anything.</li>
          <li>Splits are chronological with explicit boundaries, never random.</li>
          <li>Labels are kept out of feature columns and are never used to choose what the graph view shows.</li>
          <li>Known exception: the graph features were designed knowing the synthetic fixture contains pivots, so that ablation is not blind (stated wherever it is shown).</li>
        </ul>
      </Prose>
    </Panel>
  );
}

function GraphSection() {
  return (
    <Panel id="graph">
      <SectionTitle title="Graph and incidents" />
      <Prose>
        <p>
          The graph has computers as nodes and one directed edge per account authenticating from a source to a destination
          computer, in the direction LANL records it. Queries are bounded in time, hops and edges, and do not expand through hub
          computers used by many accounts.
        </p>
        <p>
          An incident is a run of red-team-matched events by one account. It reconstructs documented activity; it is not a
          detection. Replay places each model&apos;s alert at the end of its window, when it would have been raised. Write-ups are
          filled in from the computed numbers by fixed templates, without a language model.
        </p>
      </Prose>
    </Panel>
  );
}

function LimitationsSection() {
  return (
    <Panel id="limitations">
      <SectionTitle title="Limitations" />
      <Prose>
        <ul className="list-disc space-y-1 pl-5">
          <li>Synthetic results show the pipeline works; the fixture was designed by the author and says nothing about real-world performance.</li>
          <li>An alert means an account-hour was unusual compared with the training period. It is not evidence of compromise.</li>
          <li>New accounts and hosts look unusual by construction; admin maintenance and similar benign activity rank high.</li>
          <li>Slow activity spread thinly over many hours is hard to see at a one-hour scoring unit.</li>
          <li>Isolation Forest explanations are approximate diagnostics, not attributions.</li>
          <li>Machine accounts and LogOff events are outside the scoring and graph scope.</li>
          <li>No clock-time features: LANL time is relative, so &quot;off-hours&quot; cannot be modeled.</li>
        </ul>
      </Prose>
    </Panel>
  );
}

function ReproSection({ bench, models }: { bench: Benchmarks; models: ModelList }) {
  const order = ["ingest", "features", "graph", "train", "evaluate"];
  const rank = (k: string) => (order.indexOf(k) === -1 ? order.length : order.indexOf(k));
  const stages = Object.entries(bench.stages).sort(([a], [b]) => rank(a) - rank(b));
  return (
    <Panel id="reproducibility">
      <SectionTitle title="Reproducibility and performance" subtitle="Measured during the pipeline run that produced this page, on the machine that ran it." />
      <div className="grid gap-6 lg:grid-cols-2">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm tabular-nums" data-testid="stage-table">
            <caption className="mb-1 text-left text-xs text-ink-3">Pipeline stages</caption>
            <thead className="text-xs text-ink-3">
              <tr>
                <th className="py-1 pr-3 font-normal">Stage</th>
                <th className="py-1 pr-3 text-right font-normal">Seconds</th>
                <th className="py-1 text-right font-normal">Peak memory (MB)</th>
              </tr>
            </thead>
            <tbody>
              {stages.map(([name, s]) => (
                <tr key={name} className="border-t border-line">
                  <td className="py-1 pr-3">{name}</td>
                  <td className="py-1 pr-3 text-right">{String(s.seconds ?? "N/A")}</td>
                  <td className="py-1 text-right">{String(s.peak_rss_mb ?? "N/A")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-xs text-ink-3">
            Ingest: {bench.ingest_rows_per_second ? `${int(Math.round(bench.ingest_rows_per_second))} rows/s` : "n/a"} · public bundle{" "}
            {bench.export_payload_bytes ? bytes(bench.export_payload_bytes) : "(measured only in the static export)"}. Peak memory is the process high-water mark when the
            stages run in one process.
          </p>
        </div>
        <div className="overflow-x-auto">
          {bench.api_latency ? (
            <table className="w-full text-left text-sm tabular-nums" data-testid="api-latency-table">
              <caption className="mb-1 text-left text-xs text-ink-3">
                API latency, in-process, {bench.api_latency.repeats} requests each
              </caption>
              <thead className="text-xs text-ink-3">
                <tr>
                  <th className="py-1 pr-3 font-normal">Endpoint</th>
                  <th className="py-1 pr-3 text-right font-normal">p50 ms</th>
                  <th className="py-1 pr-3 text-right font-normal">p95 ms</th>
                  <th className="py-1 text-right font-normal">Response</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(bench.api_latency.endpoints).map(([name, e]) => (
                  <tr key={name} className="border-t border-line">
                    <td className="py-1 pr-3">{name.replace(/_/g, " ")}</td>
                    <td className="py-1 pr-3 text-right">{e.p50_ms.toFixed(1)}</td>
                    <td className="py-1 pr-3 text-right">{e.p95_ms.toFixed(1)}</td>
                    <td className="py-1 text-right">{bytes(e.response_bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-sm text-ink-3">API latency has not been measured for this bundle. Run <code className="font-mono">make benchmark</code>.</p>
          )}
        </div>
      </div>
      <div className="mt-4 text-xs text-ink-3">
        <p>
          Config {models.provenance.config_hash} · pipeline {models.provenance.pipeline_version} · models{" "}
          {models.models.map((m) => `${m.model_id} ${m.artifact_sha256.slice(0, 12)}`).join(", ")}
        </p>
        <p className="mt-1">{Object.entries(bench.library_versions).map(([k, v]) => `${k} ${v}`).join(" · ")}</p>
        <p className="mt-1">
          Rebuild everything with <code className="font-mono">make demo</code>; every number above is regenerated, none is typed by hand.
        </p>
      </div>
    </Panel>
  );
}

function DownloadSection({ models }: { models: ModelList }) {
  const files: [string, string][] = [
    ["model_comparison.csv", "Model comparison: every model × split, at the calibrated threshold (CSV)"],
    ["incident_writeups.md", "Incident write-ups for validation and test incidents (Markdown)"],
    ...models.models.map((m): [string, string] => [`model_cards/${m.model_id}.md`, `Model card: ${m.display_name} (Markdown)`]),
  ];
  return (
    <Panel id="downloads">
      <SectionTitle title="Downloads" subtitle="Generated by the exporter from the same artifacts; each file names its dataset mode in its first line." />
      <ul className="space-y-1 text-sm" data-testid="downloads">
        {files.map(([rel, label]) => (
          <li key={rel}>
            <a className="text-ink underline decoration-line underline-offset-2 hover:decoration-ink" href={downloadUrl(rel)} download>
              {label}
            </a>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
