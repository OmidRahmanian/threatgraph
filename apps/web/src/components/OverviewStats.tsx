"use client";

import { api, useLoad } from "@/lib/data";
import { bytes, compact, int } from "@/lib/format";
import { Callout, ErrorBlock, LoadingBlock, ProvenanceBadge, StatTile } from "./ui";

export function OverviewStats() {
  const state = useLoad(() => Promise.all([api.summary(), api.metadata(), api.models(), api.benchmarks()]), "overview");
  if (state.status === "loading") return <LoadingBlock label="Loading computed statistics…" />;
  if (state.status === "error") return <ErrorBlock error={state.error} />;
  const [summary, meta, models, bench] = state.data;
  const p = summary.provenance;
  const test = meta.splits.find((s) => s.split === "test");
  const names = Object.fromEntries(models.models.map((m) => [m.model_id, m.display_name]));

  return (
    <section aria-labelledby="stats" className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 id="stats" className="text-base font-semibold">
          What was processed
        </h2>
        <ProvenanceBadge provenance={p} />
      </div>

      {p.is_synthetic ? (
        <Callout title="Synthetic demo: no real network data on this page" tone="synthetic">
          <p>
            Every number below is computed by the pipeline from a deterministic synthetic fixture in the
            exact LANL file format (seeded with lateral-movement campaigns, benign look-alikes, and
            deliberately incomplete labels). These are <strong>not</strong> measured results on LANL data.
            Real-data mode needs the LANL files, which you download yourself.
          </p>
        </Callout>
      ) : (
        <Callout title="Real, de-identified historical data">
          <p>{p.source}</p>
        </Callout>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatTile testId="stat-events" label="Authentication events processed" value={compact(summary.processed_auth_events)} note={`${int(summary.rejected_source_rows)} malformed rows rejected`} />
        <StatTile label="Accounts · computers" value={`${int(summary.distinct_principals)} · ${int(summary.distinct_computers)}`} note={`${meta.n_days} days of relative time`} />
        <StatTile label="Scored account-hours" value={compact(summary.scored_windows)} note="train + validation + test windows" />
        <StatTile
          label="Known red-team events"
          value={int(summary.labeled_redteam_events)}
          note={`${int(summary.known_positive_windows)} labeled windows · ${int(summary.redteam_records_in_window)} red-team records`}
        />
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        {summary.flagged_windows.map((f) => (
          <StatTile
            key={f.model_id}
            label={`Alerts on the held-out test period · ${names[f.model_id] ?? f.model_id}`}
            value={int(f.alerts)}
            note={`of ${int(test?.n_windows ?? 0)} test windows, at the threshold fixed on validation · model ${summary.model_versions[f.model_id]}`}
          />
        ))}
      </div>

      <details className="rounded-lg border border-line bg-panel px-4 py-3 text-sm text-ink-2">
        <summary className="cursor-pointer font-medium text-ink">Engineering facts from the last pipeline run</summary>
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[420px] text-left text-sm">
            <thead className="text-xs text-ink-3">
              <tr>
                <th className="py-1 pr-4 font-normal">Stage</th>
                <th className="py-1 pr-4 font-normal">Wall time</th>
                <th className="py-1 pr-4 font-normal">Peak memory</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(bench.stages).map(([stage, s]) => (
                <tr key={stage} className="border-t border-line">
                  <td className="py-1 pr-4">{stage}</td>
                  <td className="py-1 pr-4 tabular-nums">{Number(s.seconds).toFixed(2)} s</td>
                  <td className="py-1 pr-4 tabular-nums">{Number(s.peak_rss_mb).toFixed(0)} MB</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-xs text-ink-3">
            Ingest throughput {bench.ingest_rows_per_second ? `${compact(bench.ingest_rows_per_second)} rows/s` : "n/a"} · public
            payload {bench.export_payload_bytes ? bytes(bench.export_payload_bytes) : "n/a"} · Python {bench.library_versions.python},
            scikit-learn {bench.library_versions["scikit-learn"]}, Polars {bench.library_versions.polars}.
          </p>
        </div>
      </details>
    </section>
  );
}
