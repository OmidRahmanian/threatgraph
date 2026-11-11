"use client";

import { api, useLoad } from "@/lib/data";
import { int, ratio } from "@/lib/format";
import type { DatasetState, DatasetStatus } from "@/lib/types";
import { Panel, SectionTitle } from "../ui";

const STATE_TEXT: Record<DatasetState, string> = {
  files_missing: "Pending: files not obtained",
  not_processed: "Pending: not processed",
  ingested: "Pending: not evaluated",
  stale: "Pending: outputs out of date",
  evaluated: "Evaluated",
};

function StateBadge({ state }: { state: DatasetState }) {
  const done = state === "evaluated";
  return (
    <span
      data-testid={`dataset-state-${state}`}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium ${
        done ? "border-line bg-panel-2 text-ink" : "border-dashed border-line text-ink-3"
      }`}
    >
      <svg aria-hidden width="8" height="8" viewBox="0 0 8 8">
        {done ? <circle cx="4" cy="4" r="3.5" fill="currentColor" /> : <circle cx="4" cy="4" r="3" fill="none" stroke="currentColor" strokeWidth="1.2" />}
      </svg>
      {STATE_TEXT[state]}
    </span>
  );
}

function Results({ d }: { d: DatasetStatus }) {
  if (d.status !== "evaluated") return <span className="text-ink-3">No results: nothing is shown until the pipeline has run</span>;
  return (
    <ul className="space-y-0.5">
      {d.models.map((m) => (
        <li key={m.model_id}>
          {m.display_name}: test AP {m.test_average_precision === null ? "n/e" : ratio(m.test_average_precision)} ·{" "}
          {int(m.test_known_positive_windows)} known positive windows
        </li>
      ))}
    </ul>
  );
}

/** Which research datasets have real results. Real LANL stays "pending" until it has been run. */
export function ResearchDatasets() {
  const st = useLoad(api.datasets, "datasets");
  if (st.status !== "ready" || st.data === null) return null;
  const list = st.data.datasets;
  const lanlPending = list.some((d) => d.mode === "lanl" && d.status !== "evaluated");
  return (
    <Panel id="datasets">
      <SectionTitle
        title="Research datasets"
        subtitle="Synthetic demo results and real LANL results are kept apart. This page shows the dataset in the badge above."
      />
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm" data-testid="dataset-status">
          <thead className="text-xs text-ink-3">
            <tr>
              <th className="py-1 pr-3 font-medium">Dataset</th>
              <th className="py-1 pr-3 font-medium">Status</th>
              <th className="py-1 pr-3 text-right font-medium">Events accepted</th>
              <th className="py-1 font-medium">Held-out results</th>
            </tr>
          </thead>
          <tbody>
            {list.map((d) => (
              <tr key={d.dataset} className="border-t border-line align-top">
                <td className="py-2 pr-3">
                  <div className="font-medium text-ink">{d.dataset}</div>
                  <div className="text-xs text-ink-3">{d.mode_label}</div>
                </td>
                <td className="py-2 pr-3">
                  <StateBadge state={d.status} />
                  <div className="mt-1 max-w-xs text-xs text-ink-3">{d.status_detail}</div>
                </td>
                <td className="py-2 pr-3 text-right tabular-nums">{d.rows_accepted === null ? "Not ingested" : int(d.rows_accepted)}</td>
                <td className="py-2 text-xs text-ink-2">
                  <Results d={d} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {lanlPending ? (
        <p className="mt-3 text-xs leading-relaxed text-ink-3">
          Real LANL evaluation is pending. LANL distributes the files through its own data-use form, so they are never downloaded or
          bundled here. Once they are placed in <code className="font-mono">data/raw/lanl/</code>, run{" "}
          <code className="font-mono">python scripts/verify_lanl.py</code> and{" "}
          <code className="font-mono">python scripts/run_pipeline.py --dataset lanl</code>.
        </p>
      ) : null}
    </Panel>
  );
}
