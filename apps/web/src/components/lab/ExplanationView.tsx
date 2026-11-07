"use client";

import Link from "next/link";
import { api, useLoad } from "@/lib/data";
import { relTime, score as fmtScore, windowLabel } from "@/lib/format";
import type { EvalSplit } from "@/lib/types";
import { AlertBadge, Callout, ErrorBlock, KnownRedteamBadge, LoadingBlock, UnlabeledBadge } from "../ui";

export function ExplanationView({ modelId, split, windowId }: { modelId: string; split: EvalSplit; windowId: string }) {
  const state = useLoad(() => api.explanation(modelId, split, windowId), `${modelId}|${split}|${windowId}`);
  if (state.status === "loading") return <LoadingBlock label="Loading evidence…" />;
  if (state.status === "error") return <ErrorBlock error={state.error} />;
  const e = state.data;
  if (!e) {
    return (
      <p className="rounded-lg border border-line bg-panel-2 p-4 text-sm text-ink-2">
        This window&apos;s explanation is not part of the static export (it includes the top-ranked and all known red-team test
        windows). Run the API to inspect any window.
      </p>
    );
  }
  const maxAbs = Math.max(1, ...e.diagnostics.map((d) => Math.abs(d.robust_z)));
  return (
    <div className="space-y-4 fade-in" data-testid="explanation">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm text-ink">{e.principal}</span>
        <span className="text-sm text-ink-2">{windowLabel(e.window_start, e.window_end)}</span>
        <AlertBadge flagged={e.flagged} />
        {e.label === "known_redteam" ? <KnownRedteamBadge count={e.n_labeled_events} /> : <UnlabeledBadge />}
        <Link
          href={`/threatgraph/explorer/?window=${encodeURIComponent(e.window_id)}&model=${encodeURIComponent(modelId)}`}
          className="ml-auto text-xs text-ink-2 underline decoration-line underline-offset-2 hover:text-ink"
        >
          Open in network explorer →
        </Link>
      </div>
      <p className="text-sm text-ink-2">
        Score <span className="font-mono text-ink">{fmtScore(e.score)}</span> vs threshold{" "}
        <span className="font-mono">{fmtScore(e.threshold)}</span> (calibrated on validation). {e.n_events_in_window} events in
        this window.
      </p>

      <Callout title={`Explanation method: ${e.method.split(":")[0]}`}>
        <p>{e.method}.</p>
        <p>{e.caveat}</p>
      </Callout>

      <div>
        <h4 className="mb-2 text-sm font-medium text-ink">Observed feature deviations (vs training-period median)</h4>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[520px] text-left text-sm">
            <thead className="text-xs text-ink-3">
              <tr>
                <th className="py-1 pr-3 font-normal">Feature</th>
                <th className="py-1 pr-3 text-right font-normal">Value</th>
                <th className="py-1 pr-3 text-right font-normal">Train median</th>
                <th className="py-1 pr-3 text-right font-normal">Robust z</th>
                <th className="w-1/3 py-1 font-normal">
                  <span className="sr-only">Deviation bar</span>
                </th>
              </tr>
            </thead>
            <tbody className="tabular-nums">
              {e.diagnostics.slice(0, 8).map((d) => (
                <tr key={d.feature} className="border-t border-line" title={d.description}>
                  <td className="py-1.5 pr-3">
                    <div className="font-mono text-xs text-ink">{d.feature}</div>
                    <div className="text-xs text-ink-3">{d.description}</div>
                  </td>
                  <td className="py-1.5 pr-3 text-right">{d.value.toFixed(2)}</td>
                  <td className="py-1.5 pr-3 text-right text-ink-2">{d.reference_median.toFixed(2)}</td>
                  <td className="py-1.5 pr-3 text-right">{d.robust_z.toFixed(1)}</td>
                  <td className="py-1.5">
                    <div className="h-2 w-full rounded-sm bg-panel-2">
                      <div
                        className="h-2 rounded-sm"
                        style={{
                          width: `${(100 * Math.abs(d.robust_z)) / maxAbs}%`,
                          background: d.robust_z >= 0 ? "var(--model)" : "var(--ink-3)",
                        }}
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <h4 className="mb-2 text-sm font-medium text-ink">
          Evidence: source events in this window
          {e.evidence_truncated ? (
            <span className="ml-2 text-xs font-normal text-ink-3">
              showing {e.evidence_events.length} of {e.n_events_in_window} (labeled events first)
            </span>
          ) : null}
        </h4>
        <div className="max-h-80 overflow-auto rounded-lg border border-line">
          <table className="w-full min-w-[760px] text-left text-xs" data-testid="evidence-table">
            <thead className="sticky top-0 bg-panel-2 text-ink-3">
              <tr>
                <th className="px-2 py-1.5 font-normal">Event</th>
                <th className="px-2 py-1.5 font-normal">Time</th>
                <th className="px-2 py-1.5 font-normal">Source → destination</th>
                <th className="px-2 py-1.5 font-normal">Auth / logon / orientation</th>
                <th className="px-2 py-1.5 font-normal">Outcome</th>
                <th className="px-2 py-1.5 font-normal">Label</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {e.evidence_events.map((ev) => (
                <tr key={ev.event_id} className={`border-t border-line ${ev.used_in_features ? "" : "text-ink-3"}`}>
                  <td className="px-2 py-1">auth:{ev.event_id}</td>
                  <td className="whitespace-nowrap px-2 py-1">{relTime(ev.event_time_seconds)}</td>
                  <td className="whitespace-nowrap px-2 py-1">
                    {ev.src_computer ?? "∅"} → {ev.dst_computer ?? "∅"}
                  </td>
                  <td className="px-2 py-1">
                    {ev.auth_type ?? "∅"} / {ev.logon_type ?? "∅"} / {ev.auth_orientation ?? "∅"}
                  </td>
                  <td className="px-2 py-1">{ev.outcome ?? "∅"}</td>
                  <td className="px-2 py-1 font-sans">{ev.known_redteam ? <KnownRedteamBadge /> : null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-xs text-ink-3">
          ∅ = missing in source (<code>?</code>). Greyed rows (e.g. LogOff) are shown for context but excluded from features. Time is
          relative to the dataset start; no clock time is implied.
        </p>
      </div>
    </div>
  );
}
