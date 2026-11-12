"use client";

import { useCallback, useEffect, useState } from "react";
import { ASSESSMENT_TEXT, describeEvent, live, utc, type IncidentDetail, type Me } from "@/lib/live";
import { LoadingBlock } from "../ui";
import { SeverityBadge, SimulatedBadge } from "./badges";

const VERDICTS = [
  { value: "confirmed_malicious", label: "Confirmed malicious" },
  { value: "false_positive", label: "False positive" },
  { value: "expected_activity", label: "Expected activity" },
  { value: "benign", label: "Benign" },
];

export function IncidentPanel({ id, me, onChange, onClose }: { id: string; me: Me; onChange: () => void; onClose: () => void }) {
  const [d, setD] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [verdict, setVerdict] = useState("false_positive");
  const [note, setNote] = useState("");
  const [focus, setFocus] = useState<number | null>(null);

  const load = useCallback(() => {
    live.incident(id).then(setD, (e: unknown) => setError(String(e)));
  }, [id]);
  useEffect(load, [load]);

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      load();
      onChange();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!d) return error ? <p role="alert" className="text-sm text-ink-2">{error}</p> : <LoadingBlock label="Loading incident…" />;
  const inc = d.incident;
  const inv = d.investigation;
  const byRow = new Map(d.evidence_events.map((e) => [e.rowid, e]));

  return (
    <div className="space-y-4" data-testid="incident-panel">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={inc.severity} />
            {inc.simulated ? <SimulatedBadge /> : null}
            <span className="font-mono text-xs text-ink-3">{inc.id}</span>
          </div>
          <h3 className="mt-1 text-lg font-semibold text-ink">{inc.title}</h3>
          <p className="text-sm text-ink-2">
            {ASSESSMENT_TEXT[inc.assessment]} · {inc.status} · detected {utc(inc.detected_at)} · seen {inc.occurrences}×
          </p>
        </div>
        <button onClick={onClose} className="rounded-md border border-line px-2.5 py-1 text-xs text-ink-2 hover:text-ink">
          Close
        </button>
      </div>

      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
        <Fact k="Detector" v={`${inc.detector} · ${inc.rule_id}`} />
        <Fact k="Host / service" v={`${inc.source_id ?? "external check"} · ${inc.service ?? "n/a"}`} />
        <Fact k="First / last seen" v={`${utc(inc.first_seen)} → ${utc(inc.last_seen)}`} />
        <Fact k="Confidence" v={inc.confidence} />
      </dl>

      <section>
        <h4 className="text-sm font-medium text-ink">Evidence</h4>
        <ul className="mt-1 list-disc space-y-0.5 pl-5 text-sm text-ink-2">
          {inc.evidence.map((e, i) => (
            <li key={i}>{e}</li>
          ))}
        </ul>
        <p className="mt-2 text-xs text-ink-3">Limitations: {inc.limitations}</p>
        <p className="mt-1 text-sm text-ink-2">
          <span className="font-medium text-ink">Recommended action:</span> {inc.recommended_action}
        </p>
      </section>

      <section>
        <h4 className="text-sm font-medium text-ink">Supporting events ({d.evidence_events.length})</h4>
        <div className="mt-1 max-h-64 overflow-auto rounded-lg border border-line">
          <table className="w-full text-left text-xs" data-testid="incident-events">
            <tbody>
              {d.evidence_events.map((e) => (
                <tr key={e.rowid} id={`ev-${e.rowid}`} className={`border-t border-line first:border-t-0 ${focus === e.rowid ? "bg-model-soft" : ""}`}>
                  <td className="whitespace-nowrap px-2 py-1 text-ink-3">{utc(e.ts).slice(11)}</td>
                  <td className="px-2 py-1 text-ink-3">{e.kind}</td>
                  <td className="break-all px-2 py-1 text-ink-2">{describeEvent(e)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h4 className="text-sm font-medium text-ink">Notifications</h4>
        {d.notifications.length === 0 ? (
          <p className="text-xs text-ink-3">
            None: below the notification threshold, or no channel configured ({me.channels.join(", ") || "none configured"}).
          </p>
        ) : (
          <ul className="mt-1 space-y-0.5 text-xs text-ink-2" data-testid="incident-notifications">
            {d.notifications.map((n) => (
              <li key={n.id}>
                {n.channel} · {n.kind} · <span className="font-medium text-ink">{n.status}</span> · {n.attempts} attempt
                {n.attempts === 1 ? "" : "s"}
                {n.sent_at ? ` · sent ${utc(n.sent_at)}` : ""}
                {n.last_error ? ` · last error: ${n.last_error}` : ""}
                {n.status === "suppressed" ? " (simulated incident: not delivered)" : ""}
              </li>
            ))}
          </ul>
        )}
      </section>

      {inc.status !== "resolved" ? (
        <section className="space-y-2 rounded-lg border border-line bg-panel-2 p-3">
          <div className="flex flex-wrap gap-2">
            {inc.status === "open" ? (
              <button disabled={busy} onClick={() => act(() => live.ack(inc.id))} className="rounded-md border border-line bg-panel px-3 py-1.5 text-sm text-ink hover:bg-panel-2">
                Acknowledge
              </button>
            ) : (
              <span className="text-xs text-ink-3">Acknowledged by {inc.acknowledged_by}</span>
            )}
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-xs text-ink-3">
              Verdict
              <select value={verdict} onChange={(e) => setVerdict(e.target.value)} className="mt-1 block rounded-md border border-line bg-panel px-2 py-1.5 text-sm text-ink">
                {VERDICTS.map((v) => (
                  <option key={v.value} value={v.value}>
                    {v.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="min-w-48 flex-1 text-xs text-ink-3">
              Note
              <input value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} className="mt-1 block w-full rounded-md border border-line bg-panel px-2 py-1.5 text-sm text-ink" />
            </label>
            <button disabled={busy} onClick={() => act(() => live.resolve(inc.id, verdict, note))} className="rounded-md border border-line bg-panel px-3 py-1.5 text-sm text-ink hover:bg-panel-2">
              Resolve
            </button>
          </div>
          <p className="text-xs text-ink-3">Verdicts are the verified labels used to measure false-alert rates.</p>
        </section>
      ) : (
        <p className="text-sm text-ink-2">
          Resolved by {inc.resolved_by}
          {inc.verdict ? ` · verdict: ${inc.verdict.replace("_", " ")}` : ""}
          {inc.resolution ? ` · ${inc.resolution}` : ""}
        </p>
      )}

      <section className="rounded-lg border border-dashed border-line p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-sm font-medium text-ink">AI investigation (optional, advisory)</h4>
          {me.llm_enabled ? (
            <button disabled={busy} onClick={() => act(() => live.investigate(inc.id))} className="rounded-md border border-line px-3 py-1 text-xs text-ink-2 hover:text-ink">
              {inv ? "Run again" : "Investigate"}
            </button>
          ) : (
            <span className="text-xs text-ink-3">Disabled on this server (llm.enabled = false). Detection does not use it.</span>
          )}
        </div>
        {inv ? (
          <div className="mt-2 space-y-2 text-sm text-ink-2" data-testid="investigation">
            <p className="text-xs text-ink-3">
              {inv.model} · {utc(inv.created_at)} · {inv.result?.advisory ?? ""}
            </p>
            {inv.status === "failed" ? <p>Investigation failed: {inv.error}</p> : null}
            {inv.result?.injection_warnings.length ? (
              <p className="text-xs">
                Log content resembling instructions to an AI was found and treated as data: {inv.result.injection_warnings.join("; ")}
              </p>
            ) : null}
            {inv.result?.summary ? <p>{inv.result.summary}</p> : null}
            {inv.result?.possible_causes?.map((c, i) => (
              <p key={i}>
                Possible cause{c.likelihood ? ` (${c.likelihood})` : ""}: {c.cause}{" "}
                {c.evidence_ids.map((eid) => {
                  const row = inv.result!.evidence_map[eid];
                  return (
                    <button key={eid} onClick={() => { setFocus(row); document.getElementById(`ev-${row}`)?.scrollIntoView({ block: "nearest" }); }} className="mr-1 rounded border border-line px-1 font-mono text-xs text-ink hover:bg-panel-2" title={byRow.get(row) ? describeEvent(byRow.get(row)!) : "event"}>
                      {eid}
                    </button>
                  );
                })}
              </p>
            ))}
            {inv.result?.uncertainty ? <p className="text-xs">Uncertainty: {inv.result.uncertainty}</p> : null}
            {inv.result?.suggested_steps?.length ? (
              <ul className="list-disc pl-5 text-xs">
                {inv.result.suggested_steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            ) : null}
            {inv.result?.dropped_unsupported_claims ? (
              <p className="text-xs text-ink-3">{inv.result.dropped_unsupported_claims} claims without valid evidence were removed.</p>
            ) : null}
          </div>
        ) : null}
      </section>
      {error ? <p role="alert" className="text-sm text-ink-2">{error}</p> : null}
    </div>
  );
}

function Fact({ k, v }: { k: string; v: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-ink-3">{k}</dt>
      <dd className="break-words text-ink-2">{v}</dd>
    </div>
  );
}
