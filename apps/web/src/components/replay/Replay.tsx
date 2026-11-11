"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { api, useLoad } from "@/lib/data";
import { duration, relTime, score as fmtScore } from "@/lib/format";
import { layoutGraph } from "@/lib/graphLayout";
import { alertVisible, cursorTime, pathSoFar, shortModelName } from "@/lib/replay";
import type { Incident, IncidentIndex, IncidentSummary, ModelList } from "@/lib/types";
import { AlertBadge, Callout, ErrorBlock, KnownRedteamBadge, LoadingBlock, Panel, ProvenanceBadge, SectionTitle, UnlabeledBadge } from "../ui";

export function Replay() {
  const base = useLoad(() => Promise.all([api.incidents(), api.models()]), "replay-base");
  if (base.status === "loading") return <LoadingBlock label="Loading incidents…" />;
  if (base.status === "error") return <ErrorBlock error={base.error} />;
  return <ReplayBody index={base.data[0]} models={base.data[1]} />;
}

function ReplayBody({ index, models }: { index: IncidentIndex; models: ModelList }) {
  const [selected, setSelected] = useState<string | null>(() => {
    if (typeof window === "undefined") return null;
    return new URLSearchParams(window.location.search).get("incident");
  });
  const active = selected ?? index.incidents.find((i) => i.split === "test")?.incident_id ?? index.incidents[0]?.incident_id ?? null;
  const choose = (id: string) => {
    setSelected(id);
    window.history.replaceState(null, "", `${window.location.pathname}?${new URLSearchParams({ incident: id })}`);
  };
  return (
    <div className="space-y-6 fade-in">
      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">Incident replay</h1>
          <ProvenanceBadge provenance={index.provenance} />
        </div>
        <p className="max-w-3xl text-sm leading-relaxed text-ink-2">
          Step through documented red-team activity event by event and see when each model would have raised an alert. Alerts
          appear only once their window has closed, because that is when a score exists.
        </p>
        <p className="max-w-3xl text-xs text-ink-3">{index.definition}</p>
      </header>
      <div className="grid gap-6 lg:grid-cols-[300px_minmax(0,1fr)]">
        <Panel className="self-start">
          <SectionTitle title="Incidents" subtitle={`${index.incidents.length} · ${index.scope}`} />
          <ul className="divide-y divide-line overflow-hidden rounded-lg border border-line" data-testid="incident-list">
            {index.incidents.map((s) => (
              <IncidentItem key={s.incident_id} s={s} active={s.incident_id === active} onClick={() => choose(s.incident_id)} />
            ))}
          </ul>
        </Panel>
        <div className="min-w-0">
          {active ? <IncidentView key={active} id={active} models={models} /> : <Panel><p className="text-sm text-ink-3">No incidents in this dataset.</p></Panel>}
        </div>
      </div>
    </div>
  );
}

function DetectionChip({ d }: { d: IncidentSummary["detections"][number] }) {
  const name = shortModelName(d.display_name);
  const text =
    d.status === "detected" ? `${name} alerted after ${duration(d.latency_seconds ?? 0)}` : d.status === "missed" ? `${name} missed` : `${name} not scored`;
  return (
    <span className={`rounded-full border px-2 py-0.5 text-[11px] ${d.status === "detected" ? "border-model bg-model-soft text-ink" : "border-line text-ink-3"}`}>
      {text}
    </span>
  );
}

function IncidentItem({ s, active, onClick }: { s: IncidentSummary; active: boolean; onClick: () => void }) {
  return (
    <li>
      <button onClick={onClick} aria-pressed={active} className={`flex w-full flex-col gap-1.5 px-3 py-2.5 text-left hover:bg-panel-2 ${active ? "bg-panel-2" : ""}`}>
        <div className="flex items-center justify-between gap-2">
          <span className="truncate font-mono text-xs text-ink">{s.principal}</span>
          <span className="rounded-full border border-line px-1.5 text-[11px] text-ink-3">{s.split}</span>
        </div>
        <div className="text-xs text-ink-3">
          {relTime(s.start_seconds)} · {s.n_labeled_events} labeled events · {s.n_computers} computers
        </div>
        <div className="flex flex-wrap gap-1">
          {s.detections.map((d) => (
            <DetectionChip key={d.model_id} d={d} />
          ))}
        </div>
      </button>
    </li>
  );
}

function IncidentView({ id, models }: { id: string; models: ModelList }) {
  const state = useLoad(() => api.incident(id), id);
  if (state.status === "loading") return <LoadingBlock label="Loading incident…" />;
  if (state.status === "error") return <ErrorBlock error={state.error} />;
  if (!state.data) {
    return (
      <Panel>
        <p className="text-sm text-ink-2">This incident is not in the static export. Run the API to replay any incident.</p>
      </Panel>
    );
  }
  return <Player inc={state.data} models={models} />;
}

const SPEEDS = [
  { label: "1×", ms: 900 },
  { label: "3×", ms: 300 },
];

function Player({ inc, models }: { inc: Incident; models: ModelList }) {
  const n = inc.events.length;
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(0);
  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => {
      setStep((s) => {
        if (s >= n) {
          setPlaying(false);
          return s;
        }
        return s + 1;
      });
    }, SPEEDS[speed].ms);
    return () => clearInterval(t);
  }, [playing, speed, n]);
  // At the end of the replay the clock runs to the range end, so every window has closed.
  const t = step >= n ? inc.range_end_seconds : cursorTime(inc.events, step, inc.range_start_seconds);
  const s = inc.summary;
  const modelIds = models.models.map((m) => m.model_id);
  const names = Object.fromEntries(models.models.map((m) => [m.model_id, shortModelName(m.display_name)]));

  return (
    <div className="space-y-6">
      <Panel>
        <SectionTitle
          title={`${s.principal} · ${relTime(s.start_seconds)} → ${relTime(s.end_seconds)}`}
          subtitle={`${s.split} split · ${s.n_labeled_events} labeled events · ${inc.n_events_total} events by this account in the replay range`}
          right={<ProvenanceBadge provenance={inc.provenance} />}
        />
        <div className="space-y-1.5 text-sm leading-relaxed text-ink-2" data-testid="writeup">
          {inc.writeup.map((line) => (
            <p key={line}>{line}</p>
          ))}
        </div>
        <p className="mt-2 text-xs text-ink-3">Write-up generated from the numbers on this page by a fixed template; no language model is involved.</p>
      </Panel>

      <Panel>
        <SectionTitle title="Replay" subtitle={`Event ${step} of ${n} · clock ${relTime(t)}`} />
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <button className="rounded-md border border-line px-2.5 py-1 text-sm" onClick={() => { setPlaying(false); setStep(0); }} aria-label="Back to start">
            ⏮
          </button>
          <button className="rounded-md border border-line px-2.5 py-1 text-sm" onClick={() => setStep((x) => Math.max(0, x - 1))} aria-label="Previous event">
            ◀
          </button>
          <button
            className="rounded-md border border-line bg-panel-2 px-3 py-1 text-sm font-medium"
            onClick={() => {
              if (step >= n) setStep(0);
              setPlaying((p) => !p);
            }}
            data-testid="play"
          >
            {playing ? "Pause" : "Play"}
          </button>
          <button className="rounded-md border border-line px-2.5 py-1 text-sm" onClick={() => setStep((x) => Math.min(n, x + 1))} aria-label="Next event" data-testid="next">
            ▶
          </button>
          <button className="rounded-md border border-line px-2.5 py-1 text-sm" onClick={() => { setPlaying(false); setStep(n); }} aria-label="Jump to end" data-testid="end">
            ⏭
          </button>
          <div className="ml-2 inline-flex rounded-md border border-line text-xs" role="radiogroup" aria-label="Speed">
            {SPEEDS.map((sp, i) => (
              <button key={sp.label} role="radio" aria-checked={speed === i} onClick={() => setSpeed(i)} className={`px-2 py-1 ${speed === i ? "bg-panel-2 text-ink" : "text-ink-3"}`}>
                {sp.label}
              </button>
            ))}
          </div>
        </div>
        <input
          type="range"
          min={0}
          max={n}
          value={step}
          onChange={(e) => {
            setPlaying(false);
            setStep(Number(e.target.value));
          }}
          aria-label="Replay position"
          aria-valuetext={`event ${step} of ${n}, ${relTime(t)}`}
          className="w-full"
          data-testid="replay-slider"
        />
        <Timeline inc={inc} t={t} step={step} modelIds={modelIds} names={names} />
        <DetectionStatus inc={inc} t={t} />
      </Panel>

      <div className="grid gap-6">
        <Panel>
          <SectionTitle title="Path so far" subtitle="Remote authentications replayed up to the clock; the latest is highlighted." />
          <PathGraph inc={inc} step={step} />
        </Panel>
        <Panel>
          <SectionTitle title="Event log" subtitle="Newest first." />
          <EventLog inc={inc} step={step} />
        </Panel>
      </div>

      <Panel>
        <SectionTitle title="Windows in range" subtitle="Each account-hour as scored at its end. Links open the window's graph or evidence." />
        <WindowTable inc={inc} t={t} modelIds={modelIds} names={names} />
      </Panel>

      <Callout title="How to read this">
        <ul className="list-disc space-y-1 pl-5">
          {inc.caveats.map((c) => (
            <li key={c}>{c}</li>
          ))}
          {inc.events_truncated ? <li>Showing {inc.events.length} of {inc.n_events_total} events: every labeled event, then remote events first.</li> : null}
        </ul>
      </Callout>
    </div>
  );
}

const W = 760;
const LEFT = 70;
const RIGHT = 16;
const ROW = 30;

function Timeline({ inc, t, step, modelIds, names }: { inc: Incident; t: number; step: number; modelIds: string[]; names: Record<string, string> }) {
  const lo = inc.range_start_seconds;
  const hi = inc.range_end_seconds;
  const x = (v: number) => LEFT + ((v - lo) / (hi - lo)) * (W - LEFT - RIGHT);
  const winLen = inc.windows[0] ? inc.windows[0].window_end - inc.windows[0].window_start : 3600;
  const bounds: number[] = [];
  for (let b = lo; b <= hi; b += winLen) bounds.push(b);
  const rows = ["Labels", "Events", ...modelIds.map((m) => names[m])];
  const H = 26 + rows.length * ROW;
  const y = (i: number) => 18 + i * ROW + ROW / 2;
  const [tip, setTip] = useState<string | null>(null);
  return (
    <div className="mt-4">
      <div className="overflow-x-auto">
        <svg viewBox={`0 0 ${W} ${H}`} className="block h-auto w-full min-w-[560px]" role="img" aria-label="Incident timeline with events, labels and model alerts" data-testid="timeline">
          {bounds.map((b) => (
            <g key={b}>
              <line x1={x(b)} x2={x(b)} y1={14} y2={H - 4} stroke="var(--grid)" />
              <text x={x(b)} y={10} textAnchor={b === lo ? "start" : b + winLen > hi ? "end" : "middle"} fontSize={11} className="fill-ink-3">
                {`D${Math.floor(b / 86400)} +${Math.round((b % 86400) / 3600)}h`}
              </text>
            </g>
          ))}
          {rows.map((r, i) => (
            <text key={r} x={4} y={y(i) + 4} fontSize={12} className="fill-ink-2">
              {r}
            </text>
          ))}
          {inc.windows
            .filter((w) => w.label === "known_redteam")
            .map((w) => (
              <g key={w.window_id}>
                <rect x={x(w.window_start) + 1} y={y(0) - 8} width={x(w.window_end) - x(w.window_start) - 2} height={16} rx={3} fill="var(--redteam-soft)" />
                <path d={`M${x(w.window_start) + 8},${y(0) - 4} l4,4 l-4,4 l-4,-4 Z`} fill="var(--redteam)" />
              </g>
            ))}
          {inc.events.map((e, i) => {
            const past = i < step;
            const cx = x(e.event_time_seconds);
            return e.known_redteam ? (
              <path key={e.event_id} d={`M${cx},${y(1) - 7} l6,7 l-6,7 l-6,-7 Z`} fill="var(--redteam)" opacity={past ? 1 : 0.15} />
            ) : (
              <line key={e.event_id} x1={cx} x2={cx} y1={y(1) - 6} y2={y(1) + 6} stroke="var(--ink-3)" strokeWidth={e.outcome === "Fail" ? 2.5 : 1} opacity={past ? 0.9 : 0.15} />
            );
          })}
          {modelIds.map((m, mi) =>
            inc.windows.map((w) => {
              if (w.window_end > t) return null;
              const sc = w.scores[m];
              const shown = alertVisible(w, m, t);
              const label = `${names[m]} · window ${relTime(w.window_start)}: score ${fmtScore(sc.score)} vs threshold ${fmtScore(sc.threshold)}${shown ? ", alert" : ""}`;
              return (
                <g key={`${m}-${w.window_id}`} onMouseEnter={() => setTip(label)} onMouseLeave={() => setTip(null)} data-testid={shown ? `alert-${m}` : undefined}>
                  <title>{label}</title>
                  <rect x={x(w.window_end) - 9} y={y(2 + mi) - 9} width={18} height={18} fill="transparent" />
                  {shown ? (
                    <circle cx={x(w.window_end)} cy={y(2 + mi)} r={6} fill="var(--model)" stroke="var(--panel)" strokeWidth={1.5} />
                  ) : (
                    <circle cx={x(w.window_end)} cy={y(2 + mi)} r={2.5} fill="none" stroke="var(--ink-3)" />
                  )}
                </g>
              );
            }),
          )}
          <line x1={x(t)} x2={x(t)} y1={14} y2={H - 4} stroke="var(--ink)" strokeWidth={1.5} strokeDasharray="3 3" />
        </svg>
      </div>
      <div className="mt-1 min-h-5 text-xs text-ink-2" aria-live="polite">
        {tip}
      </div>
      <ul className="mt-1 flex flex-wrap gap-x-5 gap-y-1 text-xs text-ink-2">
        <li className="flex items-center gap-1.5">
          <svg aria-hidden width="12" height="12" viewBox="0 0 12 12"><path d="M6,0 L12,6 L6,12 L0,6 Z" fill="var(--redteam)" /></svg>
          Known red-team event / window (label)
        </li>
        <li className="flex items-center gap-1.5">
          <svg aria-hidden width="12" height="12" viewBox="0 0 12 12"><line x1="6" x2="6" y1="0" y2="12" stroke="var(--ink-3)" strokeWidth="2.5" /></svg>
          Other event (thick = failed)
        </li>
        <li className="flex items-center gap-1.5">
          <svg aria-hidden width="12" height="12" viewBox="0 0 12 12"><circle cx="6" cy="6" r="5" fill="var(--model)" /></svg>
          Model alert, placed at window end
        </li>
        <li className="flex items-center gap-1.5">
          <svg aria-hidden width="12" height="12" viewBox="0 0 12 12"><circle cx="6" cy="6" r="2.5" fill="none" stroke="var(--ink-3)" /></svg>
          Scored, below threshold
        </li>
      </ul>
    </div>
  );
}

function DetectionStatus({ inc, t }: { inc: Incident; t: number }) {
  return (
    <table className="mt-4 w-full text-left text-sm" data-testid="detection-status">
      <thead className="text-xs text-ink-3">
        <tr>
          <th className="py-1 font-normal">Model</th>
          <th className="py-1 font-normal">At this point in the replay</th>
          <th className="py-1 font-normal">Whole incident</th>
        </tr>
      </thead>
      <tbody>
        {inc.summary.detections.map((d) => {
          const fired = d.first_alert_seconds !== null && d.first_alert_seconds <= t;
          return (
            <tr key={d.model_id} className="border-t border-line">
              <td className="py-1.5 pr-3 text-ink">{d.display_name}</td>
              <td className="py-1.5 pr-3">
                {fired ? <AlertBadge flagged /> : <span className="text-xs text-ink-3">No alert on a labeled window yet</span>}
              </td>
              <td className="py-1.5 text-xs text-ink-2">
                {d.status === "detected"
                  ? `First alert ${duration(d.latency_seconds ?? 0)} after the first labeled event · ${d.alerted_labeled_windows}/${d.labeled_windows} labeled windows`
                  : d.status === "missed"
                    ? `Missed: 0/${d.labeled_windows} labeled windows (max score ${fmtScore(d.max_labeled_score ?? 0)} vs ${fmtScore(d.threshold)})`
                    : "No labeled window was scored"}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function PathGraph({ inc, step }: { inc: Incident; step: number }) {
  const edges = useMemo(() => pathSoFar(inc.events, step), [inc, step]);
  const nodes = useMemo(() => [...new Set(edges.flatMap((e) => [e.source, e.target]))], [edges]);
  const layout = useMemo(() => layoutGraph(nodes, edges, { colGap: 120, rowGap: 46, pad: 32 }), [nodes, edges]);
  if (!edges.length) return <p className="text-sm text-ink-3">No remote authentication replayed yet. Press Play or step forward.</p>;
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${Math.max(layout.width, 260)} ${layout.height + 16}`} className="block h-auto w-full min-w-[300px]" style={{ maxHeight: 360 }} role="img" aria-label="Computers reached so far" data-testid="path-graph">
        <defs>
          {[
            ["rp-arrow-redteam", "var(--redteam)"],
            ["rp-arrow-other", "var(--ink-3)"],
          ].map(([mid, fill]) => (
            <marker key={mid} id={mid} viewBox="0 0 10 10" refX="7" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,1 L9,5 L0,9 Z" fill={fill} />
            </marker>
          ))}
        </defs>
        {edges.map((e) => {
          const a = layout.nodes.get(e.source)!;
          const b = layout.nodes.get(e.target)!;
          const back = b.layer <= a.layer;
          const mx = (a.x + b.x) / 2;
          const d = back
            ? `M${a.x},${a.y + 8} Q${mx},${Math.max(a.y, b.y) + 50} ${b.x},${b.y + 10}`
            : `M${a.x + 8},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x - 11},${b.y}`;
          const color = e.redteam ? "var(--redteam)" : "var(--ink-3)";
          return (
            <g key={`${e.source}-${e.target}`}>
              {e.last ? <path d={d} fill="none" stroke="var(--focus)" strokeWidth={6} opacity={0.3} /> : null}
              <path d={d} fill="none" stroke={color} strokeWidth={e.redteam ? 2.2 : 1.2} markerEnd={`url(#${e.redteam ? "rp-arrow-redteam" : "rp-arrow-other"})`} />
              <title>{`${e.source} → ${e.target}: ${e.n} event(s)${e.redteam ? `, ${e.redteam} known red-team` : ""}`}</title>
            </g>
          );
        })}
        {nodes.map((id) => {
          const p = layout.nodes.get(id)!;
          return (
            <g key={id}>
              <circle cx={p.x} cy={p.y} r={8} fill="var(--panel)" stroke="var(--ink-2)" strokeWidth={1.5} />
              <text x={p.x} y={p.y + 21} textAnchor="middle" fontSize={10} className="fill-ink-2 font-mono">
                {id}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function EventLog({ inc, step }: { inc: Incident; step: number }) {
  const rows = inc.events.slice(0, step).reverse();
  if (!rows.length) return <p className="text-sm text-ink-3">Nothing replayed yet.</p>;
  return (
    <div className="max-h-[360px] overflow-auto">
      <table className="w-full min-w-[560px] text-left text-xs tabular-nums" data-testid="event-log">
        <thead className="sticky top-0 bg-panel text-ink-3">
          <tr>
            <th className="py-1 pr-2 font-normal">Time</th>
            <th className="py-1 pr-2 font-normal">Source → destination</th>
            <th className="py-1 pr-2 font-normal">Type</th>
            <th className="py-1 pr-2 font-normal">Outcome</th>
            <th className="py-1 font-normal">Label</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((e, i) => (
            <tr key={e.event_id} className={`border-t border-line ${i === 0 ? "bg-panel-2" : ""}`}>
              <td className="py-1 pr-2">{relTime(e.event_time_seconds)}</td>
              <td className="py-1 pr-2 font-mono">
                {e.src_computer ?? "?"} → {e.dst_computer ?? "?"}
              </td>
              <td className="py-1 pr-2">{[e.auth_type, e.auth_orientation].filter(Boolean).join(" · ")}</td>
              <td className="py-1 pr-2">{e.outcome ?? "Unknown"}</td>
              <td className="whitespace-nowrap py-1">{e.known_redteam ? <KnownRedteamBadge /> : <UnlabeledBadge />}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function WindowTable({ inc, t, modelIds, names }: { inc: Incident; t: number; modelIds: string[]; names: Record<string, string> }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-xs tabular-nums" data-testid="window-table">
        <thead className="text-ink-3">
          <tr>
            <th className="py-1 pr-2 font-normal">Window</th>
            <th className="py-1 pr-2 font-normal">Split</th>
            <th className="py-1 pr-2 font-normal">Label</th>
            {modelIds.map((m) => (
              <th key={m} className="py-1 pr-2 font-normal">
                {names[m]} score
              </th>
            ))}
            <th className="py-1 font-normal">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {inc.windows.map((w) => (
            <tr key={w.window_id} className="border-t border-line">
              <td className="py-1.5 pr-2">{relTime(w.window_start)}</td>
              <td className="py-1.5 pr-2">{w.split}</td>
              <td className="py-1.5 pr-2">{w.label === "known_redteam" ? <KnownRedteamBadge count={w.n_labeled_events} /> : <UnlabeledBadge />}</td>
              {modelIds.map((m) => {
                const sc = w.scores[m];
                const closed = w.window_end <= t;
                return (
                  <td key={m} className="py-1.5 pr-2">
                    {closed ? (
                      <span className="inline-flex items-center gap-1.5">
                        <span className="font-mono">{fmtScore(sc.score)}</span>
                        {sc.flagged ? <AlertBadge flagged /> : null}
                      </span>
                    ) : (
                      <span className="text-ink-3">window still open</span>
                    )}
                  </td>
                );
              })}
              <td className="py-1.5">
                {w.split === "test" ? (
                  <Link className="text-ink-2 underline decoration-line underline-offset-2 hover:text-ink" href={`/threatgraph/explorer/?window=${encodeURIComponent(w.window_id)}`}>
                    Graph →
                  </Link>
                ) : (
                  <span className="text-ink-3">Not available</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
