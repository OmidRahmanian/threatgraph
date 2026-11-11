"use client";

import { api, isLiveApi, useLoad } from "@/lib/data";
import { int, relTime, score as fmtScore } from "@/lib/format";
import type { EntityDetail, GraphEdge, GraphNode } from "@/lib/types";
import { AlertBadge, ErrorBlock, KnownRedteamBadge, LoadingBlock, UnlabeledBadge } from "../ui";
import type { EdgeGroup } from "./GraphView";

export function EdgeEvidence({
  group,
  nodes,
  onEntity,
}: {
  group: EdgeGroup;
  nodes: Map<string, GraphNode>;
  onEntity: (id: string) => void;
}) {
  const label = (id: string) => nodes.get(id)?.label ?? id;
  return (
    <div className="space-y-4 fade-in" data-testid="edge-evidence">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <button className="font-mono text-ink underline decoration-line underline-offset-2" onClick={() => onEntity(group.source)}>
          {label(group.source)}
        </button>
        <span aria-hidden className="text-ink-3">→</span>
        <span className="sr-only">to</span>
        <button className="font-mono text-ink underline decoration-line underline-offset-2" onClick={() => onEntity(group.target)}>
          {label(group.target)}
        </button>
        {group.knownRedteam ? <KnownRedteamBadge count={group.knownRedteam} /> : <UnlabeledBadge />}
      </div>
      <p className="text-xs text-ink-3">
        Direction is as recorded: each event authenticated from {label(group.source)} to {label(group.target)}. One entry per
        account below.
      </p>
      {group.edges.map((e) => (
        <AccountEdge key={e.edge_id} e={e} onEntity={onEntity} />
      ))}
    </div>
  );
}

function AccountEdge({ e, onEntity }: { e: GraphEdge; onEntity: (id: string) => void }) {
  return (
    <div className="rounded-lg border border-line p-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <button className="font-mono text-ink underline decoration-line underline-offset-2" onClick={() => onEntity(e.principal_id)}>
          {e.principal}
        </button>
        <span className="text-xs text-ink-3">{e.hop === 1 ? "focus account" : "other account (hop 2)"}</span>
      </div>
      <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
        <Fact k="Events" v={int(e.n_events)} />
        <Fact k="Success / failed" v={`${e.n_success} / ${e.n_fail}`} />
        <Fact k="Auth types" v={e.auth_types.join(", ") || "Unknown"} />
        <Fact k="Pair first observed" v={relTime(e.edge_first_seen_seconds)} />
      </dl>
      <table className="mt-3 w-full text-left text-xs tabular-nums" data-testid="edge-events">
        <caption className="mb-1 text-left text-ink-3">
          {e.sample_events.length} of {int(e.n_events)} events shown (known red-team first, then earliest)
        </caption>
        <thead className="text-ink-3">
          <tr>
            <th className="py-1 pr-2 font-normal">Time</th>
            <th className="py-1 pr-2 font-normal">Type</th>
            <th className="py-1 pr-2 font-normal">Outcome</th>
            <th className="py-1 font-normal">Label</th>
          </tr>
        </thead>
        <tbody>
          {e.sample_events.map((ev) => (
            <tr key={ev.event_id} className="border-t border-line">
              <td className="py-1 pr-2">{relTime(ev.event_time_seconds)}</td>
              <td className="py-1 pr-2">
                {[ev.auth_type, ev.logon_type, ev.auth_orientation].filter(Boolean).join(" · ") || "Unknown"}
              </td>
              <td className="py-1 pr-2">{ev.outcome ?? "Unknown"}</td>
              <td className="py-1">{ev.known_redteam ? <KnownRedteamBadge /> : <UnlabeledBadge />}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Fact({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-ink-3">{k}</dt>
      <dd className="truncate text-ink-2">{v}</dd>
    </div>
  );
}

export function EntityPanel({
  entityId,
  onEntity,
  onWindow,
  windowIds,
}: {
  entityId: string;
  onEntity: (id: string) => void;
  onWindow: (windowId: string) => void;
  windowIds: Set<string>;
}) {
  const state = useLoad(() => api.entity(entityId), entityId);
  if (state.status === "loading") return <LoadingBlock label="Loading entity…" />;
  if (state.status === "error") return <ErrorBlock error={state.error} />;
  if (!state.data) {
    return (
      <p className="rounded-lg border border-line bg-panel-2 p-4 text-sm text-ink-2" data-testid="entity-unavailable">
        {isLiveApi
          ? "No entity with this id in the processed data."
          : "Details for this entity are not in the static export (it covers accounts and computers near exported windows and on the network maps). Run the API to inspect any entity."}
      </p>
    );
  }
  return <EntityView e={state.data} onEntity={onEntity} onWindow={onWindow} windowIds={windowIds} />;
}

function EntityView({
  e,
  onEntity,
  onWindow,
  windowIds,
}: {
  e: EntityDetail;
  onEntity: (id: string) => void;
  onWindow: (windowId: string) => void;
  windowIds: Set<string>;
}) {
  const facts: [string, React.ReactNode][] = [
    ["Active", `${relTime(e.first_seen_seconds)} → ${relTime(e.last_seen_seconds)}`],
    ["Events", `${int(e.n_events)} (${int(e.n_fail)} failed)`],
    ["Known red-team events", int(e.n_known_redteam_events)],
  ];
  if (e.entity_type === "principal") {
    facts.push(
      ["Active windows", int(e.n_active_windows ?? 0)],
      ["Source computers", int(e.n_distinct_src_computers ?? 0)],
      ["Destination computers", int(e.n_distinct_dst_computers ?? 0)],
    );
  } else {
    facts.push(
      ["Accounts", int(e.n_distinct_principals ?? 0)],
      ["Inbound from", `${int(e.in_degree ?? 0)} computers`],
      ["Outbound to", `${int(e.out_degree ?? 0)} computers`],
      ["Local logon events", int(e.n_local_events ?? 0)],
    );
  }
  return (
    <div className="space-y-4 fade-in" data-testid="entity-panel">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded-full border border-line px-2 py-0.5 text-xs text-ink-3">{e.entity_type === "principal" ? "Account" : "Computer"}</span>
        <span className="font-mono text-sm text-ink">{e.label}</span>
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-3">
        {facts.map(([k, v]) => (
          <div key={k}>
            <dt className="text-xs text-ink-3">{k}</dt>
            <dd className="text-ink-2 tabular-nums">{v}</dd>
          </div>
        ))}
      </dl>
      {e.model_windows.length ? (
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-ink">Highest-scoring test windows</h3>
          {e.model_windows.map((m) => (
            <div key={m.model_id} className="text-xs">
              <div className="text-ink-2">
                {m.display_name}: {m.alerts} of {m.n_windows} test windows alerted
              </div>
              <ul className="mt-1 flex flex-wrap gap-1.5">
                {m.top_windows.map((w) => {
                  const available = windowIds.has(w.window_id);
                  return (
                    <li key={w.window_id}>
                      <button
                        disabled={!available}
                        onClick={() => onWindow(w.window_id)}
                        title={available ? "Show this window's graph" : "Window not in the exported list"}
                        className="flex items-center gap-1.5 rounded-md border border-line px-2 py-1 enabled:hover:bg-panel-2 disabled:opacity-60"
                      >
                        <span>{relTime(w.window_start)}</span>
                        <span className="font-mono text-ink-3">{fmtScore(w.score)}</span>
                        {w.flagged ? <AlertBadge flagged /> : null}
                        {w.known_redteam ? <KnownRedteamBadge /> : null}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
      ) : null}
      <div>
        <h3 className="text-sm font-medium text-ink">
          {e.entity_type === "principal" ? "Most-used computers" : "Most active accounts"}{" "}
          <span className="font-normal text-ink-3">
            (top {e.top_links.length} of {int(e.n_links_total)})
          </span>
        </h3>
        <table className="mt-1 w-full text-left text-xs tabular-nums">
          <thead className="text-ink-3">
            <tr>
              <th className="py-1 font-normal">{e.entity_type === "principal" ? "Computer" : "Account"}</th>
              <th className="py-1 text-right font-normal">Events</th>
              <th className="py-1 text-right font-normal">Known red-team</th>
              <th className="py-1 font-normal pl-3">Active</th>
            </tr>
          </thead>
          <tbody>
            {e.top_links.map((l) => (
              <tr key={l.entity_id} className="border-t border-line">
                <td className="py-1">
                  <button className="font-mono text-ink underline decoration-line underline-offset-2" onClick={() => onEntity(l.entity_id)}>
                    {l.label}
                  </button>
                </td>
                <td className="py-1 text-right">{int(l.n_events)}</td>
                <td className="py-1 text-right">{l.n_known_redteam}</td>
                <td className="py-1 pl-3">
                  {relTime(l.first_seen_seconds)} → {relTime(l.last_seen_seconds)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-ink-3">{e.scope}</p>
    </div>
  );
}
