"use client";

import { useMemo, useRef, useState } from "react";
import { edgeKey, layoutGraph } from "@/lib/graphLayout";
import { int, relTime } from "@/lib/format";
import type { GraphEdge, GraphNode, Subgraph } from "@/lib/types";

export interface EdgeGroup {
  key: string;
  source: string;
  target: string;
  edges: GraphEdge[];
  hop: number;
  knownRedteam: number;
  firstObserved: boolean;
  nEvents: number;
  nFail: number;
  first: number;
}

export type Selection = { kind: "edge"; key: string } | { kind: "node"; id: string } | null;

/** Edges drawn between the same two computers are merged; local logons become node loops. */
export function groupEdges(edges: readonly GraphEdge[]): { groups: EdgeGroup[]; local: Map<string, GraphEdge[]> } {
  const groups = new Map<string, EdgeGroup>();
  const local = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    if (e.is_local) {
      local.set(e.source, [...(local.get(e.source) ?? []), e]);
      continue;
    }
    const key = edgeKey(e.source, e.target);
    const g = groups.get(key) ?? {
      key,
      source: e.source,
      target: e.target,
      edges: [],
      hop: e.hop,
      knownRedteam: 0,
      firstObserved: false,
      nEvents: 0,
      nFail: 0,
      first: e.first_event_seconds,
    };
    g.edges.push(e);
    g.hop = Math.min(g.hop, e.hop);
    g.knownRedteam += e.n_known_redteam;
    g.firstObserved ||= e.first_observed_in_range;
    g.nEvents += e.n_events;
    g.nFail += e.n_fail;
    g.first = Math.min(g.first, e.first_event_seconds);
    groups.set(key, g);
  }
  return { groups: [...groups.values()], local };
}

const R = 9;

function edgePath(x1: number, y1: number, x2: number, y2: number, curved: boolean) {
  // Forward edges are horizontal S-curves; same-layer and back edges bow out so that a
  // reverse pair (A→B and B→A) never overlaps.
  const dx = x2 - x1;
  const dy = y2 - y1;
  let c1x: number, c1y: number, c2x: number, c2y: number;
  if (!curved && dx > 0) {
    c1x = x1 + dx / 2;
    c1y = y1;
    c2x = x2 - dx / 2;
    c2y = y2;
  } else {
    const len = Math.hypot(dx, dy) || 1;
    const bow = Math.max(36, len * 0.35);
    const nx = -dy / len;
    const ny = dx / len;
    c1x = x1 + dx / 3 + nx * bow;
    c1y = y1 + dy / 3 + ny * bow;
    c2x = x1 + (2 * dx) / 3 + nx * bow;
    c2y = y1 + (2 * dy) / 3 + ny * bow;
  }
  // Start and end on the node rims, along the curve's tangent.
  const sLen = Math.hypot(c1x - x1, c1y - y1) || 1;
  const eLen = Math.hypot(x2 - c2x, y2 - c2y) || 1;
  const sx = x1 + ((c1x - x1) / sLen) * R;
  const sy = y1 + ((c1y - y1) / sLen) * R;
  const ex = x2 - ((x2 - c2x) / eLen) * (R + 3);
  const ey = y2 - ((y2 - c2y) / eLen) * (R + 3);
  // Midpoint of the cubic (t = 0.5) for the red-team marker.
  const mx = (sx + 3 * c1x + 3 * c2x + ex) / 8;
  const my = (sy + 3 * c1y + 3 * c2y + ey) / 8;
  return { d: `M${sx},${sy} C${c1x},${c1y} ${c2x},${c2y} ${ex},${ey}`, mx, my };
}

function strokeFor(g: EdgeGroup) {
  if (g.knownRedteam > 0) return { color: "var(--redteam)", width: 2.5, marker: "arrow-redteam", opacity: 1 };
  if (g.hop === 1) return { color: "var(--ink-2)", width: 1.6, marker: "arrow-focus", opacity: 1 };
  return { color: "var(--ink-3)", width: 1, marker: "arrow-other", opacity: 0.55 };
}

export function GraphView({
  graph,
  showHop2,
  selection,
  onSelect,
}: {
  graph: Subgraph;
  showHop2: boolean;
  selection: Selection;
  onSelect: (s: Selection) => void;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const [tip, setTip] = useState<{ x: number; y: number; lines: string[] } | null>(null);
  const visible = useMemo(() => graph.edges.filter((e) => e.hop <= (showHop2 ? 2 : 1)), [graph, showHop2]);
  const { groups, local } = useMemo(() => groupEdges(visible), [visible]);
  const nodes = useMemo(() => {
    const ids = new Set(visible.flatMap((e) => [e.source, e.target]));
    return graph.nodes.filter((n) => ids.has(n.node_id) || n.hop === 0);
  }, [graph, visible]);
  const layout = useMemo(
    () => layoutGraph(nodes.map((n) => n.node_id), groups.map((g) => ({ source: g.source, target: g.target, first: g.first }))),
    [nodes, groups],
  );
  const byId = useMemo(() => new Map(nodes.map((n) => [n.node_id, n])), [nodes]);

  const show = (ev: React.MouseEvent, lines: string[]) => {
    const r = wrap.current?.getBoundingClientRect();
    if (r) setTip({ x: ev.clientX - r.left + 12, y: ev.clientY - r.top + 12, lines });
  };
  const keySelect = (s: Selection) => (ev: React.KeyboardEvent) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      onSelect(s);
    }
  };
  const edgeLines = (g: EdgeGroup) => [
    `${labelOf(byId, g.source)} → ${labelOf(byId, g.target)}`,
    `${int(g.nEvents)} events · ${g.nFail} failed · ${g.edges.length} account${g.edges.length === 1 ? "" : "s"}`,
    ...(g.knownRedteam ? [`${g.knownRedteam} known red-team event${g.knownRedteam === 1 ? "" : "s"}`] : []),
    ...(g.firstObserved ? ["First observed in this window"] : []),
  ];
  const nodeLines = (n: GraphNode) => [
    n.label,
    `${n.n_principals_in_range} account${n.n_principals_in_range === 1 ? "" : "s"} in this window${n.is_hub ? " · hub (not expanded)" : ""}`,
    ...(local.get(n.node_id) ? [`${local.get(n.node_id)!.reduce((a, e) => a + e.n_events, 0)} local logon events`] : []),
  ];

  if (nodes.length === 0) {
    return <p className="rounded-lg border border-line bg-panel-2 p-4 text-sm text-ink-2">No in-scope edges in this window.</p>;
  }
  return (
    <div ref={wrap} className="relative" onMouseLeave={() => setTip(null)}>
      <div className="overflow-x-auto rounded-lg border border-line bg-panel">
        <svg
          role="group"
          aria-label="Authentication graph: computers as nodes, directed edges from source to destination"
          data-testid="graph-svg"
          viewBox={`0 0 ${Math.max(layout.width, 320)} ${layout.height + 24}`}
          className="block h-auto w-full min-w-[520px]"
          style={{ maxHeight: 620 }}
        >
          <defs>
            {[
              ["arrow-redteam", "var(--redteam)"],
              ["arrow-focus", "var(--ink-2)"],
              ["arrow-other", "var(--ink-3)"],
            ].map(([id, color]) => (
              <marker key={id} id={id} viewBox="0 0 10 10" refX="7" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0,1 L9,5 L0,9 Z" fill={color} />
              </marker>
            ))}
          </defs>
          {groups.map((g) => {
            const a = layout.nodes.get(g.source)!;
            const b = layout.nodes.get(g.target)!;
            const { d, mx, my } = edgePath(a.x, a.y, b.x, b.y, layout.backEdges.has(g.key) || b.layer <= a.layer);
            const st = strokeFor(g);
            const selected = selection?.kind === "edge" && selection.key === g.key;
            return (
              <g
                key={g.key}
                role="button"
                tabIndex={0}
                aria-label={edgeLines(g).join(". ")}
                aria-pressed={selected}
                data-testid={g.knownRedteam ? "edge-redteam" : "edge"}
                className="cursor-pointer outline-none"
                onClick={() => onSelect({ kind: "edge", key: g.key })}
                onKeyDown={keySelect({ kind: "edge", key: g.key })}
                onMouseMove={(ev) => show(ev, edgeLines(g))}
              >
                <path d={d} fill="none" stroke="transparent" strokeWidth={14} />
                {selected ? <path d={d} fill="none" stroke="var(--focus)" strokeWidth={st.width + 4} opacity={0.35} /> : null}
                <path
                  d={d}
                  fill="none"
                  stroke={st.color}
                  strokeWidth={st.width}
                  strokeOpacity={st.opacity}
                  strokeDasharray={g.firstObserved ? "5 4" : undefined}
                  markerEnd={`url(#${st.marker})`}
                />
                {g.knownRedteam ? (
                  <path d={`M${mx},${my - 6} L${mx + 6},${my} L${mx},${my + 6} L${mx - 6},${my} Z`} fill="var(--redteam)" stroke="var(--panel)" strokeWidth={1.5} />
                ) : null}
              </g>
            );
          })}
          {nodes.map((n) => {
            const p = layout.nodes.get(n.node_id)!;
            const selected = selection?.kind === "node" && selection.id === n.node_id;
            const loops = local.get(n.node_id);
            const loopRed = loops?.some((e) => e.n_known_redteam > 0);
            const faded = n.hop === 2;
            return (
              <g
                key={n.node_id}
                role="button"
                tabIndex={0}
                aria-label={nodeLines(n).join(". ")}
                aria-pressed={selected}
                data-testid="graph-node"
                className="cursor-pointer outline-none"
                onClick={() => onSelect({ kind: "node", id: n.node_id })}
                onKeyDown={keySelect({ kind: "node", id: n.node_id })}
                onMouseMove={(ev) => show(ev, nodeLines(n))}
                opacity={faded ? 0.7 : 1}
              >
                {loops ? (
                  <path
                    d={`M${p.x - 5},${p.y - R + 1} C${p.x - 16},${p.y - 30} ${p.x + 16},${p.y - 30} ${p.x + 5},${p.y - R + 1}`}
                    fill="none"
                    stroke={loopRed ? "var(--redteam)" : "var(--ink-3)"}
                    strokeWidth={loopRed ? 2 : 1.2}
                  />
                ) : null}
                {selected ? <circle cx={p.x} cy={p.y} r={R + 5} fill="none" stroke="var(--focus)" strokeWidth={2} /> : null}
                {n.is_hub ? (
                  <rect x={p.x - R} y={p.y - R} width={R * 2} height={R * 2} rx={2} fill="var(--panel-2)" stroke="var(--ink-3)" strokeWidth={1.5} />
                ) : (
                  <circle cx={p.x} cy={p.y} r={R} fill="var(--panel)" stroke={n.hop <= 1 ? "var(--ink-2)" : "var(--ink-3)"} strokeWidth={n.hop === 0 ? 3 : 1.5} />
                )}
                <text x={p.x} y={p.y + R + 13} textAnchor="middle" className="fill-ink-2 font-mono" fontSize={10}>
                  {n.label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      {tip ? (
        <div
          role="tooltip"
          className="pointer-events-none absolute z-10 max-w-xs rounded-md border border-line bg-panel px-2.5 py-1.5 text-xs text-ink-2 shadow-sm"
          style={{ left: tip.x, top: tip.y }}
        >
          {tip.lines.map((l, i) => (
            <div key={i} className={i === 0 ? "font-mono text-ink" : ""}>
              {l}
            </div>
          ))}
        </div>
      ) : null}
      <Legend />
      <EdgeTable groups={groups} local={local} byId={byId} selection={selection} onSelect={onSelect} />
    </div>
  );
}

function labelOf(byId: Map<string, GraphNode>, id: string) {
  return byId.get(id)?.label ?? id.replace(/^computer:/, "");
}

function Legend() {
  const item = (svg: React.ReactNode, text: string) => (
    <li className="flex items-center gap-2">
      <svg aria-hidden width="34" height="14" viewBox="0 0 34 14">
        {svg}
      </svg>
      {text}
    </li>
  );
  return (
    <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-xs text-ink-2" aria-label="Graph legend">
      {item(
        <>
          <line x1="2" y1="7" x2="32" y2="7" stroke="var(--redteam)" strokeWidth="2.5" />
          <path d="M17,2 L22,7 L17,12 L12,7 Z" fill="var(--redteam)" />
        </>,
        "Contains known red-team events (label from the red-team file)",
      )}
      {item(<line x1="2" y1="7" x2="32" y2="7" stroke="var(--ink-2)" strokeWidth="1.6" />, "This account's authentication (direction = arrow)")}
      {item(<line x1="2" y1="7" x2="32" y2="7" stroke="var(--ink-3)" strokeOpacity="0.55" strokeWidth="1" />, "Other accounts on the same computers")}
      {item(<line x1="2" y1="7" x2="32" y2="7" stroke="var(--ink-2)" strokeWidth="1.6" strokeDasharray="5 4" />, "Computer pair first observed in this window")}
      {item(<rect x="11" y="1" width="12" height="12" rx="2" fill="var(--panel-2)" stroke="var(--ink-3)" strokeWidth="1.5" />, "Hub: too many accounts to expand")}
      {item(<path d="M12,12 C6,0 28,0 22,12" fill="none" stroke="var(--ink-3)" strokeWidth="1.2" />, "Local logon (source = destination)")}
    </ul>
  );
}

function EdgeTable({
  groups,
  local,
  byId,
  selection,
  onSelect,
}: {
  groups: EdgeGroup[];
  local: Map<string, GraphEdge[]>;
  byId: Map<string, GraphNode>;
  selection: Selection;
  onSelect: (s: Selection) => void;
}) {
  const rows = [...groups].sort((a, b) => a.hop - b.hop || a.first - b.first || a.key.localeCompare(b.key));
  return (
    <details className="mt-4 rounded-lg border border-line">
      <summary className="cursor-pointer px-3 py-2 text-sm text-ink-2">
        Table view · {groups.length} edges{local.size ? `, ${local.size} computers with local logons` : ""}
      </summary>
      <div className="max-h-80 overflow-auto">
        <table className="w-full text-left text-xs tabular-nums" data-testid="edge-table">
          <thead className="sticky top-0 bg-panel text-ink-3">
            <tr>
              <th className="px-3 py-1.5 font-normal">Source → destination</th>
              <th className="px-3 py-1.5 font-normal">Hop</th>
              <th className="px-3 py-1.5 text-right font-normal">Events</th>
              <th className="px-3 py-1.5 text-right font-normal">Failed</th>
              <th className="px-3 py-1.5 text-right font-normal">Known red-team</th>
              <th className="px-3 py-1.5 font-normal">First event</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((g) => (
              <tr key={g.key} className={`border-t border-line ${selection?.kind === "edge" && selection.key === g.key ? "bg-panel-2" : ""}`}>
                <td className="px-3 py-1.5">
                  <button className="font-mono text-ink underline decoration-line underline-offset-2" onClick={() => onSelect({ kind: "edge", key: g.key })}>
                    {labelOf(byId, g.source)} → {labelOf(byId, g.target)}
                  </button>
                </td>
                <td className="px-3 py-1.5">{g.hop}</td>
                <td className="px-3 py-1.5 text-right">{int(g.nEvents)}</td>
                <td className="px-3 py-1.5 text-right">{g.nFail}</td>
                <td className="px-3 py-1.5 text-right">{g.knownRedteam || "—"}</td>
                <td className="px-3 py-1.5">{relTime(g.first)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
