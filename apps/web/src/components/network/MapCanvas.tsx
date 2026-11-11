"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { forceLayout, type Positioned } from "@/lib/forceLayout";
import { int } from "@/lib/format";
import { neighbors, type AccountView, type ComputerView, type LinkView, type MapView } from "@/lib/networkMap";

const W = 1000;
const H = 640;
const MIN_K = 0.25;
const MAX_K = 6;

export const accountRadius = (a: AccountView) => Math.min(18, 7 + 1.6 * Math.sqrt(a.degree));
export const computerRadius = (c: ComputerView) => Math.min(11, 3.5 + 1.4 * Math.sqrt(c.degree));

interface Transform {
  k: number;
  x: number;
  y: number;
}

const ROLE_TEXT: Record<LinkView["link"]["role"], string> = {
  source: "authenticated from this computer",
  destination: "authenticated to this computer",
  both: "authenticated from and to this computer",
  local: "local logons on this computer",
};

export function MapCanvas({
  view,
  modelName,
  selected,
  onSelect,
  focus,
}: {
  view: MapView;
  modelName: string;
  selected: string | null;
  onSelect: (id: string | null) => void;
  /** Bumping `seq` centers the map on `id`. */
  focus: { id: string; seq: number } | null;
}) {
  const svg = useRef<SVGSVGElement>(null);
  const wrap = useRef<HTMLDivElement>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [tip, setTip] = useState<{ x: number; y: number; lines: string[] } | null>(null);
  const [dragging, setDragging] = useState(false);

  // Re-run the layout when the view changes, starting from the previous positions.
  const [placed, setPlaced] = useState<{ view: MapView; layout: ReturnType<typeof forceLayout> } | null>(null);
  let layout = placed?.layout;
  if (!placed || placed.view !== view) {
    layout = layoutView(view, placed?.layout.pos);
    setPlaced({ view, layout });
  }
  const lay = layout!;

  const fit = useMemo((): Transform => {
    const bw = Math.max(lay.maxX - lay.minX, 1);
    const bh = Math.max(lay.maxY - lay.minY, 1);
    const k = Math.min(MAX_K, Math.max(MIN_K, Math.min((W - 60) / bw, (H - 60) / bh)));
    return { k, x: W / 2 - k * (lay.minX + bw / 2), y: H / 2 - k * (lay.minY + bh / 2) };
  }, [lay]);
  const [t, setT] = useState<{ layout: unknown; value: Transform }>({ layout: lay, value: fit });
  const tf = t.layout === lay ? t.value : fit;
  const setTf = (value: Transform) => setT({ layout: lay, value });

  const [lastFocus, setLastFocus] = useState<number | null>(null);
  if (focus && focus.seq !== lastFocus) {
    setLastFocus(focus.seq);
    const p = lay.pos.get(focus.id);
    if (p) {
      const k = Math.max(tf.k, 1.8);
      setTf({ k, x: W / 2 - k * p.x, y: H / 2 - k * p.y });
    }
  }

  // Map a client point to viewBox coordinates.
  const toView = (cx: number, cy: number) => {
    const m = svg.current?.getScreenCTM();
    if (!m) return { x: cx, y: cy };
    const p = new DOMPoint(cx, cy).matrixTransform(m.inverse());
    return { x: p.x, y: p.y };
  };
  const zoomAt = (factor: number, at = { x: W / 2, y: H / 2 }, from = tf) => {
    const k = Math.min(MAX_K, Math.max(MIN_K, from.k * factor));
    const f = k / from.k;
    return { k, x: at.x - (at.x - from.x) * f, y: at.y - (at.y - from.y) * f };
  };

  // Wheel zoom needs a non-passive listener to stop the page from scrolling.
  const tfRef = useRef(tf);
  useEffect(() => {
    tfRef.current = tf;
  });
  useEffect(() => {
    const el = svg.current;
    if (!el) return;
    const onWheel = (ev: WheelEvent) => {
      ev.preventDefault();
      const m = el.getScreenCTM();
      const at = m ? new DOMPoint(ev.clientX, ev.clientY).matrixTransform(m.inverse()) : { x: W / 2, y: H / 2 };
      setT({ layout: lay, value: zoomAt(Math.exp(-ev.deltaY * 0.0015), { x: at.x, y: at.y }, tfRef.current) });
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lay]);

  const drag = useRef<{ x: number; y: number; tf: Transform; moved: boolean } | null>(null);
  const onPointerDown = (ev: React.PointerEvent) => {
    if ((ev.target as Element).closest("[data-node]")) return;
    const p = toView(ev.clientX, ev.clientY);
    drag.current = { x: p.x, y: p.y, tf, moved: false };
    setDragging(true);
    (ev.currentTarget as Element).setPointerCapture(ev.pointerId);
  };
  const onPointerMove = (ev: React.PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const p = toView(ev.clientX, ev.clientY);
    const dx = p.x - d.x;
    const dy = p.y - d.y;
    if (Math.abs(dx) + Math.abs(dy) > 2) d.moved = true;
    setTf({ k: d.tf.k, x: d.tf.x + dx, y: d.tf.y + dy });
  };
  const onPointerUp = () => {
    const d = drag.current;
    drag.current = null;
    setDragging(false);
    if (d && !d.moved) onSelect(null);
  };

  const accounts = useMemo(() => new Map(view.accounts.map((a) => [a.id, a])), [view]);
  const computers = useMemo(() => new Map(view.computers.map((c) => [c.id, c])), [view]);
  const active = hovered ?? selected;
  const lit = useMemo(() => (active ? neighbors(view, active) : null), [view, active]);
  const label = (id: string) => accounts.get(id)?.label ?? computers.get(id)?.label ?? id;

  const show = (ev: React.MouseEvent, lines: string[]) => {
    const r = wrap.current?.getBoundingClientRect();
    if (r) setTip({ x: Math.min(ev.clientX - r.left + 14, r.width - 260), y: ev.clientY - r.top + 14, lines });
  };
  const accountLines = (a: AccountView) => [
    a.label,
    `Account · ${a.degree} computer${a.degree === 1 ? "" : "s"} · ${int(a.events)} events in range`,
    a.alerts ? `${a.alerts} window${a.alerts === 1 ? "" : "s"} flagged by ${modelName}` : `No ${modelName} alert in range`,
    ...(a.redteamWindows ? [`${a.redteamWindows} window${a.redteamWindows === 1 ? "" : "s"} with known red-team events`] : []),
  ];
  const computerLines = (c: ComputerView) => [
    c.label,
    `Computer · ${c.degree} mapped account${c.degree === 1 ? "" : "s"} in range · ${c.computer.n_accounts_in_split} accounts in the split`,
    ...(c.knownRedteam ? [`${c.knownRedteam} known red-team event${c.knownRedteam === 1 ? "" : "s"} on mapped links`] : []),
  ];
  const linkLines = (l: LinkView) => [
    `${label(l.account)} · ${label(l.computer)}`,
    `${ROLE_TEXT[l.link.role]} · ${int(l.events)} events · ${l.fail} failed`,
    ...(l.alerted ? [`In a window flagged by ${modelName}`] : []),
    ...(l.knownRedteam ? [`${l.knownRedteam} known red-team event${l.knownRedteam === 1 ? "" : "s"}`] : []),
  ];

  const lk = (l: LinkView) => (l.knownRedteam ? 2 : l.alerted ? 1 : 0);
  const orderedLinks = useMemo(() => [...view.links].sort((a, b) => lk(a) - lk(b)), [view]);
  const showLabel = (id: string, important: boolean, degree: number) =>
    (lit?.has(id) ?? false) || id === selected || (important && tf.k >= 1.2) || tf.k >= 2.6 || (degree >= 3 && tf.k >= 1.8);
  const fs = 11 / tf.k;

  if (!view.accounts.length) {
    return (
      <p className="flex h-64 items-center justify-center rounded-lg border border-line bg-panel-2 p-4 text-sm text-ink-2" data-testid="map-empty">
        No accounts match these filters.
      </p>
    );
  }
  return (
    <div ref={wrap} className="relative" onMouseLeave={() => setTip(null)}>
      <div className="relative overflow-hidden rounded-lg border border-line bg-panel-2">
        <svg
          ref={svg}
          role="group"
          aria-label="Network map: accounts and the computers they authenticated from or to"
          data-testid="map-svg"
          viewBox={`0 0 ${W} ${H}`}
          className="block h-[min(70vh,640px)] w-full touch-none select-none"
          style={{ cursor: dragging ? "grabbing" : "grab" }}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={() => {
            drag.current = null;
            setDragging(false);
          }}
        >
          <g transform={`translate(${tf.x},${tf.y}) scale(${tf.k})`}>
            {orderedLinks.map((l) => {
              const a = lay.pos.get(l.account);
              const b = lay.pos.get(l.computer);
              if (!a || !b) return null;
              const on = lit ? lit.has(l.account) && lit.has(l.computer) && (l.account === active || l.computer === active) : true;
              const color = l.knownRedteam ? "var(--redteam)" : l.alerted ? "var(--model)" : "var(--ink-3)";
              const width = (l.knownRedteam ? 2 : l.alerted ? 1.1 : 0.8) * (lit && on ? 1.4 : 1);
              // Links into crowded hubs stay faint until a node is hovered or selected.
              const faint = !l.knownRedteam && lay.crowded.has(l.computer);
              const opacity = lit ? (on ? 0.95 : 0.04) : l.knownRedteam ? 0.95 : faint ? 0.07 : l.alerted ? 0.5 : 0.3;
              return (
                <g
                  key={l.id}
                  data-node
                  data-testid={l.knownRedteam ? "map-link-redteam" : l.alerted ? "map-link-alerted" : "map-link"}
                  onMouseMove={(ev) => show(ev, linkLines(l))}
                  onMouseLeave={() => setTip(null)}
                  onClick={() => onSelect(l.account)}
                  className="cursor-pointer"
                >
                  <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="transparent" strokeWidth={8 / tf.k} />
                  <line
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke={color}
                    strokeWidth={width / Math.sqrt(tf.k)}
                    strokeOpacity={opacity}
                    strokeDasharray={l.link.role === "local" ? `${3 / tf.k} ${3 / tf.k}` : undefined}
                  />
                </g>
              );
            })}
            {view.computers.map((c) => {
              const p = lay.pos.get(c.id)!;
              const r = computerRadius(c);
              const dim = lit && !lit.has(c.id);
              return (
                <g
                  key={c.id}
                  data-node
                  data-testid="map-computer"
                  opacity={dim ? 0.15 : 1}
                  className="cursor-pointer"
                  onClick={() => onSelect(c.id)}
                  onMouseEnter={() => setHovered(c.id)}
                  onMouseMove={(ev) => show(ev, computerLines(c))}
                  onMouseLeave={() => {
                    setHovered(null);
                    setTip(null);
                  }}
                >
                  {c.id === selected ? <rect x={p.x - r - 4} y={p.y - r - 4} width={2 * r + 8} height={2 * r + 8} rx={3} fill="none" stroke="var(--focus)" strokeWidth={2 / tf.k} /> : null}
                  <rect x={p.x - r} y={p.y - r} width={2 * r} height={2 * r} rx={1.5} fill="var(--ink-3)" fillOpacity={0.7} stroke="var(--panel-2)" strokeWidth={1} />
                  {c.knownRedteam ? <Diamond x={p.x + r * 0.9} y={p.y - r * 0.9} s={3.2} /> : null}
                  {showLabel(c.id, false, c.degree) ? <NodeLabel x={p.x} y={p.y + r + fs * 1.05} text={c.label} fs={fs} /> : null}
                </g>
              );
            })}
            {view.accounts.map((a) => {
              const p = lay.pos.get(a.id)!;
              const r = accountRadius(a);
              const dim = lit && !lit.has(a.id);
              return (
                <g
                  key={a.id}
                  data-node
                  data-testid="map-account"
                  role="button"
                  tabIndex={0}
                  aria-label={accountLines(a).join(". ")}
                  aria-pressed={a.id === selected}
                  opacity={dim ? 0.15 : 1}
                  className="cursor-pointer outline-none"
                  onClick={() => onSelect(a.id)}
                  onKeyDown={(ev) => {
                    if (ev.key === "Enter" || ev.key === " ") {
                      ev.preventDefault();
                      onSelect(a.id);
                    }
                  }}
                  onFocus={() => setHovered(a.id)}
                  onBlur={() => setHovered(null)}
                  onMouseEnter={() => setHovered(a.id)}
                  onMouseMove={(ev) => show(ev, accountLines(a))}
                  onMouseLeave={() => {
                    setHovered(null);
                    setTip(null);
                  }}
                >
                  {a.id === selected ? <circle cx={p.x} cy={p.y} r={r + 7} fill="none" stroke="var(--focus)" strokeWidth={2 / tf.k} /> : null}
                  {a.alerts ? <circle cx={p.x} cy={p.y} r={r + 3.2} fill="none" stroke="var(--model)" strokeWidth={2.4} data-testid="map-alert-ring" /> : null}
                  <circle cx={p.x} cy={p.y} r={r} fill="var(--ink-2)" stroke="var(--panel-2)" strokeWidth={1.2} />
                  <circle cx={p.x} cy={p.y - r * 0.22} r={r * 0.26} fill="var(--panel-2)" />
                  <path d={`M${p.x - r * 0.48},${p.y + r * 0.5} a${r * 0.48},${r * 0.4} 0 0 1 ${r * 0.96},0 Z`} fill="var(--panel-2)" />
                  {a.redteamWindows ? <Diamond x={p.x + r * 0.8} y={p.y - r * 0.8} s={4.4} testId="map-redteam-marker" /> : null}
                  {a.redteamWindows || showLabel(a.id, a.alerts > 0, a.degree) ? (
                    <NodeLabel x={p.x} y={p.y + r + fs * 1.15} text={a.label} fs={fs} strong />
                  ) : null}
                </g>
              );
            })}
          </g>
        </svg>
        <div className="absolute right-2 top-2 flex flex-col gap-1" role="group" aria-label="Zoom">
          {[
            ["+", "Zoom in", () => setTf(zoomAt(1.4))],
            ["−", "Zoom out", () => setTf(zoomAt(1 / 1.4))],
            ["⤢", "Fit to view", () => setTf(fit)],
          ].map(([text, aria, fn]) => (
            <button
              key={aria as string}
              aria-label={aria as string}
              title={aria as string}
              onClick={fn as () => void}
              className="h-8 w-8 rounded-md border border-line bg-panel text-sm text-ink-2 shadow-sm hover:text-ink"
            >
              {text as string}
            </button>
          ))}
        </div>
        <p className="pointer-events-none absolute bottom-2 left-3 text-[11px] text-ink-3" data-testid="map-hint">
          Scroll to zoom · drag to pan · click a node
          {lay.crowded.size
            ? ` · ${lay.crowded.size} computer${lay.crowded.size === 1 ? "" : "s"} shared by ${lay.crowdSize}+ mapped accounts sit${lay.crowded.size === 1 ? "s" : ""} in the middle with faint links; hover to trace them`
            : ""}
        </p>
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
    </div>
  );
}

function layoutView(view: MapView, previous?: Map<string, Positioned>) {
  return forceLayout(
    [
      ...view.accounts.map((a) => ({ id: a.id, r: accountRadius(a), hub: true })),
      ...view.computers.map((c) => ({ id: c.id, r: computerRadius(c), hub: false })),
    ],
    view.links.map((l) => ({ source: l.account, target: l.computer })),
    previous,
  );
}

function Diamond({ x, y, s, testId }: { x: number; y: number; s: number; testId?: string }) {
  return (
    <path
      d={`M${x},${y - s} L${x + s},${y} L${x},${y + s} L${x - s},${y} Z`}
      fill="var(--redteam)"
      stroke="var(--panel-2)"
      strokeWidth={1}
      data-testid={testId}
    />
  );
}

function NodeLabel({ x, y, text, fs, strong = false }: { x: number; y: number; text: string; fs: number; strong?: boolean }) {
  return (
    <text
      x={x}
      y={y}
      textAnchor="middle"
      fontSize={fs}
      className={`pointer-events-none font-mono ${strong ? "fill-ink" : "fill-ink-2"}`}
      stroke="var(--panel-2)"
      strokeWidth={fs / 3.5}
      paintOrder="stroke"
    >
      {text}
    </text>
  );
}
