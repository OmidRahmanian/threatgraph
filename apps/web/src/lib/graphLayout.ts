// Deterministic layered layout for small directed authentication graphs.
//
// Edges are added in time order (first event first); an edge that would close a cycle is
// kept for drawing but marked as a back edge and ignored for layering. Each node's layer is
// its longest path from a source in the remaining DAG, so a hop chain A→B→C reads left to
// right in the order it happened. Within a layer, nodes are ordered by first activity.

export interface LayoutEdge {
  source: string;
  target: string;
  first: number;
}

export interface PlacedNode {
  id: string;
  layer: number;
  x: number;
  y: number;
}

export interface Layout {
  nodes: Map<string, PlacedNode>;
  backEdges: Set<string>; // `${source}->${target}`
  width: number;
  height: number;
}

export const edgeKey = (source: string, target: string) => `${source}->${target}`;

export function layoutGraph(
  nodeIds: readonly string[],
  edges: readonly LayoutEdge[],
  opts: { colGap?: number; rowGap?: number; pad?: number } = {},
): Layout {
  const colGap = opts.colGap ?? 170;
  const rowGap = opts.rowGap ?? 56;
  const pad = opts.pad ?? 48;
  const ordered = [...edges]
    .filter((e) => e.source !== e.target)
    .sort((a, b) => a.first - b.first || a.source.localeCompare(b.source) || a.target.localeCompare(b.target));

  const out = new Map<string, Set<string>>(nodeIds.map((n) => [n, new Set()]));
  const reaches = (from: string, to: string): boolean => {
    const seen = new Set<string>();
    const stack = [from];
    while (stack.length) {
      const n = stack.pop()!;
      if (n === to) return true;
      if (seen.has(n)) continue;
      seen.add(n);
      for (const m of out.get(n) ?? []) stack.push(m);
    }
    return false;
  };
  const backEdges = new Set<string>();
  for (const e of ordered) {
    if (!out.has(e.source)) out.set(e.source, new Set());
    if (!out.has(e.target)) out.set(e.target, new Set());
    if (out.get(e.source)!.has(e.target)) continue;
    if (reaches(e.target, e.source)) backEdges.add(edgeKey(e.source, e.target));
    else out.get(e.source)!.add(e.target);
  }

  // Longest-path layering via Kahn's algorithm (sorted queue keeps it deterministic).
  const indeg = new Map<string, number>([...out.keys()].map((n) => [n, 0]));
  for (const targets of out.values()) for (const t of targets) indeg.set(t, (indeg.get(t) ?? 0) + 1);
  const layer = new Map<string, number>();
  let queue = [...indeg].filter(([, d]) => d === 0).map(([n]) => n).sort();
  for (const n of queue) layer.set(n, 0);
  while (queue.length) {
    const next: string[] = [];
    for (const n of queue) {
      for (const t of out.get(n)!) {
        layer.set(t, Math.max(layer.get(t) ?? 0, layer.get(n)! + 1));
        indeg.set(t, indeg.get(t)! - 1);
        if (indeg.get(t) === 0) next.push(t);
      }
    }
    queue = next.sort();
  }

  const firstSeen = new Map<string, number>();
  for (const e of edges) {
    for (const n of [e.source, e.target]) firstSeen.set(n, Math.min(firstSeen.get(n) ?? Infinity, e.first));
  }
  const byLayer = new Map<number, string[]>();
  for (const n of out.keys()) {
    const l = layer.get(n) ?? 0;
    byLayer.set(l, [...(byLayer.get(l) ?? []), n]);
  }
  const tallest = Math.max(1, ...[...byLayer.values()].map((v) => v.length));
  const nLayers = Math.max(1, ...[...byLayer.keys()].map((l) => l + 1));
  const nodes = new Map<string, PlacedNode>();
  for (const [l, members] of byLayer) {
    members.sort((a, b) => (firstSeen.get(a) ?? Infinity) - (firstSeen.get(b) ?? Infinity) || a.localeCompare(b));
    const offset = ((tallest - members.length) * rowGap) / 2;
    members.forEach((id, i) => nodes.set(id, { id, layer: l, x: pad + l * colGap, y: pad + offset + i * rowGap }));
  }
  return {
    nodes,
    backEdges,
    width: pad * 2 + (nLayers - 1) * colGap,
    height: pad * 2 + (tallest - 1) * rowGap,
  };
}
