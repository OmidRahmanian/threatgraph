// Force-directed layout for the network map, run to completion before drawing.
//
// d3-force seeds its jitter from a fixed LCG and places new nodes on a phyllotaxis spiral,
// so the same input always yields the same picture. Nodes that were already placed start
// from their previous position, so changing a filter moves the graph instead of redrawing it.

import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationNodeDatum } from "d3-force";

export interface ForceNode {
  id: string;
  r: number;
  /** Accounts repel more strongly, so each one's computers fan out around it. */
  hub: boolean;
}

export interface ForceLink {
  source: string;
  target: string;
}

export interface Positioned {
  x: number;
  y: number;
}

export interface ForceResult {
  pos: Map<string, Positioned>;
  /** Computers linked to at least `crowdSize` accounts; laid out at their accounts' centroid. */
  crowded: Set<string>;
  crowdSize: number;
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
}

type SimNode = SimulationNodeDatum & ForceNode;

export function forceLayout(
  nodes: readonly ForceNode[],
  links: readonly ForceLink[],
  previous?: Map<string, Positioned>,
  ticks = 300,
): ForceResult {
  const sim: SimNode[] = nodes.map((n) => {
    const p = previous?.get(n.id);
    return p ? { ...n, x: p.x, y: p.y } : { ...n };
  });
  const ids = new Set(nodes.map((n) => n.id));
  const simLinks = links.filter((l) => ids.has(l.source) && ids.has(l.target)).map((l) => ({ ...l }));
  const degree = new Map<string, number>();
  for (const l of simLinks) for (const id of [l.source, l.target]) degree.set(id, (degree.get(id) ?? 0) + 1);
  // Computers shared by a large share of the accounts (domain controllers, file servers) would
  // pull every account into one ball. They stay drawn and linked, but barely pull, and settle
  // at the centroid of their accounts.
  const nHubs = nodes.filter((n) => n.hub).length;
  const crowd = Math.max(5, Math.ceil(0.2 * nHubs));
  const crowded = new Set(nodes.filter((n) => !n.hub && (degree.get(n.id) ?? 0) >= crowd).map((n) => n.id));

  const simulation = forceSimulation<SimNode>(sim)
    .force(
      "link",
      forceLink<SimNode, (typeof simLinks)[number] & { source: string | SimNode; target: string | SimNode }>(simLinks)
        .id((d) => d.id)
        .distance((l) => {
          const s = l.source as SimNode;
          const t = l.target as SimNode;
          // Computers used by one account sit close to it; shared ones are pulled between.
          const shared = Math.min(degree.get(s.id) ?? 1, degree.get(t.id) ?? 1) > 1;
          return s.r + t.r + (shared ? 80 : 14);
        })
        // A computer shared by k accounts pulls on each with 1/k, so busy hubs do not drag
        // every account into one clump.
        .strength((l) => {
          const s = (l.source as SimNode).id;
          const t = (l.target as SimNode).id;
          if (crowded.has(s) || crowded.has(t)) return 0.01;
          return 0.9 / Math.min(degree.get(s) ?? 1, degree.get(t) ?? 1);
        }),
    )
    .force("charge", forceManyBody<SimNode>().strength((d) => (d.hub ? -900 : -18)).distanceMax(700))
    .force("collide", forceCollide<SimNode>().radius((d) => d.r + 2.5).iterations(2))
    .force("x", forceX<SimNode>(0).strength(0.04))
    .force("y", forceY<SimNode>(0).strength(0.04))
    .stop();
  // Already-placed graphs only need to settle.
  const n = previous && previous.size ? Math.round(ticks / 2) : ticks;
  if (previous && previous.size) simulation.alpha(0.5);
  simulation.tick(n);
  const byId = new Map(sim.map((s) => [s.id, s]));
  for (const id of crowded) {
    // forceLink replaced simLinks' endpoints with node objects; `links` still holds ids.
    const ends = links
      .map((l) => (l.source === id ? l.target : l.target === id ? l.source : null))
      .filter((x): x is string => x !== null && byId.has(x));
    const c = byId.get(id)!;
    c.x = ends.reduce((a, e) => a + (byId.get(e)!.x ?? 0), 0) / ends.length;
    c.y = ends.reduce((a, e) => a + (byId.get(e)!.y ?? 0), 0) / ends.length;
  }
  // Let collisions push the moved hubs off anything they landed on.
  simulation.force("link", null).force("charge", null).alpha(0.1);
  simulation.tick(20);

  const pos = new Map<string, Positioned>();
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const s of sim) {
    const x = s.x ?? 0;
    const y = s.y ?? 0;
    pos.set(s.id, { x, y });
    minX = Math.min(minX, x - s.r);
    minY = Math.min(minY, y - s.r);
    maxX = Math.max(maxX, x + s.r);
    maxY = Math.max(maxY, y + s.r);
  }
  if (!sim.length) return { pos, crowded, crowdSize: crowd, minX: 0, minY: 0, maxX: 0, maxY: 0 };
  return { pos, crowded, crowdSize: crowd, minX, minY, maxX, maxY };
}
