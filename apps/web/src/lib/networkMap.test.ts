import { describe, expect, it } from "vitest";
import { forceLayout } from "./forceLayout";
import { buildView, neighbors, searchNodes } from "./networkMap";
import type { MapAccount, MapLink, NetworkMap, WindowScore } from "./types";

const ws = (flagged: boolean): WindowScore => ({ score: flagged ? 2 : 0.1, threshold: 1, flagged, rank: 1 });

const account = (id: string, windows: MapAccount["windows"]): MapAccount => ({
  node_id: `principal:${id}`,
  label: id,
  n_windows: 10,
  n_known_redteam_windows: windows.filter((w) => w.known_redteam).length,
  n_computers_total: 2,
  n_computers_shown: 2,
  days: [1, 2],
  scores: { m0: { max_score: 2, best_rank: 1, n_alerts: 1, alert_days: [1] }, m1: { max_score: 1, best_rank: 5, n_alerts: 0, alert_days: [] } },
  windows,
});

const link = (a: string, c: string, byDay: MapLink["by_day"]): MapLink => ({
  account: `principal:${a}`,
  computer: `computer:${c}`,
  role: "destination",
  n_events: byDay.reduce((s, d) => s + d.n_events, 0),
  n_fail: 0,
  n_known_redteam: byDay.reduce((s, d) => s + d.n_known_redteam, 0),
  first_event_seconds: 0,
  last_event_seconds: 0,
  by_day: byDay,
});

// U1: alerted by m0 on day 1, red-team on day 2 (on C2 only). U2: nothing notable.
const MAP: NetworkMap = {
  provenance: {} as NetworkMap["provenance"],
  split: "test",
  models: ["m0", "m1"],
  start_seconds: 86400,
  end_seconds: 3 * 86400,
  days: [1, 2],
  selection: "",
  semantics: "",
  n_accounts_in_split: 5,
  n_accounts_selected: 2,
  max_accounts: 60,
  max_computers_per_account: 40,
  max_links: 1200,
  computer_order: "",
  accounts: [
    account("U1", [
      { window_id: "w:U1:86400", window_start: 86400, day: 1, known_redteam: false, scores: { m0: ws(true), m1: ws(false) } },
      { window_id: "w:U1:172800", window_start: 172800, day: 2, known_redteam: true, scores: { m0: ws(false), m1: ws(false) } },
    ]),
    account("U2", []),
  ],
  computers: [
    { node_id: "computer:C1", label: "C1", n_accounts_in_split: 3, n_accounts_shown: 2, n_known_redteam: 0 },
    { node_id: "computer:C2", label: "C2", n_accounts_in_split: 1, n_accounts_shown: 1, n_known_redteam: 4 },
    { node_id: "computer:C3", label: "C3", n_accounts_in_split: 1, n_accounts_shown: 1, n_known_redteam: 0 },
  ],
  links: [
    link("U1", "C1", [
      { day: 1, n_events: 5, n_fail: 0, n_known_redteam: 0, alerted: [0] },
      { day: 2, n_events: 3, n_fail: 0, n_known_redteam: 0, alerted: [] },
    ]),
    link("U1", "C2", [{ day: 2, n_events: 4, n_fail: 0, n_known_redteam: 4, alerted: [] }]),
    link("U2", "C1", [{ day: 1, n_events: 7, n_fail: 0, n_known_redteam: 0, alerted: [] }]),
    link("U2", "C3", [{ day: 2, n_events: 1, n_fail: 0, n_known_redteam: 0, alerted: [] }]),
  ],
};

describe("buildView", () => {
  it("shows every mapped account with its links over the full range", () => {
    const v = buildView(MAP, { modelId: "m0", show: "all", from: 1, to: 2 });
    expect(v.accounts.map((a) => a.label)).toEqual(["U1", "U2"]);
    expect(v.computers.map((c) => c.label)).toEqual(["C1", "C2", "C3"]);
    expect(v.links).toHaveLength(4);
    const u1 = v.accounts[0];
    expect([u1.alerts, u1.redteamWindows, u1.events, u1.degree]).toEqual([1, 1, 12, 2]);
    expect(v.computers.find((c) => c.label === "C1")!.degree).toBe(2);
  });

  it("recomputes labels and alerts from the selected days only", () => {
    const day1 = buildView(MAP, { modelId: "m0", show: "all", from: 1, to: 1 });
    expect(day1.links.some((l) => l.knownRedteam > 0)).toBe(false);
    expect(day1.accounts.find((a) => a.label === "U1")!.redteamWindows).toBe(0);
    expect(day1.links.find((l) => l.id === "principal:U1|computer:C1")!.alerted).toBe(true);
    expect(day1.computers.map((c) => c.label)).toEqual(["C1"]);

    const day2 = buildView(MAP, { modelId: "m0", show: "all", from: 2, to: 2 });
    const c1 = day2.links.find((l) => l.id === "principal:U1|computer:C1")!;
    expect([c1.events, c1.alerted]).toEqual([3, false]);
    expect(day2.links.find((l) => l.id === "principal:U1|computer:C2")!.knownRedteam).toBe(4);
  });

  it("alerts follow the selected model", () => {
    const m1 = buildView(MAP, { modelId: "m1", show: "all", from: 1, to: 2 });
    expect(m1.accounts.every((a) => a.alerts === 0)).toBe(true);
    expect(m1.links.every((l) => !l.alerted)).toBe(true);
    expect(buildView(MAP, { modelId: "m1", show: "alerted", from: 1, to: 2 }).accounts).toHaveLength(0);
  });

  it("filters keep only the chosen accounts and their computers", () => {
    const rt = buildView(MAP, { modelId: "m0", show: "redteam", from: 1, to: 2 });
    expect(rt.accounts.map((a) => a.label)).toEqual(["U1"]);
    expect(rt.computers.map((c) => c.label)).toEqual(["C1", "C2"]);
    expect(rt.computers.find((c) => c.label === "C1")!.degree).toBe(1);
    expect(buildView(MAP, { modelId: "m0", show: "redteam", from: 1, to: 1 }).accounts).toHaveLength(0);
  });

  it("search ranks exact and prefix matches first; neighbors are one hop", () => {
    const v = buildView(MAP, { modelId: "m0", show: "all", from: 1, to: 2 });
    expect(searchNodes(v, "c1").map((h) => h.label)).toEqual(["C1"]);
    expect(searchNodes(v, "u").map((h) => h.kind)).toEqual(["account", "account"]);
    expect(searchNodes(v, "  ")).toEqual([]);
    expect([...neighbors(v, "computer:C1")].sort()).toEqual(["computer:C1", "principal:U1", "principal:U2"]);
  });
});

describe("forceLayout", () => {
  const nodes = [
    { id: "a", r: 10, hub: true },
    { id: "b", r: 10, hub: true },
    ...["x", "y", "z", "s"].map((id) => ({ id, r: 4, hub: false })),
  ];
  const links = [
    { source: "a", target: "x" },
    { source: "a", target: "y" },
    { source: "a", target: "s" },
    { source: "b", target: "z" },
    { source: "b", target: "s" },
  ];

  it("is deterministic and places every node at a finite position", () => {
    const one = forceLayout(nodes, links);
    const two = forceLayout(nodes, links);
    expect([...one.pos]).toEqual([...two.pos]);
    for (const p of one.pos.values()) expect(Number.isFinite(p.x) && Number.isFinite(p.y)).toBe(true);
    expect(one.maxX).toBeGreaterThan(one.minX);
  });

  it("keeps nodes apart and places a shared computer between its accounts", () => {
    const { pos } = forceLayout(nodes, links);
    const d = (p: string, q: string) => Math.hypot(pos.get(p)!.x - pos.get(q)!.x, pos.get(p)!.y - pos.get(q)!.y);
    expect(d("a", "b")).toBeGreaterThan(40);
    expect(d("s", "a")).toBeLessThan(d("a", "b"));
    expect(d("s", "b")).toBeLessThan(d("a", "b"));
    expect(d("x", "a")).toBeLessThan(d("x", "b"));
  });

  it("starts from previous positions, ignores links to unknown nodes", () => {
    const first = forceLayout(nodes, links);
    const again = forceLayout(nodes, [...links, { source: "a", target: "missing" }], first.pos);
    for (const [id, p] of first.pos) expect(Math.hypot(p.x - again.pos.get(id)!.x, p.y - again.pos.get(id)!.y)).toBeLessThan(60);
  });
});
