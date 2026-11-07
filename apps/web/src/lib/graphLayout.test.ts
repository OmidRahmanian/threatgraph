import { describe, expect, it } from "vitest";
import { edgeKey, layoutGraph } from "./graphLayout";

describe("layoutGraph", () => {
  it("lays a hop chain out left to right in time order", () => {
    const l = layoutGraph(["A", "B", "C"], [
      { source: "B", target: "C", first: 20 },
      { source: "A", target: "B", first: 10 },
    ]);
    expect([l.nodes.get("A")!.layer, l.nodes.get("B")!.layer, l.nodes.get("C")!.layer]).toEqual([0, 1, 2]);
    expect(l.nodes.get("A")!.x).toBeLessThan(l.nodes.get("C")!.x);
  });

  it("keeps direction: a reversed edge is not the same edge", () => {
    const l = layoutGraph(["A", "B"], [{ source: "B", target: "A", first: 1 }]);
    expect(l.nodes.get("B")!.layer).toBe(0);
    expect(l.nodes.get("A")!.layer).toBe(1);
  });

  it("marks the later edge of a cycle as a back edge instead of looping", () => {
    const l = layoutGraph(["A", "B"], [
      { source: "A", target: "B", first: 1 },
      { source: "B", target: "A", first: 2 },
    ]);
    expect(l.backEdges).toEqual(new Set([edgeKey("B", "A")]));
    expect(l.nodes.get("A")!.layer).toBe(0);
  });

  it("places isolated and self-loop-only nodes, and is deterministic", () => {
    const edges = [
      { source: "X", target: "X", first: 5 },
      { source: "A", target: "B", first: 1 },
      { source: "A", target: "C", first: 1 },
    ];
    const a = layoutGraph(["A", "B", "C", "X"], edges);
    const b = layoutGraph(["A", "B", "C", "X"], [...edges].reverse());
    expect(a.nodes.get("X")!.layer).toBe(0);
    expect([...a.nodes.values()]).toEqual([...b.nodes.values()]);
    expect(new Set([...a.nodes.values()].map((n) => `${n.x},${n.y}`)).size).toBe(4);
  });
});
