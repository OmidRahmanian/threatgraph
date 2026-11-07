import { describe, expect, it } from "vitest";
import { alertVisible, cursorTime, pathSoFar, shortModelName } from "./replay";
import type { AuthEvent, IncidentWindow } from "./types";

const ev = (id: number, t: number, src: string, dst: string, known = false): AuthEvent => ({
  event_id: id,
  event_time_seconds: t,
  day: 0,
  src_principal: "U1",
  dst_principal: "U1",
  src_computer: src,
  dst_computer: dst,
  auth_type: "NTLM",
  logon_type: "Network",
  auth_orientation: "LogOn",
  outcome: "Success",
  known_redteam: known,
  used_in_features: true,
});

const win = (start: number, flagged: boolean): IncidentWindow => ({
  window_id: `w:U1:${start}`,
  window_start: start,
  window_end: start + 3600,
  split: "test",
  label: "known_redteam",
  n_labeled_events: 1,
  scores: { m1: { score: 1, threshold: 0.5, flagged } },
});

describe("replay", () => {
  it("places the cursor at the latest replayed event", () => {
    const events = [ev(1, 100, "A", "B"), ev(2, 200, "B", "C")];
    expect(cursorTime(events, 0, 0)).toBe(0);
    expect(cursorTime(events, 1, 0)).toBe(100);
    expect(cursorTime(events, 9, 0)).toBe(200);
  });

  it("shows an alert only after its window closes", () => {
    expect(alertVisible(win(0, true), "m1", 3599)).toBe(false);
    expect(alertVisible(win(0, true), "m1", 3600)).toBe(true);
    expect(alertVisible(win(0, false), "m1", 99_999)).toBe(false);
    expect(alertVisible(win(0, true), "unknown", 99_999)).toBe(false);
  });

  it("builds the path so far from remote hops only, marking the latest", () => {
    const events = [ev(1, 1, "A", "A"), ev(2, 2, "A", "B", true), ev(3, 3, "B", "C"), ev(4, 4, "A", "B")];
    expect(pathSoFar(events, 1)).toEqual([]);
    const two = pathSoFar(events, 3);
    expect(two.map((e) => `${e.source}${e.target}`)).toEqual(["AB", "BC"]);
    expect(two.find((e) => e.target === "C")!.last).toBe(true);
    const all = pathSoFar(events, 4);
    const ab = all.find((e) => e.target === "B")!;
    expect([ab.n, ab.redteam, ab.last]).toEqual([2, 1, true]);
  });

  it("shortens model names", () => {
    expect(shortModelName("M1 · Isolation Forest")).toBe("M1");
  });
});
