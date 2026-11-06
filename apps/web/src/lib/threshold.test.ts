import { describe, expect, it } from "vitest";
import { indexToSlider, ladderIndexFor, rankRows, SLIDER_STEPS, sliderToIndex, thresholdLadder, thresholdMetrics } from "./threshold";
import type { ScoreRow } from "./types";

// Same fixture as tests/unit/test_metrics.py so both implementations are checked against
// identical expectations.
const ROWS: ScoreRow[] = [
  ["a", 0.9, 1],
  ["b", 0.8, 0],
  ["c", 0.1, 0],
  ["d", 0.4, 1],
  ["e", 0.4, 0],
  ["f", 0.3, 0],
  ["g", 0.2, 0],
  ["h", 0.0, 0],
];

describe("thresholdMetrics", () => {
  it("matches the Python threshold_counts semantics (inclusive >=)", () => {
    const m = thresholdMetrics(ROWS, 0.4, 2);
    expect(m.alerts).toBe(4);
    expect(m.knownPositiveAlerts).toBe(2);
    expect(m.unlabeledAlerts).toBe(2);
    expect(m.missedKnownPositives).toBe(0);
    expect(m.unlabeledNotAlerted).toBe(4);
    expect(m.precisionLowerBound).toBeCloseTo(0.5);
    expect(m.knownLabelRecall).toBeCloseTo(1);
    expect(m.alertsPerDay).toBeCloseTo(2);
  });

  it("returns null (not zero) for undefined ratios", () => {
    const none = thresholdMetrics(ROWS, 10, 1);
    expect(none.alerts).toBe(0);
    expect(none.precisionLowerBound).toBeNull();
    const noPositives = thresholdMetrics([["x", 1, 0]], 0, 1);
    expect(noPositives.knownLabelRecall).toBeNull();
  });

  it("confusion counts always partition the table", () => {
    for (const t of [-1, 0.15, 0.4, 0.85, 2]) {
      const m = thresholdMetrics(ROWS, t, 1);
      expect(m.knownPositiveAlerts + m.unlabeledAlerts + m.missedKnownPositives + m.unlabeledNotAlerted).toBe(ROWS.length);
    }
  });
});

describe("ladder", () => {
  it("is distinct scores, descending", () => {
    expect(thresholdLadder(ROWS)).toEqual([0.9, 0.8, 0.4, 0.3, 0.2, 0.1, 0.0]);
  });

  it("maps a calibrated threshold to the matching ladder step", () => {
    const ladder = thresholdLadder(ROWS);
    expect(ladderIndexFor(ladder, 0.4)).toBe(2);
    expect(ladderIndexFor(ladder, 0.45)).toBe(1);
    expect(ladderIndexFor(ladder, 5)).toBe(0);
    expect(ladderIndexFor(ladder, -5)).toBe(ladder.length - 1);
    // A threshold between ladder steps alerts the same windows as its mapped step.
    for (const t of [0.05, 0.25, 0.45, 0.85]) {
      const step = ladder[ladderIndexFor(ladder, t)];
      expect(thresholdMetrics(ROWS, t, 1).alerts).toBe(thresholdMetrics(ROWS, step, 1).alerts);
    }
  });
});

describe("rankRows", () => {
  it("breaks ties by table order", () => {
    expect(rankRows(ROWS).map((r) => r[0])).toEqual(["a", "b", "d", "e", "f", "g", "c", "h"]);
  });
});

describe("non-linear slider mapping", () => {
  it("is monotone, covers both ends, and round-trips the ladder position", () => {
    const L = 2778;
    let prev = -1;
    for (let p = 0; p <= SLIDER_STEPS; p++) {
      const i = sliderToIndex(p, L);
      expect(i).toBeGreaterThanOrEqual(prev);
      prev = i;
    }
    expect(sliderToIndex(0, L)).toBe(0);
    expect(sliderToIndex(SLIDER_STEPS, L)).toBe(L - 1);
    for (const idx of [0, 1, 34, 500, L - 1]) {
      const back = sliderToIndex(indexToSlider(idx, L), L);
      expect(Math.abs(back - idx)).toBeLessThanOrEqual(Math.max(1, idx * 0.01));
    }
    // The top 1% of a 2,778-step ladder spans a usable share of the slider.
    expect(indexToSlider(Math.round(L * 0.01), L)).toBeGreaterThan(150);
  });
});
