// Threshold metrics recomputed in the browser from persisted held-out scores.
// Must match threatgraph.ml.metrics.threshold_counts (scores >= threshold are alerts;
// unlabeled windows are treated as negatives, so precision is a lower bound).

import type { ScoreRow } from "./types";

export interface ThresholdMetrics {
  threshold: number;
  alerts: number;
  knownPositiveAlerts: number;
  unlabeledAlerts: number;
  missedKnownPositives: number;
  unlabeledNotAlerted: number;
  knownPositives: number;
  total: number;
  precisionLowerBound: number | null;
  knownLabelRecall: number | null;
  alertRate: number | null;
  alertsPerDay: number | null;
}

export function thresholdMetrics(rows: readonly ScoreRow[], threshold: number, nDays: number): ThresholdMetrics {
  let tp = 0;
  let fp = 0;
  let positives = 0;
  for (const [, score, label] of rows) {
    const flagged = score >= threshold;
    if (label === 1) {
      positives += 1;
      if (flagged) tp += 1;
    } else if (flagged) {
      fp += 1;
    }
  }
  const alerts = tp + fp;
  const total = rows.length;
  return {
    threshold,
    alerts,
    knownPositiveAlerts: tp,
    unlabeledAlerts: fp,
    missedKnownPositives: positives - tp,
    unlabeledNotAlerted: total - positives - fp,
    knownPositives: positives,
    total,
    precisionLowerBound: alerts ? tp / alerts : null,
    knownLabelRecall: positives ? tp / positives : null,
    alertRate: total ? alerts / total : null,
    alertsPerDay: nDays > 0 ? alerts / nDays : null,
  };
}

/** Distinct scores, descending. Slider position i means "alert on the top i+1 distinct scores". */
export function thresholdLadder(rows: readonly ScoreRow[]): number[] {
  return Array.from(new Set(rows.map((r) => r[1]))).sort((a, b) => b - a);
}

/**
 * Ladder index that alerts exactly the same rows as `target`: the smallest ladder score
 * that is still >= target. Returns 0 when target is above every score (nothing alerts).
 */
export function ladderIndexFor(ladder: readonly number[], target: number): number {
  if (ladder.length === 0 || target > ladder[0]) return 0;
  let lo = 0;
  let hi = ladder.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (ladder[mid] >= target) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

/** Rows ranked by score descending; ties keep table order (matches metrics.ranking). */
export function rankRows(rows: readonly ScoreRow[]): ScoreRow[] {
  return rows
    .map((r, i) => [r, i] as const)
    .sort((a, b) => b[0][1] - a[0][1] || a[1] - b[1])
    .map(([r]) => r);
}

// The slider is non-linear: realistic alert budgets are a small fraction of windows, so a
// linear ladder would squeeze every useful threshold into the first few pixels. Position
// p in [0, SLIDER_STEPS] maps to ladder index round((L-1) * (p/STEPS)^3).
export const SLIDER_STEPS = 1000;

export function sliderToIndex(position: number, ladderLength: number): number {
  if (ladderLength <= 1) return 0;
  const u = Math.min(1, Math.max(0, position / SLIDER_STEPS));
  return Math.round((ladderLength - 1) * u ** 3);
}

export function indexToSlider(index: number, ladderLength: number): number {
  if (ladderLength <= 1) return 0;
  return Math.round(SLIDER_STEPS * Math.cbrt(index / (ladderLength - 1)));
}
