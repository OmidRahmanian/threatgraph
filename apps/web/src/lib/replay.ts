// Pure helpers for the incident replay (unit-tested in replay.test.ts).

import type { AuthEvent, IncidentWindow } from "./types";

/** Replay time after `step` events (step 0 = before the first event in range). */
export function cursorTime(events: readonly AuthEvent[], step: number, rangeStart: number): number {
  return step <= 0 ? rangeStart : events[Math.min(step, events.length) - 1].event_time_seconds;
}

/**
 * An alert exists only once its window has closed: scores are produced at window end from
 * events before it. At replay time t, a flagged window is visible iff window_end <= t.
 */
export function alertVisible(w: IncidentWindow, modelId: string, t: number): boolean {
  return Boolean(w.scores[modelId]?.flagged) && w.window_end <= t;
}

export function shortModelName(displayName: string): string {
  return displayName.split(" · ")[0];
}

/** Remote hops (src ≠ dst) up to and including `step`, merged per computer pair. */
export function pathSoFar(events: readonly AuthEvent[], step: number) {
  const edges = new Map<string, { source: string; target: string; first: number; n: number; redteam: number; last: boolean }>();
  const seen = events.slice(0, Math.max(0, step));
  seen.forEach((e, i) => {
    if (!e.src_computer || !e.dst_computer || e.src_computer === e.dst_computer) return;
    const key = `${e.src_computer}->${e.dst_computer}`;
    const cur = edges.get(key) ?? { source: e.src_computer, target: e.dst_computer, first: e.event_time_seconds, n: 0, redteam: 0, last: false };
    cur.n += 1;
    if (e.known_redteam) cur.redteam += 1;
    cur.last = i === seen.length - 1;
    edges.set(key, cur);
  });
  for (const v of edges.values()) v.last = false;
  const latest = seen.at(-1);
  if (latest?.src_computer && latest.dst_computer) {
    const k = edges.get(`${latest.src_computer}->${latest.dst_computer}`);
    if (k) k.last = true;
  }
  return [...edges.values()];
}
