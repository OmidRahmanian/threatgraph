import { describe, expect, it } from "vitest";
import { ago, bucketLabel, describeEvent, missingCount, sortIncidents, sum, toRows, utc, type IncidentRow, type LiveEvent } from "./live";

const T = Date.UTC(2026, 10, 11, 17, 40) / 1000;

describe("live helpers", () => {
  it("formats UTC labels", () => {
    expect(bucketLabel(T, "1h")).toBe("17:40");
    expect(bucketLabel(T, "7d")).toBe("11/11 17:40");
    expect(utc(T)).toBe("2026-11-11 17:40:00 UTC");
    expect(utc(null)).toBe("Never");
  });

  it("keeps missing telemetry as null, never zero", () => {
    const rows = toRows([T, T + 60, T + 120], [5, null, 0], "1h");
    expect(rows.map((r) => r.value)).toEqual([5, null, 0]);
    expect(missingCount([1, null, null])).toBe(2);
    expect(sum([null, null])).toBeNull();
    expect(sum([1, null, 2])).toBe(3);
  });

  it("describes relative ages", () => {
    expect(ago(null)).toBe("never");
    expect(ago(30)).toBe("30 s ago");
    expect(ago(600)).toBe("10 min ago");
  });

  it("orders open incidents first, then by severity, then newest", () => {
    const base = { title: "", assessment: "unusual", category: "security", service: null, source_id: null, entity: "", detector: "rule", rule_id: "r", last_seen: 0, occurrences: 1, simulated: false } as const;
    const rows: IncidentRow[] = [
      { ...base, id: "a", severity: "critical", status: "resolved", detected_at: 5 },
      { ...base, id: "b", severity: "low", status: "open", detected_at: 9 },
      { ...base, id: "c", severity: "high", status: "acknowledged", detected_at: 1 },
      { ...base, id: "d", severity: "high", status: "open", detected_at: 3 },
    ];
    expect(sortIncidents(rows).map((r) => r.id)).toEqual(["d", "c", "b", "a"]);
  });

  it("describes events from fields only", () => {
    const e: LiveEvent = {
      rowid: 1, source_id: "web1", event_id: "x", kind: "ssh.auth", ts: T, service: "sshd", message: null, simulated: true,
      attrs: { outcome: "failure", user: "<img src=x onerror=alert(1)>", src_ip: "203.0.113.9", method: "password" },
    };
    // Rendered as React text, so markup in attacker-chosen fields is never interpreted.
    expect(describeEvent(e)).toBe("SSH failure for <img src=x onerror=alert(1)> from 203.0.113.9 (password)");
  });
});
