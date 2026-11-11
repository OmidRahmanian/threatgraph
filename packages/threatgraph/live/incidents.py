"""Findings → deduplicated incidents → queued notifications.

- **Deduplication.** A finding's `dedup_key` (rule, host, service, entity) maps to at most one
  open incident. Repeated findings update it (last seen, occurrences, evidence links) instead
  of creating new incidents. A finding whose evidence is no newer than an already *resolved*
  incident does not reopen anything, so resolving an incident while its events are still
  inside the detection window does not create a duplicate.
- **Severity** only moves up automatically (escalation notifies again). It comes from the
  rule's documented criteria, never from a raw anomaly score.
- **Condition incidents** (outages, full disks, offline agents) resolve automatically when the
  condition clears, with a recovery notification if the outage was notified.
- **Notifications** are queued per configured channel for incidents at or above
  `notifications.min_severity`. While an incident stays open, a reminder is sent at most once
  per `cooldown_seconds`, and only when new evidence arrived. Simulated (test-fixture)
  incidents are queued as `suppressed` unless test delivery is explicitly enabled.
- **Status and verdict.** open → acknowledged → resolved. On resolution a person can record a
  verdict (`confirmed_malicious`, `benign`, `false_positive`, `expected_activity`); these
  verified labels are what false-alert rates are measured against.
"""

from __future__ import annotations

import json
import time
from typing import Any

from threatgraph.live.config import LiveConfig, severity_rank
from threatgraph.live.detect import Finding
from threatgraph.live.store import LiveStore

MAX_EVIDENCE_LINKS = 200
VERDICTS = ("confirmed_malicious", "benign", "false_positive", "expected_activity")


class IncidentManager:
    def __init__(
        self,
        store: LiveStore,
        cfg: LiveConfig,
        channels: list[str],
        *,
        notify_simulated: bool = False,
    ) -> None:
        self.store = store
        self.cfg = cfg
        self.channels = channels
        self.notify_simulated = notify_simulated

    # ------------------------------------------------------------------ apply findings
    def apply(self, findings: list[Finding], now: float | None = None) -> dict[str, int]:
        now = time.time() if now is None else now
        stats = {"created": 0, "updated": 0, "escalated": 0, "auto_resolved": 0, "queued": 0}
        active_conditions: set[tuple[str, bool]] = set()
        for f in findings:
            if f.condition:
                active_conditions.add((f.dedup_key, f.simulated))
            stats_key = self._upsert(f, now)
            if stats_key:
                stats[stats_key] += 1
        stats["auto_resolved"] = self._auto_resolve(active_conditions, now)
        stats["queued"] = self.store.scalar(
            "SELECT count(*) FROM notifications WHERE created_at = ?", (now,)
        )
        return stats

    def _open_for(self, key: str, simulated: bool) -> dict[str, Any] | None:
        rows = self.store.query(
            "SELECT * FROM incidents WHERE dedup_key = ? AND simulated = ? "
            "ORDER BY seq DESC LIMIT 1",
            (key, int(simulated)),
        )
        return rows[0] if rows else None

    def _upsert(self, f: Finding, now: float) -> str | None:
        prev = self._open_for(f.dedup_key, f.simulated)
        if prev and prev["status"] == "resolved":
            if f.last_seen <= prev["last_seen"] or (
                prev["resolved_at"] and f.last_seen <= prev["resolved_at"] and not f.condition
            ):
                return None  # already covered by the resolved incident
            prev = None
        with self.store.tx() as c:
            if prev is None:
                seq = (c.execute("SELECT COALESCE(max(seq), 0) FROM incidents").fetchone()[0]) + 1
                inc_id = f"TG-{seq:06d}"
                c.execute(
                    "INSERT INTO incidents (id, seq, dedup_key, detector, rule_id, category, "
                    "title, severity, assessment, status, service, source_id, entity, "
                    "first_seen, last_seen, detected_at, occurrences, confidence, limitations, "
                    "evidence, recommended_action, auto_resolve, simulated) "
                    "VALUES (?,?,?,?,?,?,?,?,?,'open',?,?,?,?,?,?,1,?,?,?,?,?,?)",
                    (
                        inc_id,
                        seq,
                        f.dedup_key,
                        f.detector,
                        f.rule_id,
                        f.category,
                        f.title,
                        f.severity,
                        f.assessment,
                        f.service,
                        f.source_id,
                        f.entity,
                        f.first_seen,
                        f.last_seen,
                        now,
                        f.confidence,
                        f.limitations,
                        json.dumps(f.evidence),
                        f.recommended_action,
                        int(f.condition),
                        int(f.simulated),
                    ),
                )
                self._link(c, inc_id, f.event_rowids)
                if severity_rank(f.severity) >= severity_rank(self.cfg.notifications.min_severity):
                    self._queue(c, inc_id, "alert", now, f.simulated)
                    c.execute(
                        "UPDATE incidents SET notified_severity = ?, last_notified_at = ? "
                        "WHERE id = ?",
                        (f.severity, now, inc_id),
                    )
                return "created"

            inc_id = prev["id"]
            newer = f.last_seen > prev["last_seen"]
            escalate = severity_rank(f.severity) > severity_rank(prev["severity"])
            c.execute(
                "UPDATE incidents SET last_seen = max(last_seen, ?), "
                "occurrences = occurrences + ?, severity = ?, evidence = ?, title = ? "
                "WHERE id = ?",
                (
                    f.last_seen,
                    1 if newer else 0,
                    f.severity if escalate else prev["severity"],
                    json.dumps(f.evidence),
                    f.title if escalate else prev["title"],
                    inc_id,
                ),
            )
            self._link(c, inc_id, f.event_rowids)
            min_rank = severity_rank(self.cfg.notifications.min_severity)
            if escalate and severity_rank(f.severity) >= min_rank:
                self._queue(c, inc_id, "escalation", now, f.simulated)
                c.execute(
                    "UPDATE incidents SET notified_severity = ?, last_notified_at = ? WHERE id = ?",
                    (f.severity, now, inc_id),
                )
                return "escalated"
            cooldown = self.cfg.notifications.cooldown_seconds
            if (
                newer
                and prev["status"] == "open"
                and prev["last_notified_at"] is not None
                and now - prev["last_notified_at"] >= cooldown
            ):
                self._queue(c, inc_id, "reminder", now, f.simulated)
                c.execute("UPDATE incidents SET last_notified_at = ? WHERE id = ?", (now, inc_id))
            return "updated" if newer else None

    def _link(self, c: Any, inc_id: str, rowids: list[int]) -> None:
        have = c.execute(
            "SELECT count(*) FROM incident_events WHERE incident_id = ?", (inc_id,)
        ).fetchone()[0]
        room = max(0, MAX_EVIDENCE_LINKS - have)
        c.executemany(
            "INSERT OR IGNORE INTO incident_events VALUES (?, ?)",
            [(inc_id, r) for r in rowids[:room]],
        )

    def _queue(self, c: Any, inc_id: str, kind: str, now: float, simulated: bool) -> None:
        status = "suppressed" if simulated and not self.notify_simulated else "pending"
        for ch in self.channels:
            c.execute(
                "INSERT INTO notifications (incident_id, channel, kind, status, next_attempt_at, "
                "created_at, subject, body) VALUES (?, ?, ?, ?, ?, ?, '', '')",
                (inc_id, ch, kind, status, now, now),
            )

    def _auto_resolve(self, active: set[tuple[str, bool]], now: float) -> int:
        rows = self.store.query(
            "SELECT id, dedup_key, simulated, notified_severity FROM incidents "
            "WHERE auto_resolve = 1 AND status != 'resolved'"
        )
        n = 0
        for r in rows:
            if (r["dedup_key"], bool(r["simulated"])) in active:
                continue
            with self.store.tx() as c:
                c.execute(
                    "UPDATE incidents SET status = 'resolved', resolved_at = ?, resolved_by = "
                    "'system', resolution = 'Condition cleared (resolved automatically).' "
                    "WHERE id = ?",
                    (now, r["id"]),
                )
                if r["notified_severity"] and self.cfg.notifications.recovery_notifications:
                    self._queue(c, r["id"], "recovery", now, bool(r["simulated"]))
            n += 1
        return n

    # ------------------------------------------------------------------ analyst actions
    def acknowledge(self, inc_id: str, user: str, now: float | None = None) -> bool:
        with self.store.tx() as c:
            return bool(
                c.execute(
                    "UPDATE incidents SET status = 'acknowledged', acknowledged_at = ?, "
                    "acknowledged_by = ? WHERE id = ? AND status = 'open'",
                    (now or time.time(), user, inc_id),
                ).rowcount
            )

    def resolve(
        self, inc_id: str, user: str, verdict: str, note: str, now: float | None = None
    ) -> bool:
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        assessment = "confirmed" if verdict == "confirmed_malicious" else None
        with self.store.tx() as c:
            return bool(
                c.execute(
                    "UPDATE incidents SET status = 'resolved', resolved_at = ?, resolved_by = ?, "
                    "verdict = ?, resolution = ?, assessment = COALESCE(?, assessment) "
                    "WHERE id = ? AND status != 'resolved'",
                    (now or time.time(), user, verdict, note[:2000], assessment, inc_id),
                ).rowcount
            )

    # ------------------------------------------------------------------ reads
    def get(self, inc_id: str) -> dict[str, Any] | None:
        rows = self.store.query("SELECT * FROM incidents WHERE id = ?", (inc_id,))
        return rows[0] if rows else None

    def evidence_events(self, inc_id: str) -> list[dict[str, Any]]:
        ids = [
            r["event_rowid"]
            for r in self.store.query(
                "SELECT event_rowid FROM incident_events WHERE incident_id = ?", (inc_id,)
            )
        ]
        return self.store.events_by_rowid(ids)
