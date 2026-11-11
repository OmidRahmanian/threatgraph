"""Storage for Live Monitoring Mode.

SQLite in WAL mode is the initial backend: one file, no server process, safe for one writer
and many readers, and enough for a single VPS (tens of events per second). Everything else
talks to the `LiveStore` interface, so a different backend (Postgres/Timescale) can replace
it without touching ingestion, detection or the dashboard.

Retention deletes old events, but never an event that is evidence for a stored incident.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from threatgraph.live.events import LiveEvent

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS events (
    rowid INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    ts REAL NOT NULL,
    service TEXT,
    attrs TEXT NOT NULL,
    message TEXT,
    simulated INTEGER NOT NULL DEFAULT 0,
    received_at REAL NOT NULL,
    UNIQUE (source_id, event_id)
);
CREATE INDEX IF NOT EXISTS events_kind_ts ON events (kind, ts);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_received ON events (received_at);

CREATE TABLE IF NOT EXISTS agents (
    source_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'agent',
    created_at REAL NOT NULL,
    last_seen REAL,
    last_heartbeat TEXT,
    disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL UNIQUE,
    dedup_key TEXT NOT NULL,
    detector TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    assessment TEXT NOT NULL,
    status TEXT NOT NULL,
    service TEXT,
    source_id TEXT,
    entity TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    detected_at REAL NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1,
    confidence TEXT NOT NULL,
    limitations TEXT NOT NULL,
    evidence TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    auto_resolve INTEGER NOT NULL DEFAULT 0,
    simulated INTEGER NOT NULL DEFAULT 0,
    notified_severity TEXT,
    last_notified_at REAL,
    acknowledged_at REAL,
    acknowledged_by TEXT,
    resolved_at REAL,
    resolved_by TEXT,
    resolution TEXT,
    verdict TEXT
);
CREATE INDEX IF NOT EXISTS incidents_open ON incidents (dedup_key, status);
CREATE INDEX IF NOT EXISTS incidents_detected ON incidents (detected_at);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id TEXT NOT NULL,
    event_rowid INTEGER NOT NULL,
    PRIMARY KEY (incident_id, event_rowid)
);
CREATE INDEX IF NOT EXISTS incident_events_event ON incident_events (event_rowid);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY,
    incident_id TEXT,
    channel TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL,
    last_error TEXT,
    created_at REAL NOT NULL,
    sent_at REAL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS notifications_due ON notifications (status, next_attempt_at);

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY,
    incident_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    model TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class InsertResult:
    accepted: int
    duplicates: int


def _row(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    for key in ("attrs", "evidence", "last_heartbeat", "result"):
        if key in d and isinstance(d[key], str):
            d[key] = json.loads(d[key])
    for key in ("simulated", "auto_resolve", "disabled"):
        if key in d and d[key] is not None:
            d[key] = bool(d[key])
    return d


class LiveStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        with self._write_lock:
            self.conn().executescript(SCHEMA)  # executescript manages its own transaction
        with self.tx() as c:
            c.execute(
                "INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
            )

    # ------------------------------------------------------------------ connections
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=10000")
            self._local.conn = c
        return c

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        c = self.conn()
        with self._write_lock:
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
            except BaseException:
                c.execute("ROLLBACK")
                raise
            c.execute("COMMIT")

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        return [_row(r) for r in self.conn().execute(sql, tuple(params)).fetchall()]

    def scalar(self, sql: str, params: Iterable[Any] = ()) -> Any:
        r = self.conn().execute(sql, tuple(params)).fetchone()
        return None if r is None else r[0]

    # ------------------------------------------------------------------ agents
    def add_agent(self, source_id: str, role: str = "agent") -> str:
        """Register an agent (or probe) and return its token. Only the hash is stored."""
        token = secrets.token_urlsafe(32)
        with self.tx() as c:
            c.execute(
                "INSERT INTO agents (source_id, token_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (source_id, token_hash(token), role, time.time()),
            )
        return token

    def rotate_agent_token(self, source_id: str) -> str:
        token = secrets.token_urlsafe(32)
        with self.tx() as c:
            n = c.execute(
                "UPDATE agents SET token_hash = ? WHERE source_id = ?",
                (token_hash(token), source_id),
            ).rowcount
        if not n:
            raise KeyError(source_id)
        return token

    def set_agent_disabled(self, source_id: str, disabled: bool) -> None:
        with self.tx() as c:
            c.execute(
                "UPDATE agents SET disabled = ? WHERE source_id = ?", (int(disabled), source_id)
            )

    def agent_for_token(self, token: str) -> dict[str, Any] | None:
        rows = self.query(
            "SELECT source_id, role, disabled FROM agents WHERE token_hash = ?",
            (token_hash(token),),
        )
        if not rows or rows[0]["disabled"]:
            return None
        return rows[0]

    def agents(self) -> list[dict[str, Any]]:
        return self.query(
            "SELECT source_id, role, created_at, last_seen, last_heartbeat, disabled "
            "FROM agents ORDER BY source_id"
        )

    # ------------------------------------------------------------------ events
    def insert_events(self, events: list[LiveEvent], received_at: float) -> InsertResult:
        heartbeat: dict[str, Any] | None = None
        with self.tx() as c:
            before = c.total_changes
            c.executemany(
                "INSERT OR IGNORE INTO events (source_id, event_id, kind, ts, service, attrs, "
                "message, simulated, received_at) VALUES (?,?,?,?,?,?,?,?,?)",
                [
                    (
                        e.source_id,
                        e.event_id,
                        e.kind,
                        e.ts,
                        e.service,
                        json.dumps(e.attrs, separators=(",", ":"), default=str),
                        e.message,
                        int(e.simulated),
                        received_at,
                    )
                    for e in events
                ],
            )
            accepted = c.total_changes - before
            for e in events:
                if e.kind == "agent.heartbeat":
                    heartbeat = {"ts": e.ts, **e.attrs}
            if events:
                c.execute(
                    "UPDATE agents SET last_seen = ?, last_heartbeat = COALESCE(?, last_heartbeat) "
                    "WHERE source_id = ?",
                    (
                        received_at,
                        json.dumps(heartbeat) if heartbeat else None,
                        events[0].source_id,
                    ),
                )
        return InsertResult(accepted=accepted, duplicates=len(events) - accepted)

    def events(
        self,
        *,
        kinds: Iterable[str] | None = None,
        since: float | None = None,
        until: float | None = None,
        source_id: str | None = None,
        simulated: bool | None = False,
        limit: int = 10_000,
        order: str = "ASC",
    ) -> list[dict[str, Any]]:
        where, params = ["1=1"], []
        if kinds:
            kinds = list(kinds)
            where.append(f"kind IN ({','.join('?' * len(kinds))})")
            params += kinds
        if since is not None:
            where.append("ts >= ?")
            params.append(since)
        if until is not None:
            where.append("ts < ?")
            params.append(until)
        if source_id:
            where.append("source_id = ?")
            params.append(source_id)
        if simulated is not None:
            where.append("simulated = ?")
            params.append(int(simulated))
        direction = "DESC" if order.upper() == "DESC" else "ASC"
        return self.query(
            f"SELECT rowid, source_id, event_id, kind, ts, service, attrs, message, simulated "
            f"FROM events WHERE {' AND '.join(where)} ORDER BY ts {direction}, rowid {direction} "
            f"LIMIT ?",
            [*params, limit],
        )

    def events_by_rowid(self, rowids: list[int]) -> list[dict[str, Any]]:
        if not rowids:
            return []
        rows: list[dict[str, Any]] = []
        for i in range(0, len(rowids), 500):
            chunk = rowids[i : i + 500]
            rows += self.query(
                "SELECT rowid, source_id, event_id, kind, ts, service, attrs, message, simulated "
                f"FROM events WHERE rowid IN ({','.join('?' * len(chunk))})",
                chunk,
            )
        return sorted(rows, key=lambda r: (r["ts"], r["rowid"]))

    # ------------------------------------------------------------------ key/value
    def kv_get(self, key: str, default: Any = None) -> Any:
        v = self.scalar("SELECT value FROM kv WHERE key = ?", (key,))
        return default if v is None else json.loads(v)

    def kv_set(self, key: str, value: Any) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO kv VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value)),
            )

    # ------------------------------------------------------------------ retention
    def apply_retention(
        self,
        *,
        now: float,
        event_days: float,
        metrics_days: float,
        incident_days: float,
        notification_days: float,
    ) -> dict[str, int]:
        """Delete expired rows. Events that are evidence for a kept incident are kept."""
        out = {}
        with self.tx() as c:
            out["incidents"] = c.execute(
                "DELETE FROM incidents WHERE status = 'resolved' AND resolved_at < ?",
                (now - incident_days * 86_400,),
            ).rowcount
            c.execute(
                "DELETE FROM incident_events WHERE incident_id NOT IN (SELECT id FROM incidents)"
            )
            c.execute(
                "DELETE FROM investigations WHERE incident_id NOT IN (SELECT id FROM incidents)"
            )
            keep = "rowid NOT IN (SELECT event_rowid FROM incident_events)"
            out["metrics"] = c.execute(
                f"DELETE FROM events WHERE kind IN ('system.metrics', 'agent.heartbeat', "
                f"'probe.http') AND ts < ? AND {keep}",
                (now - metrics_days * 86_400,),
            ).rowcount
            out["events"] = c.execute(
                f"DELETE FROM events WHERE ts < ? AND {keep}", (now - event_days * 86_400,)
            ).rowcount
            out["notifications"] = c.execute(
                "DELETE FROM notifications WHERE created_at < ? AND status != 'pending'",
                (now - notification_days * 86_400,),
            ).rowcount
            out["sessions"] = c.execute(
                "DELETE FROM sessions WHERE expires_at < ?", (now,)
            ).rowcount
        return out

    def backup(self, dest: str | Path) -> None:
        """Consistent online copy (SQLite backup API); safe while services are running."""
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        target = sqlite3.connect(str(dest))
        try:
            self.conn().backup(target)
        finally:
            target.close()
