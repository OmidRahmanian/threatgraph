"""Ingestion API + SQLite store: authentication, source binding, validation, limits, dedup,
retention, and the real agent delivering simulated log lines through the API."""

from __future__ import annotations

import gzip
import json
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from threatgraph.live.agent import Agent, AgentConfig, LogSpec
from threatgraph.live.config import LiveConfig
from threatgraph.live.events import make_event_id
from threatgraph.live.store import LiveStore
from threatgraph_live.ingest import create_ingest_app
from threatgraph_live.settings import LiveSettings

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "live"


def ev(source: str = "web1", i: int = 0, **kw: Any) -> dict[str, Any]:
    return {
        "event_id": make_event_id(source, i),
        "source_id": source,
        "kind": "ssh.auth",
        "ts": time.time() - 10,
        "service": "sshd",
        "attrs": {"outcome": "failure", "src_ip": "203.0.113.9", "user": "root"},
        "simulated": True,
        **kw,
    }


@pytest.fixture
def env(tmp_path: Path):
    store = LiveStore(tmp_path / "live.db")
    cfg = LiveConfig()
    cfg.ingest.max_batch_events = 100
    cfg.ingest.max_events_per_minute_per_agent = 300
    app = create_ingest_app(LiveSettings(db_path=str(tmp_path / "live.db")), store, cfg)
    token = store.add_agent("web1")
    other = store.add_agent("db1")
    probe = store.add_agent("probe-ext", role="probe")
    with TestClient(app) as client:
        yield store, client, {"web1": token, "db1": other, "probe": probe}


def post(client: TestClient, token: str | None, payload: Any, gz: bool = False, **headers: str):
    body = json.dumps(payload).encode()
    h = {"Content-Type": "application/json", **headers}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if gz:
        body = gzip.compress(body)
        h["Content-Encoding"] = "gzip"
    return client.post("/ingest/v1/events", content=body, headers=h)


def test_requires_valid_agent_token(env) -> None:
    store, client, tok = env
    batch = {"source_id": "web1", "events": [ev()]}
    assert post(client, None, batch).status_code == 401
    assert post(client, "wrong-token", batch).status_code == 401
    store.set_agent_disabled("web1", True)
    assert post(client, tok["web1"], batch).status_code == 401
    store.set_agent_disabled("web1", False)
    assert post(client, tok["web1"], batch).status_code == 200


def test_agent_cannot_write_another_hosts_events(env) -> None:
    store, client, tok = env
    assert post(client, tok["db1"], {"source_id": "web1", "events": [ev()]}).status_code == 403
    r = post(client, tok["db1"], {"source_id": "db1", "events": [ev("web1")]}).json()
    assert r["accepted"] == 0 and r["rejected"] == 1
    assert store.scalar("SELECT count(*) FROM events") == 0


def test_probe_credential_is_limited_to_probe_results(env) -> None:
    _, client, tok = env
    probe_ev = ev("probe-ext", 1, kind="probe.http", attrs={"target": "w", "ok": False})
    r = post(
        client, tok["probe"], {"source_id": "probe-ext", "events": [ev("probe-ext"), probe_ev]}
    )
    assert r.json()["accepted"] == 1 and r.json()["rejected"] == 1


def test_duplicate_batches_are_stored_once(env) -> None:
    store, client, tok = env
    batch = {"source_id": "web1", "events": [ev(i=i) for i in range(20)]}
    first = post(client, tok["web1"], batch, gz=True).json()
    again = post(client, tok["web1"], batch, gz=True).json()
    assert first["accepted"] == 20 and again == {**again, "accepted": 0, "duplicates": 20}
    assert store.scalar("SELECT count(*) FROM events") == 20
    assert store.agents()[-1]["last_seen"] is not None or store.agents()[0]["last_seen"]


def test_invalid_events_rejected_with_reasons(env) -> None:
    _, client, tok = env
    bad = [ev(i=1, kind="shell.exec"), ev(i=2, ts=time.time() + 7200), ev(i=3)]
    r = post(client, tok["web1"], {"source_id": "web1", "events": bad}).json()
    assert r["accepted"] == 1 and r["rejected"] == 2 and len(r["rejection_reasons"]) == 2


def test_size_batch_and_rate_limits(env) -> None:
    _, client, tok = env
    too_many = {"source_id": "web1", "events": [ev(i=i) for i in range(101)]}
    assert post(client, tok["web1"], too_many).status_code == 413
    bomb = gzip.compress(b'{"source_id":"web1","events":[' + b" " * 30_000_000 + b"]}")
    r = client.post(
        "/ingest/v1/events",
        content=bomb,
        headers={"Authorization": f"Bearer {tok['web1']}", "Content-Encoding": "gzip"},
    )
    assert r.status_code == 400
    assert post(client, tok["web1"], {"nope": 1}).status_code == 422
    for i in range(3):
        batch = {"source_id": "web1", "events": [ev(i=100 * i + j) for j in range(100)]}
        assert post(client, tok["web1"], batch).status_code == 200
    r = post(client, tok["web1"], {"source_id": "web1", "events": [ev(i=999)]})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1


def test_heartbeat_updates_agent_health(env) -> None:
    store, client, tok = env
    hb = ev(i=5, kind="agent.heartbeat", attrs={"version": "0.1.0", "buffered": 3})
    post(client, tok["web1"], {"source_id": "web1", "events": [hb]})
    (a,) = [x for x in store.agents() if x["source_id"] == "web1"]
    assert a["last_heartbeat"]["buffered"] == 3


def test_retention_keeps_incident_evidence(tmp_path: Path) -> None:
    store = LiveStore(tmp_path / "r.db")
    from threatgraph.live.events import LiveEvent

    old = time.time() - 40 * 86_400
    events = [
        LiveEvent(make_event_id("a", i), "web1", "ssh.auth", old + i, attrs={}) for i in range(3)
    ]
    store.insert_events(events, received_at=old)
    keep = store.events()[0]["rowid"]
    with store.tx() as c:
        c.execute("INSERT INTO incident_events VALUES ('TG-000001', ?)", (keep,))
        c.execute(
            "INSERT INTO incidents (id, seq, dedup_key, detector, rule_id, category, title, "
            "severity, assessment, status, first_seen, last_seen, detected_at, confidence, "
            "limitations, evidence, recommended_action) VALUES ('TG-000001', 1, 'k', 'rule', 'r', "
            "'security', 't', 'low', 'unusual', 'open', 0, 0, 0, 'c', 'l', '[]', 'a')"
        )
    out = store.apply_retention(
        now=time.time(), event_days=30, metrics_days=7, incident_days=365, notification_days=90
    )
    assert out["events"] == 2
    assert [e["rowid"] for e in store.events()] == [keep]


def test_backup_is_a_consistent_copy(tmp_path: Path) -> None:
    store = LiveStore(tmp_path / "b.db")
    store.add_agent("web1")
    store.backup(tmp_path / "backup" / "copy.db")
    assert LiveStore(tmp_path / "backup" / "copy.db").agents()[0]["source_id"] == "web1"


def test_real_agent_delivers_simulated_logs_through_the_api(env, tmp_path: Path) -> None:
    """Agent (real tailer, parser, privacy, batching) → HTTP API → SQLite."""
    store, client, tok = env
    logs = tmp_path / "logs"
    logs.mkdir()
    auth = logs / "auth.log"
    # Rewrite fixture dates to "now" so the server accepts them.
    stamp = time.strftime("%b %e %H:%M:%S", time.gmtime(time.time() - 60))
    lines = [
        stamp + ln[15:]
        for ln in (FIX / "auth.simulated.log").read_text().splitlines()
        if ln[:3] == "Nov"
    ]
    auth.write_text("\n".join(lines) + "\n")

    def transport(events: list[dict[str, Any]]) -> dict[str, Any]:
        r = post(client, tok["web1"], {"source_id": "web1", "events": events}, gz=True)
        assert r.status_code == 200, r.text
        return r.json()

    cfg = AgentConfig(
        source_id="web1",
        server_url="https://ingest.example.test",
        token=tok["web1"],
        state_dir=str(tmp_path / "state"),
        logs=[LogSpec("auth", str(auth), "host")],
        start_at_end=False,
        metrics={"enabled": False},
    )
    agent = Agent(cfg, transport=transport)
    agent.collect()
    while agent.flush(force=True):
        pass
    kinds = {r["kind"] for r in store.events()}
    assert {"ssh.auth", "admin.sudo", "admin.account", "agent.heartbeat"} <= kinds
    assert len(store.events(kinds=["ssh.auth"])) >= 6
