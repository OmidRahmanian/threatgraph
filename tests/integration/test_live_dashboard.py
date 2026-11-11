"""Private dashboard API: authentication, authorization, CSRF header, data semantics, actions;
and one worker cycle end to end. Uses simulated scenarios only."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatgraph.live import scenarios
from threatgraph.live.config import load_live_config
from threatgraph.live.store import LiveStore
from threatgraph_api.main import create_app as create_public_app
from threatgraph_live.auth import COOKIE, hash_password, verify_password
from threatgraph_live.dashboard import create_dashboard_app
from threatgraph_live.settings import LiveSettings
from threatgraph_live.worker import Worker

PW = "correct horse battery staple"
H = {"X-TG-Request": "1"}


@pytest.fixture
def env(tmp_path: Path):
    db = str(tmp_path / "live.db")
    store = LiveStore(db)
    cfg = load_live_config()
    settings = LiveSettings(
        db_path=db,
        admin_user="omid",
        admin_password_hash=hash_password(PW),
        cookie_secure=False,
        login_attempts_per_15min=3,
    )
    now = time.time()
    store.add_agent("web1")
    store.insert_events(
        scenarios.ssh_bruteforce(now) + scenarios.benign_traffic(now, minutes=20), received_at=now
    )
    Worker(store, cfg, db, channels=[]).cycle(now)
    app = create_dashboard_app(settings, store, cfg)
    with TestClient(app) as client:
        yield store, client


def login(client: TestClient, pw: str = PW, user: str = "omid"):
    return client.post(
        "/live-api/v1/auth/login", json={"username": user, "password": pw}, headers=H
    )


def test_password_hashing() -> None:
    h = hash_password(PW)
    assert h.startswith("scrypt$") and PW not in h
    assert (
        verify_password(PW, h) and not verify_password("wrong", h) and not verify_password(PW, None)
    )
    with pytest.raises(ValueError):
        hash_password("short")


def test_every_route_requires_a_session(env) -> None:
    _, client = env
    for path in ("overview", "incidents", "events", "model", "auth/me", "incidents/TG-000001"):
        assert client.get(f"/live-api/v1/{path}").status_code == 401, path
    for path in ("ack", "resolve", "investigate"):
        assert client.post(
            f"/live-api/v1/incidents/TG-000001/{path}", headers=H, json={}
        ).status_code in (401, 422)
    client.cookies.set(COOKIE, "forged-session-token")
    assert client.get("/live-api/v1/overview").status_code == 401


def test_login_rate_limit_and_cookie_flags(env) -> None:
    _, client = env
    assert (
        client.post(
            "/live-api/v1/auth/login", json={"username": "omid", "password": PW}
        ).status_code
        == 403
    )
    assert login(client, user="root").status_code == 401
    r = login(client)
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/live-api" in cookie
    assert client.get("/live-api/v1/auth/me").json()["username"] == "omid"
    assert r.headers["cache-control"] == "no-store"
    for _ in range(3):
        login(client, pw="nope")
    assert login(client).status_code == 429  # locked out even with the right password


def test_login_disabled_without_password_hash(tmp_path: Path) -> None:
    db = str(tmp_path / "x.db")
    app = create_dashboard_app(
        LiveSettings(db_path=db, admin_password_hash=None), LiveStore(db), load_live_config()
    )
    with TestClient(app) as c:
        assert login(c).status_code == 503


def test_logout_revokes_session(env) -> None:
    _, client = env
    login(client)
    token = client.cookies.get(COOKIE)
    client.post("/live-api/v1/auth/logout")
    client.cookies.set(COOKIE, token)
    assert client.get("/live-api/v1/overview").status_code == 401


def test_overview_separates_simulated_and_marks_missing_data(env) -> None:
    _, client = env
    login(client)
    real = client.get("/live-api/v1/overview?range=1h").json()
    assert real["web"]["total_requests"] == 0 and real["incidents"]["recent"] == []
    # No real agent reported: every bucket is missing data (null), never a fabricated zero.
    assert set(real["web"]["requests"]) == {None} and real["covered_buckets"] == 0
    assert real["agents"][0]["status"] == "never_connected"
    sim = client.get("/live-api/v1/overview?range=1h&simulated=true").json()
    assert (
        sim["web"]["total_requests"] > 0 and sim["auth"]["total_failures"] == 26
    )  # 25 attack + 1 benign typo
    assert sim["auth"]["top_failure_sources"][0]["source"] == scenarios.ATTACKER
    assert all(i["simulated"] for i in sim["incidents"]["recent"])
    assert client.get("/live-api/v1/overview?range=1y").status_code == 422


def test_incident_workflow_requires_header(env) -> None:
    store, client = env
    login(client)
    (inc,) = [
        i
        for i in client.get("/live-api/v1/incidents?simulated=true").json()["incidents"]
        if i["rule_id"] == "ssh_bruteforce"
    ]
    detail = client.get(f"/live-api/v1/incidents/{inc['id']}").json()
    assert len(detail["evidence_events"]) == 25 and detail["incident"]["simulated"] is True
    url = f"/live-api/v1/incidents/{inc['id']}"
    assert client.post(f"{url}/ack").status_code == 403  # no X-TG-Request header
    assert client.post(f"{url}/ack", headers=H).json() == {"changed": True}
    bad = client.post(f"{url}/resolve", headers=H, json={"verdict": "whatever"})
    assert bad.status_code == 422
    ok = client.post(
        f"{url}/resolve", headers=H, json={"verdict": "false_positive", "note": "test"}
    )
    assert ok.json() == {"changed": True}
    row = store.query(
        "SELECT status, verdict, resolved_by FROM incidents WHERE id = ?", (inc["id"],)
    )[0]
    assert row == {"status": "resolved", "verdict": "false_positive", "resolved_by": "omid"}
    assert client.get("/live-api/v1/incidents/TG-999999").status_code == 404
    assert client.get("/live-api/v1/incidents/..%2Fetc").status_code == 404
    inv = client.post(f"{url}/investigate", headers=H).json()
    assert inv["status"] == "disabled"


def test_events_endpoint_bounds(env) -> None:
    _, client = env
    login(client)
    r = client.get("/live-api/v1/events?kinds=ssh.auth&simulated=true&limit=5").json()
    assert len(r["events"]) == 5 and {e["kind"] for e in r["events"]} == {"ssh.auth"}
    assert client.get("/live-api/v1/events?kinds=ssh.auth;drop").status_code == 422
    assert client.get("/live-api/v1/events?limit=100000").status_code == 422


def test_public_research_api_is_unchanged_and_has_no_live_routes() -> None:
    app = create_public_app()
    paths = {getattr(r, "path", "") for r in app.routes}
    assert not any(p.startswith(("/live-api", "/ingest")) for p in paths)
    with TestClient(app) as c:
        assert c.post("/api/v1/summary").status_code == 405


def test_worker_cycle_isolates_failures(tmp_path: Path) -> None:
    db = str(tmp_path / "w.db")
    store = LiveStore(db)
    cfg = load_live_config()

    class Boom:
        name = "telegram"

        def send(self, subject: str, body: str) -> None:
            raise RuntimeError("unexpected channel bug")

    w = Worker(store, cfg, db, channels=[Boom()])  # type: ignore[list-item]
    store.insert_events(scenarios.outage(time.time()), received_at=time.time())
    w.manager.notify_simulated = True
    status = w.cycle()
    assert "notify" in status["errors"] and "detect" in status
    assert store.scalar("SELECT count(*) FROM incidents") == 1  # detection still happened
    assert store.kv_get("worker_status")["errors"]
