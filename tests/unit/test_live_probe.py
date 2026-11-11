"""External probe: real HTTP checks against a local server, one alert per outage, recovery,
and buffered reports while the ThreatGraph server is unreachable."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from threatgraph.live.probe import ProbeConfig, Prober, Target, check


class _Site(BaseHTTPRequestHandler):
    status = 200

    def do_GET(self) -> None:
        body = b"<html>hello simulated site</html>"
        self.send_response(type(self).status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a: Any) -> None:
        pass


@pytest.fixture
def site():
    _Site.status = 200
    srv = HTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/"
    srv.shutdown()


class Recorder:
    name = "record"

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send(self, subject: str, body: str) -> None:
        self.sent.append((subject, body))


def test_check_ok_status_text_and_refused(site: str) -> None:
    ok = check(Target("site", site, expect_text="hello"))
    assert ok["ok"] and ok["status"] == 200 and ok["latency_ms"] is not None
    assert check(Target("site", site, expect_text="missing"))["error"] == "expected text not found"
    _Site.status = 503
    assert check(Target("site", site))["error"] == "unexpected status 503"
    down = check(Target("x", "http://127.0.0.1:9/", timeout_seconds=1))
    assert not down["ok"] and "Error" in down["error"]


def test_one_alert_per_outage_then_recovery(site: str, tmp_path: Path) -> None:
    rec = Recorder()
    cfg = ProbeConfig(
        "probe-home",
        [Target("website", site)],
        consecutive_failures=2,
        state_file=str(tmp_path / "state.json"),
    )
    p = Prober(cfg, channels=[rec])
    p.run_once(1000.0)
    _Site.status = 502
    for k in range(5):
        p.run_once(1060.0 + 60 * k)
    assert len(rec.sent) == 1 and "Website unavailable" in rec.sent[0][0]
    assert "independent of the monitored server" in rec.sent[0][1]
    # State survives a restart of the probe process: no second alert for the same outage.
    p2 = Prober(cfg, channels=[rec])
    p2.run_once(1400.0)
    assert len(rec.sent) == 1
    _Site.status = 200
    p2.run_once(1460.0)
    assert len(rec.sent) == 2 and "Recovered" in rec.sent[1][0]
    p2.run_once(1520.0)
    assert len(rec.sent) == 2


def test_reports_are_kept_until_the_server_is_reachable(site: str, tmp_path: Path) -> None:
    got: list[list[dict[str, Any]]] = []
    up = {"v": False}

    def reporter(events: list[dict[str, Any]]) -> None:
        if not up["v"]:
            raise OSError("ThreatGraph unreachable (simulated)")
        got.append(events)

    cfg = ProbeConfig(
        "probe-home",
        [Target("website", site)],
        report_url="https://tg.example.test",
        state_file=str(tmp_path / "s.json"),
    )
    p = Prober(cfg, channels=[], reporter=reporter)
    p.run_once(1000.0)
    p.run_once(1060.0)
    assert len(p.state["pending_reports"]) == 2
    up["v"] = True
    p.run_once(1120.0)
    assert len(got) == 1 and len(got[0]) == 3 and p.state["pending_reports"] == []
    assert {e["kind"] for e in got[0]} == {"probe.http"} and got[0][0]["source_id"] == "probe-home"
