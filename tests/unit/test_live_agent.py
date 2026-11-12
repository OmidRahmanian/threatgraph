"""Collector agent: tailing across rotation, at-least-once delivery with dedup, backpressure,
retries and the periodic collectors. Every log line here is simulated."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from threatgraph.live.agent import (
    Agent,
    AgentConfig,
    Backoff,
    LogSpec,
    SendError,
    Tailer,
    load_config,
    validate_config,
)
from threatgraph.live.collectors import (
    DockerCollector,
    FileIntegrityCollector,
    MetricsCollector,
    SystemdCollector,
)

LINE = '192.0.2.{i} - - [11/Nov/2026:17:40:{s:02d} +0000] "GET /p{i} HTTP/1.1" 200 10 "-" "sim"\n'


def access_lines(start: int, n: int) -> str:
    return "".join(LINE.format(i=i % 250, s=i % 60) for i in range(start, start + n))


class FakeServer:
    """Stores events by id like the real ingestion API (INSERT OR IGNORE)."""

    def __init__(self) -> None:
        self.events: dict[str, dict[str, Any]] = {}
        self.calls = 0
        self.fail_next = 0
        self.store_then_fail = 0  # server stores the batch, but the response is lost

    def __call__(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        self.calls += 1
        if self.fail_next:
            self.fail_next -= 1
            raise SendError("unreachable: simulated outage")
        new = [e for e in events if e["event_id"] not in self.events]
        for e in events:
            self.events.setdefault(e["event_id"], e)
        if self.store_then_fail:
            self.store_then_fail -= 1
            raise SendError("unreachable: response lost (simulated)")
        return {"accepted": len(new), "duplicates": len(events) - len(new), "rejected": 0}

    def kinds(self, kind: str) -> list[dict[str, Any]]:
        return [e for e in self.events.values() if e["kind"] == kind]


class Clock:
    def __init__(self) -> None:
        self.t = 1_000.0

    def __call__(self) -> float:
        return self.t


def make_agent(
    tmp: Path, server: FakeServer, logs: list[LogSpec], **kw: Any
) -> tuple[Agent, Clock]:
    cfg = AgentConfig(
        source_id="web1",
        server_url="https://ingest.example.test",
        token="t",
        state_dir=str(tmp / "state"),
        logs=logs,
        start_at_end=False,
        metrics={"enabled": False},
        heartbeat_interval_seconds=10_000,
        **kw,
    )
    mono = Clock()
    agent = Agent(cfg, transport=server, clock=lambda: 1_794_000_000.0, mono=mono)
    agent.next_heartbeat = float("inf")
    return agent, mono


def drain(agent: Agent, mono: Clock, rounds: int = 50) -> None:
    for _ in range(rounds):
        agent.collect()
        mono.t += 1_000  # past any backoff
        while agent.flush(force=True):
            pass
        if not agent.buffer:
            agent.collect()
            if not agent.buffer:
                return


# ------------------------------------------------------------------- tailer
def test_tailer_waits_for_complete_lines(tmp_path: Path) -> None:
    f = tmp_path / "a.log"
    f.write_text("one\ntw")
    t = Tailer(str(f), None, start_at_end=False)
    assert [x for x, _ in t.read(10)] == ["one"]
    with f.open("a") as fh:
        fh.write("o\n")
    assert [x for x, _ in t.read(10)] == ["two"]


def test_tailer_follows_rename_rotation_without_loss(tmp_path: Path) -> None:
    f = tmp_path / "a.log"
    f.write_text("1\n2\n")
    t = Tailer(str(f), None, start_at_end=False)
    assert [x for x, _ in t.read(1)] == ["1"]
    with f.open("a") as fh:
        fh.write("3\n")
    os.rename(f, tmp_path / "a.log.1")  # logrotate: rename, then create
    f.write_text("4\n")
    assert [x for x, _ in t.read(10)] == ["2", "3", "4"]


def test_tailer_handles_copytruncate(tmp_path: Path) -> None:
    f = tmp_path / "a.log"
    f.write_text("1\n2\n")
    t = Tailer(str(f), None, start_at_end=False)
    assert len(t.read(10)) == 2
    f.write_text("3\n")  # truncated in place and rewritten
    assert [x for x, _ in t.read(10)] == ["3"]


def test_tailer_resumes_from_committed_position_after_rotation_while_stopped(
    tmp_path: Path,
) -> None:
    f = tmp_path / "a.log"
    f.write_text("1\n2\n3\n")
    t = Tailer(str(f), None, start_at_end=False)
    _, pos = t.read(1)[0]
    t.close()
    os.rename(f, tmp_path / "a.log.1")
    f.write_text("4\n")
    t2 = Tailer(str(f), pos, start_at_end=True)
    assert [x for x, _ in t2.read(10)] == ["2", "3", "4"]


def test_start_at_end_skips_history(tmp_path: Path) -> None:
    f = tmp_path / "a.log"
    f.write_text("old\n")
    t = Tailer(str(f), None, start_at_end=True)
    assert t.read(10) == []
    with f.open("a") as fh:
        fh.write("new\n")
    assert [x for x, _ in t.read(10)] == ["new"]


# ------------------------------------------------------------------- delivery
def test_outage_then_reconnect_delivers_every_line_once(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(access_lines(0, 120))
    server = FakeServer()
    server.fail_next = 3
    server.store_then_fail = 1
    agent, mono = make_agent(
        tmp_path, server, [LogSpec("nginx_access", str(log), "site")], batch_max_events=50
    )
    drain(agent, mono)
    assert len(server.kinds("http.access")) == 120
    assert agent.counters["send_failures"] == 4
    assert agent.counters["acked_duplicates"] > 0  # the lost-response batch was re-sent
    assert agent.backoff.failures == 0


def test_restart_resends_unacknowledged_lines_and_server_dedups(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(access_lines(0, 30))
    server = FakeServer()
    spec = [LogSpec("nginx_access", str(log), "site")]
    agent, _ = make_agent(tmp_path, server, spec, batch_max_events=10)
    agent.collect()
    assert agent.flush(force=True)  # 10 acknowledged
    server.store_then_fail = 1
    agent.flush(force=True)  # 10 stored, ack lost: position not committed
    for t in agent.tailers.values():
        t.close()
    # Process restarts: re-reads from the last committed position.
    agent2, mono2 = make_agent(tmp_path, server, spec, batch_max_events=10)
    drain(agent2, mono2)
    assert len(server.kinds("http.access")) == 30
    assert agent2.counters["acked_duplicates"] == 10


def test_unparsed_lines_are_counted_not_shipped_and_positions_advance(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text("garbage\n" + access_lines(0, 2) + "more garbage\n")
    server = FakeServer()
    agent, mono = make_agent(tmp_path, server, [LogSpec("nginx_access", str(log))])
    drain(agent, mono)
    assert len(server.events) == 2
    assert agent.unparsed[str(log)] == 2
    assert agent.state.position(str(log)).offset == log.stat().st_size  # type: ignore[union-attr]
    assert "garbage" not in str(server.events)


def test_backpressure_bounds_memory_and_keeps_lines_in_file(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(access_lines(0, 500))
    server = FakeServer()
    server.fail_next = 10**6  # server down
    agent, mono = make_agent(
        tmp_path,
        server,
        [LogSpec("nginx_access", str(log))],
        batch_max_events=20,
        buffer_max_events=50,
    )
    for _ in range(20):
        agent.collect()
        mono.t += 1_000
        agent.flush(force=True)
    assert len(agent.buffer) == 50  # bounded
    agent._add_samples([agent.heartbeat(0.0)])
    assert agent.counters["dropped_samples"] == 1  # samples drop when full; log lines wait
    server.fail_next = 0
    drain(agent, mono, rounds=200)
    assert len(server.kinds("http.access")) == 500


def test_permanent_rejection_does_not_block_the_queue(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(access_lines(0, 5))
    calls = []

    def reject(events: list[dict[str, Any]]) -> dict[str, Any]:
        calls.append(len(events))
        raise SendError("rejected (403)", permanent=True)

    agent, _ = make_agent(tmp_path, FakeServer(), [LogSpec("nginx_access", str(log))])
    agent.transport = reject
    agent.collect()
    agent.flush(force=True)
    assert not agent.buffer and agent.counters["rejected_by_server"] == 5


def test_backoff_grows_and_honours_retry_after() -> None:
    import random

    b = Backoff(base=1, cap=60, rng=random.Random(0))
    delays = [b.failure(0.0) for _ in range(8)]
    assert delays[0] <= 1 and max(delays) <= 60 and delays[5] > delays[0]
    assert b.failure(0.0, retry_after=45) >= 45
    b.success()
    assert b.ready(0.0)


def test_heartbeat_reports_agent_health(tmp_path: Path) -> None:
    log = tmp_path / "missing.log"
    agent, _ = make_agent(tmp_path, FakeServer(), [LogSpec("auth", str(log))])
    hb = agent.heartbeat(1.0)
    assert hb.kind == "agent.heartbeat"
    assert hb.attrs["logs"][str(log)]["readable"] is False
    assert {"buffered", "dropped_samples", "send_failures"} <= set(hb.attrs)


# ------------------------------------------------------------------- privacy end to end
def test_agent_applies_privacy_before_sending(tmp_path: Path) -> None:
    from threatgraph.live.redact import PrivacyPolicy

    log = tmp_path / "access.log"
    log.write_text(
        '203.0.113.9 - - [11/Nov/2026:17:40:01 +0000] "GET /login?password=hunter2 HTTP/1.1" 200 1 "-" "sim"\n'
    )
    server = FakeServer()
    agent, mono = make_agent(
        tmp_path,
        server,
        [LogSpec("nginx_access", str(log))],
        privacy=PrivacyPolicy(ip_mode="truncate"),
    )
    drain(agent, mono)
    (e,) = server.events.values()
    assert e["attrs"]["client"] == "203.0.113.0/24"
    assert e["attrs"]["path"] == "/login?[query removed]"
    assert "hunter2" not in str(e) and "203.0.113.9" not in str(e)


# ------------------------------------------------------------------- config
def test_config_requires_tls_except_explicit_loopback(tmp_path: Path) -> None:
    base = dict(source_id="web1", token="t", state_dir=str(tmp_path))
    with pytest.raises(ValueError, match="https"):
        validate_config(AgentConfig(server_url="http://203.0.113.1:8443", **base))
    with pytest.raises(ValueError, match="https"):
        validate_config(AgentConfig(server_url="http://127.0.0.1:8443", **base))
    validate_config(
        AgentConfig(server_url="http://127.0.0.1:8443", allow_insecure_http=True, **base)
    )
    validate_config(AgentConfig(server_url="https://10.8.0.1:8443", **base))
    with pytest.raises(ValueError):
        validate_config(AgentConfig(server_url="https://x", **{**base, "source_id": "bad id"}))


def test_load_example_config_and_token_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    example = Path(__file__).resolve().parents[2] / "deploy" / "agent" / "agent.example.toml"
    text = example.read_text().replace("/var/lib/threatgraph-agent", str(tmp_path))
    cfg_path = tmp_path / "agent.toml"
    cfg_path.write_text(text)
    monkeypatch.setenv("TG_AGENT_TOKEN", "from-env")
    cfg = load_config(cfg_path)
    assert cfg.token == "from-env" and cfg.logs and cfg.server_url.startswith("https://")


# ------------------------------------------------------------------- collectors
def test_metrics_from_proc(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "meminfo").write_text(
        "MemTotal: 2000000 kB\nMemAvailable: 500000 kB\nSwapTotal: 0 kB\n"
    )
    (proc / "uptime").write_text("12345.6 100.0\n")
    (proc / "stat").write_text("cpu 100 0 100 800 0 0 0 0 0 0\n")
    m = MetricsCollector("web1", [str(tmp_path)], proc_root=str(proc))
    first = m.collect(1.0)[0].attrs
    assert first["cpu_percent"] is None and first["mem_percent"] == 75.0
    assert first["uptime_seconds"] == 12346 and first["disks"][0]["used_percent"] is not None
    (proc / "stat").write_text("cpu 150 0 150 900 0 0 0 0 0 0\n")
    assert m.collect(2.0)[0].attrs["cpu_percent"] == 50.0


def test_systemd_reports_transitions_only() -> None:
    out = {"v": "nginx.service loaded failed failed A high performance web server\n"}
    c = SystemdCollector("web1", [], runner=lambda: out["v"])
    first = c.collect(1.0)
    assert [(e.attrs["unit"], e.attrs["state"]) for e in first] == [("nginx.service", "failed")]
    assert c.collect(2.0) == []
    out["v"] = ""
    assert [e.attrs["state"] for e in c.collect(3.0)] == ["active"]


def test_systemd_missing_is_reported_not_fatal() -> None:
    def boom() -> str:
        raise FileNotFoundError("systemctl not found")

    c = SystemdCollector("web1", [], runner=boom)
    assert c.collect(1.0) == [] and c.status.ok is False


def test_docker_health_transitions() -> None:
    data = {
        "v": [{"Names": ["/api"], "State": "running", "Status": "Up 1m (healthy)", "Image": "x"}]
    }
    c = DockerCollector("web1", "/nonexistent", fetch=lambda: data["v"])
    assert c.collect(1.0)[0].attrs["health"] == "healthy"
    assert c.collect(2.0) == []
    data["v"] = [
        {"Names": ["/api"], "State": "running", "Status": "Up 2m (unhealthy)", "Image": "x"}
    ]
    assert c.collect(3.0)[0].attrs["health"] == "unhealthy"
    data["v"] = []
    assert c.collect(4.0)[0].attrs["state"] == "removed"


def test_file_integrity_baseline_then_changes(tmp_path: Path) -> None:
    a, d = tmp_path / "sshd_config", tmp_path / "conf.d"
    a.write_text("PermitRootLogin no\n")
    d.mkdir()
    (d / "x.conf").write_text("1")
    c = FileIntegrityCollector("web1", [str(a), str(d)])
    assert c.collect(1.0) == []  # baseline only
    a.write_text("PermitRootLogin yes\n")
    (d / "y.conf").write_text("2")
    (d / "x.conf").unlink()
    changes = {(Path(e.attrs["path"]).name, e.attrs["change"]) for e in c.collect(2.0)}
    assert changes == {("sshd_config", "modified"), ("y.conf", "added"), ("x.conf", "removed")}
    assert c.collect(3.0) == []


def test_agent_and_probe_need_only_the_standard_library() -> None:
    """The agent and probe run on hosts without the scientific stack (pip install --no-deps)."""
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[2]
    code = (
        "import sys, importlib.abc\n"
        "class Block(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        top = name.split('.')[0]\n"
        "        if top in {'numpy','polars','pyarrow','duckdb','sklearn','pydantic','yaml','fastapi','joblib'}:\n"
        "            raise ImportError('third-party import: ' + name)\n"
        "sys.meta_path.insert(0, Block())\n"
        "import threatgraph.live.agent, threatgraph.live.probe\n"
        "print('stdlib-only')\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        env={"PYTHONPATH": str(root / "packages")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.stdout.strip() == "stdlib-only", out.stderr


def test_heartbeat_counts_lines_read_in_the_same_round(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(access_lines(0, 3) + "garbage\n")
    server = FakeServer()
    agent, _ = make_agent(tmp_path, server, [LogSpec("nginx_access", str(log))])
    agent.next_heartbeat = 0.0
    agent.collect()
    agent.flush(force=True)
    (hb,) = server.kinds("agent.heartbeat")
    assert hb["attrs"]["logs"][str(log)]["parsed"] == 3
    assert hb["attrs"]["logs"][str(log)]["unparsed"] == 1
