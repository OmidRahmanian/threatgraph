"""Detection → incidents → notifications on simulated scenarios.

All events are simulated (threatgraph.live.scenarios). Telegram and SMTP deliveries go to
local stand-in servers started by these tests; nothing contacts a real recipient. A real
delivery test runs only when TG_NOTIFY_LIVE_TEST=1 and channel credentials are set.
"""

from __future__ import annotations

import json
import os
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

from threatgraph.live import scenarios
from threatgraph.live.config import load_live_config
from threatgraph.live.detect import RuleEngine
from threatgraph.live.events import LiveEvent, make_event_id
from threatgraph.live.incidents import IncidentManager
from threatgraph.live.notify import (
    DeliveryError,
    EmailChannel,
    TelegramChannel,
    channels_from_env,
    deliver_due,
    format_message,
    send_test,
)
from threatgraph.live.store import LiveStore

NOW = 1_794_000_000.0


@pytest.fixture
def env(tmp_path: Path):
    store = LiveStore(tmp_path / "live.db")
    cfg = load_live_config()
    store.add_agent("web1")
    store.add_agent("probe-ext", role="probe")
    engine = RuleEngine(store, cfg)
    mgr = IncidentManager(store, cfg, ["telegram", "email"], notify_simulated=True)
    return store, cfg, engine, mgr


def load(store: LiveStore, events: list[LiveEvent], now: float = NOW) -> None:
    store.insert_events(events, received_at=now)
    with store.tx() as c:  # agents counted as online at `now`
        c.execute("UPDATE agents SET last_seen = ?", (now,))


def run(engine: RuleEngine, mgr: IncidentManager, now: float = NOW) -> dict[str, int]:
    return mgr.apply(engine.run(now), now)


def incidents(store: LiveStore) -> list[dict[str, Any]]:
    return store.query("SELECT * FROM incidents ORDER BY seq")


# ------------------------------------------------------------------- detections
def test_ssh_bruteforce_creates_one_simulated_incident(env) -> None:
    store, _, engine, mgr = env
    load(store, scenarios.ssh_bruteforce(NOW))
    run(engine, mgr)
    by_rule = {i["rule_id"]: i for i in incidents(store)}
    assert {"ssh_bruteforce", "ssh_password_spray"} <= set(by_rule)
    bf = by_rule["ssh_bruteforce"]
    assert bf["severity"] == "medium" and bf["assessment"] == "suspected_malicious"
    assert bf["entity"] == scenarios.ATTACKER and bf["simulated"] is True
    assert bf["id"].startswith("TG-")
    assert "25 failed SSH logins" in bf["evidence"][0]
    linked = mgr.evidence_events(bf["id"])
    assert len(linked) == 25 and all(e["simulated"] for e in linked)


def test_success_after_failures_is_high(env) -> None:
    store, _, engine, mgr = env
    load(store, scenarios.ssh_bruteforce(NOW, success=True))
    run(engine, mgr)
    (hit,) = [i for i in incidents(store) if i["rule_id"] == "ssh_success_after_failures"]
    assert hit["severity"] == "high" and "deploy" in hit["evidence"][1]


def test_recon_and_exposed_sensitive_file(env) -> None:
    store, _, engine, mgr = env
    load(store, scenarios.http_recon(NOW, exposed=True))
    run(engine, mgr)
    (rec,) = [i for i in incidents(store) if i["rule_id"] == "http_recon"]
    assert (
        rec["severity"] == "high" and rec["title"] == "Sensitive-looking path served successfully"
    )
    assert "No compromise is implied" in rec["limitations"]


def test_outage_detected_then_recovered_with_notification(env) -> None:
    store, _, engine, mgr = env
    load(store, scenarios.outage(NOW))
    run(engine, mgr)
    (down,) = incidents(store)
    assert down["rule_id"] == "availability" and down["category"] == "availability"
    assert down["status"] == "open" and down["severity"] == "high"
    # Still down 20 minutes later: escalates to critical, same incident.
    later = NOW + 1200
    load(store, scenarios.outage(later, checks=2), now=later)
    run(engine, mgr, later)
    (still,) = incidents(store)
    assert still["id"] == down["id"] and still["severity"] == "critical"
    # Back up: resolved automatically and a recovery message is queued.
    back = later + 60
    load(store, scenarios.recovery(back), now=back)
    run(engine, mgr, back)
    (rec,) = incidents(store)
    assert rec["status"] == "resolved" and rec["resolved_by"] == "system"
    kinds = [
        n["kind"]
        for n in store.query("SELECT kind FROM notifications WHERE channel='email' ORDER BY id")
    ]
    assert kinds == ["alert", "escalation", "recovery"]


def test_single_failed_check_is_not_an_outage(env) -> None:
    store, _, engine, mgr = env
    load(store, scenarios.outage(NOW, checks=1))
    run(engine, mgr)
    assert incidents(store) == []


def test_benign_traffic_creates_no_incident(env) -> None:
    store, _, engine, mgr = env
    load(store, scenarios.benign_traffic(NOW, minutes=60))
    stats = run(engine, mgr)
    assert incidents(store) == [], [i["title"] for i in incidents(store)]
    assert stats["created"] == 0


def test_real_and_simulated_events_never_combine(env) -> None:
    store, _, engine, mgr = env
    sim = scenarios.ssh_bruteforce(NOW, n=6)
    real = [
        LiveEvent(make_event_id("real", e.event_id), e.source_id, e.kind, e.ts, e.service, e.attrs)
        for e in scenarios.ssh_bruteforce(NOW, n=6)
    ]
    load(store, sim + real)
    run(engine, mgr)
    assert not [i for i in incidents(store) if i["rule_id"] == "ssh_bruteforce"]


def test_host_conditions_disk_service_agent(env) -> None:
    store, _, engine, mgr = env
    ev = [
        LiveEvent(
            make_event_id("d", 1),
            "web1",
            "system.metrics",
            NOW - 30,
            "host",
            {"disks": [{"path": "/", "used_percent": 98.2, "free_gb": 0.5}], "mem_percent": 50},
            simulated=True,
        ),
        LiveEvent(
            make_event_id("s", 1),
            "web1",
            "system.service",
            NOW - 30,
            "systemd",
            {"unit": "myapp.service", "state": "failed", "source": "systemctl"},
            simulated=True,
        ),
    ]
    load(store, ev)
    store.add_agent("db1")
    with store.tx() as c:
        c.execute("UPDATE agents SET last_seen = ? WHERE source_id = 'db1'", (NOW - 3600,))
    run(engine, mgr)
    got = {(i["rule_id"], i["severity"]) for i in incidents(store)}
    assert ("disk_usage", "critical") in got and ("service_failure", "medium") in got
    assert ("agent_offline", "medium") in got
    # The unit recovers and the agent reconnects: both incidents resolve automatically.
    later = NOW + 120
    load(
        store,
        [
            LiveEvent(
                make_event_id("s", 2),
                "web1",
                "system.service",
                later - 5,
                "systemd",
                {"unit": "myapp.service", "state": "active", "source": "systemctl"},
                simulated=True,
            )
        ],
        now=later,
    )
    run(engine, mgr, later)
    status = {i["rule_id"]: i["status"] for i in incidents(store)}
    assert status["service_failure"] == "resolved" and status["agent_offline"] == "resolved"
    assert status["disk_usage"] == "open"


def test_admin_and_integrity_events(env) -> None:
    store, _, engine, mgr = env
    ev = [
        LiveEvent(
            make_event_id("a", 1),
            "web1",
            "admin.account",
            NOW - 60,
            "usermod",
            {
                "action": "group_add_member",
                "target": "backdoor",
                "group": "sudo",
                "privileged": True,
            },
            simulated=True,
        ),
        LiveEvent(
            make_event_id("f", 1),
            "web1",
            "fim.change",
            NOW - 60,
            "fim",
            {"path": "/etc/sudoers", "change": "modified", "sha256_after": "ab"},
            simulated=True,
        ),
    ]
    load(store, ev)
    run(engine, mgr)
    got = {(i["rule_id"], i["severity"]) for i in incidents(store)}
    assert got == {("privileged_account_change", "high"), ("file_integrity", "high")}


# ------------------------------------------------------------------- dedup and cooldown
def test_repeated_detection_runs_do_not_duplicate_or_spam(env) -> None:
    store, cfg, engine, mgr = env
    load(store, scenarios.ssh_bruteforce(NOW))
    for k in range(10):  # ten overlapping detection runs over the same events
        run(engine, mgr, NOW + k * 5)
    assert len([i for i in incidents(store) if i["rule_id"] == "ssh_bruteforce"]) == 1
    sent = store.query("SELECT kind FROM notifications WHERE channel = 'telegram'")
    assert len(sent) == 2  # one alert per incident (brute force + spray), no repeats
    # The attack continues past the cooldown: one reminder, still one incident.
    later = NOW + cfg.notifications.cooldown_seconds + 60
    load(store, scenarios.ssh_bruteforce(later), now=later)
    run(engine, mgr, later)
    bf = [i for i in incidents(store) if i["rule_id"] == "ssh_bruteforce"]
    assert len(bf) == 1 and bf[0]["occurrences"] == 2
    kinds = [
        r["kind"]
        for r in store.query(
            "SELECT kind FROM notifications WHERE channel='telegram' AND incident_id = ?",
            (bf[0]["id"],),
        )
    ]
    assert kinds == ["alert", "reminder"]


def test_resolved_incident_is_not_reopened_by_the_same_events(env) -> None:
    store, _, engine, mgr = env
    load(store, scenarios.ssh_bruteforce(NOW))
    run(engine, mgr)
    bf = next(i for i in incidents(store) if i["rule_id"] == "ssh_bruteforce")
    assert mgr.acknowledge(bf["id"], "analyst")
    assert mgr.resolve(bf["id"], "analyst", "expected_activity", "pen test (simulated)")
    run(engine, mgr, NOW + 30)
    assert len([i for i in incidents(store) if i["rule_id"] == "ssh_bruteforce"]) == 1
    with pytest.raises(ValueError):
        mgr.resolve(bf["id"], "a", "maybe", "")


def test_low_severity_is_dashboard_only(env) -> None:
    store, _, engine, mgr = env
    load(store, scenarios.http_recon(NOW))  # low severity: below min_severity (medium)
    run(engine, mgr)
    (rec,) = incidents(store)
    assert rec["severity"] == "low" and store.scalar("SELECT count(*) FROM notifications") == 0


def test_simulated_notifications_are_suppressed_by_default(env) -> None:
    store, cfg, engine, _ = env
    mgr = IncidentManager(store, cfg, ["telegram"])
    load(store, scenarios.ssh_bruteforce(NOW))
    mgr.apply(engine.run(NOW), NOW)
    assert {r["status"] for r in store.query("SELECT status FROM notifications")} == {"suppressed"}


# ------------------------------------------------------------------- message format
def test_message_format_matches_spec(env) -> None:
    store, cfg, engine, mgr = env
    load(store, scenarios.http_recon(NOW, exposed=True))
    run(engine, mgr)
    inc = incidents(store)[0]
    subject, body = format_message(inc, "alert", cfg)
    for part in (
        "SIMULATED TEST",
        "Severity: HIGH",
        "Service: Production Website",
        "Evidence:",
        "Assessment:",
        "Recommended action:",
        f"Incident ID: {inc['id']}",
        "UTC",
    ):
        assert part in body, part
    assert "HIGH" in subject


# ------------------------------------------------------------------- delivery with local servers
class _TelegramStub(BaseHTTPRequestHandler):
    received: ClassVar[list[dict[str, Any]]] = []
    fail_first = 0

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        cls = type(self)
        if cls.fail_first:
            cls.fail_first -= 1
            self.send_response(502)
            self.end_headers()
            return
        assert self.path == "/botTEST-TOKEN/sendMessage"
        cls.received.append(body)
        out = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a: Any) -> None:
        pass


class _SmtpStub(socketserver.StreamRequestHandler):
    messages: ClassVar[list[str]] = []

    def handle(self) -> None:
        w = self.wfile.write
        w(b"220 stub ESMTP\r\n")
        while line := self.rfile.readline():
            cmd = line.decode().strip().upper()
            if cmd.startswith(("EHLO", "HELO")):
                w(b"250-stub\r\n250 OK\r\n")
            elif cmd.startswith(("MAIL", "RCPT", "RSET", "NOOP")):
                w(b"250 OK\r\n")
            elif cmd == "DATA":
                w(b"354 go\r\n")
                data = []
                while (ln := self.rfile.readline()) not in (b".\r\n", b""):
                    data.append(ln.decode())
                type(self).messages.append("".join(data))
                w(b"250 queued\r\n")
            elif cmd == "QUIT":
                w(b"221 bye\r\n")
                return
            else:
                w(b"502 no\r\n")


@pytest.fixture
def stubs():
    _TelegramStub.received, _TelegramStub.fail_first, _SmtpStub.messages = [], 0, []
    http = HTTPServer(("127.0.0.1", 0), _TelegramStub)
    smtp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _SmtpStub)
    for s in (http, smtp):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    tg = TelegramChannel("TEST-TOKEN", "42", api_base=f"http://127.0.0.1:{http.server_port}")
    mail = EmailChannel(
        "127.0.0.1", smtp.server_address[1], "tg@example.test", ["me@example.test"], security="none"
    )
    yield tg, mail
    http.shutdown()
    smtp.shutdown()


def test_delivery_to_local_telegram_and_smtp(env, stubs) -> None:
    store, cfg, engine, mgr = env
    tg, mail = stubs
    load(store, scenarios.ssh_bruteforce(NOW, success=True))
    run(engine, mgr)
    stats = deliver_due(store, [tg, mail], cfg, NOW)
    n_inc = store.scalar(
        "SELECT count(*) FROM incidents WHERE severity IN ('medium','high','critical')"
    )
    assert stats == {"sent": 2 * n_inc, "retry": 0, "failed": 0}
    assert len(_TelegramStub.received) == n_inc and _TelegramStub.received[0]["chat_id"] == "42"
    assert len(_SmtpStub.messages) == n_inc and "Incident ID: TG-" in _SmtpStub.messages[0]
    assert "SIMULATED TEST" in _TelegramStub.received[0]["text"]


def test_notification_retry_after_delivery_failure(env, stubs) -> None:
    store, cfg, engine, mgr = env
    tg, _ = stubs
    mgr.channels = ["telegram"]
    _TelegramStub.fail_first = 2
    load(store, scenarios.outage(NOW))
    run(engine, mgr)
    assert deliver_due(store, [tg], cfg, NOW) == {"sent": 0, "retry": 1, "failed": 0}
    row = store.query("SELECT * FROM notifications")[0]
    assert row["status"] == "pending" and row["attempts"] == 1 and "502" in row["last_error"]
    assert deliver_due(store, [tg], cfg, NOW + 1)["sent"] == 0  # not due yet (backoff)
    assert deliver_due(store, [tg], cfg, row["next_attempt_at"])["retry"] == 1
    row = store.query("SELECT * FROM notifications")[0]
    assert deliver_due(store, [tg], cfg, row["next_attempt_at"])["sent"] == 1
    row = store.query("SELECT * FROM notifications")[0]
    assert row["status"] == "sent" and row["attempts"] == 3 and row["last_error"] is None


def test_gives_up_after_max_attempts_and_hides_token(env) -> None:
    store, cfg, engine, mgr = env
    mgr.channels = ["telegram"]
    dead = TelegramChannel("SECRET-TOKEN", "1", api_base="http://127.0.0.1:9", timeout=0.5)
    load(store, scenarios.outage(NOW))
    run(engine, mgr)
    t = NOW
    for _ in range(cfg.notifications.max_attempts):
        deliver_due(store, [dead], cfg, t)
        t += cfg.notifications.retry_max_seconds + 1
    row = store.query("SELECT * FROM notifications")[0]
    assert row["status"] == "failed" and row["attempts"] == cfg.notifications.max_attempts
    assert "SECRET-TOKEN" not in (row["last_error"] or "")


def test_unconfigured_channel_is_marked_failed(env) -> None:
    store, cfg, engine, mgr = env
    load(store, scenarios.outage(NOW))
    run(engine, mgr)
    stats = deliver_due(store, [], cfg, NOW)
    assert stats["failed"] == 2
    assert {r["last_error"] for r in store.query("SELECT last_error FROM notifications")} == {
        "channel not configured"
    }


def test_channels_from_env_never_hardcode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for k in list(os.environ):
        if k.startswith(("TG_TELEGRAM", "TG_SMTP")):
            monkeypatch.delenv(k)
    assert channels_from_env() == []
    secret = tmp_path / "bot_token"
    secret.write_text("from-file\n")
    monkeypatch.setenv("TG_TELEGRAM_BOT_TOKEN_FILE", str(secret))
    monkeypatch.setenv("TG_TELEGRAM_CHAT_ID", "7")
    (ch,) = channels_from_env()
    assert isinstance(ch, TelegramChannel) and ch.token == "from-file"


@pytest.mark.skipif(os.environ.get("TG_NOTIFY_LIVE_TEST") != "1", reason="real delivery is opt-in")
def test_real_channels_opt_in() -> None:
    chans = channels_from_env()
    assert chans, "set channel credentials to run the real delivery test"
    assert all(v == "sent" for v in send_test(chans).values())


def test_delivery_error_type() -> None:
    with pytest.raises(DeliveryError):
        TelegramChannel("t", "1", api_base="http://127.0.0.1:9", timeout=0.3).send("s", "b")
