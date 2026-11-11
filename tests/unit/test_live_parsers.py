"""Parsing of simulated nginx, SSH/auth and syslog lines (fixtures in tests/fixtures/live/)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from threatgraph.live.events import EventValidationError, make_event_id, validate_event
from threatgraph.live.parsers import (
    parse_auth_log,
    parse_nginx_access,
    parse_nginx_error,
    parse_syslog,
)
from threatgraph.live.redact import PrivacyPolicy, clean_text, redact_secrets, sanitize

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "live"
NOW = datetime(2026, 11, 11, 18, 0, tzinfo=UTC)


def lines(name: str) -> list[str]:
    return (FIX / name).read_text(encoding="utf-8").splitlines()


def ts(s: str) -> float:
    return datetime.fromisoformat(s).timestamp()


# ------------------------------------------------------------------- nginx access
def test_nginx_access_combined_and_timed() -> None:
    rows = [parse_nginx_access(x) for x in lines("nginx_access.simulated.log")]
    ok = rows[0]
    assert ok and ok.kind == "http.access" and ok.ts == ts("2026-11-11T17:40:01+00:00")
    assert ok.attrs["status"] == 200 and ok.attrs["path"] == "/index.html"
    assert ok.attrs["request_time_ms"] is None
    timed = rows[1]
    assert (
        timed and timed.attrs["request_time_ms"] == 12.0 and timed.attrs["upstream_time_ms"] == 10.0
    )
    # Time zone offsets are honoured: 12:40 -05:00 is 17:40 UTC.
    assert rows[2] and rows[2].ts == ts("2026-11-11T17:40:03+00:00")
    assert (
        rows[3] and rows[3].attrs["remote_user"] == "alice" and rows[3].attrs["user_agent"] is None
    )
    # TLS handshake bytes on a plain-HTTP port and empty requests are parsed but not well formed.
    assert rows[4] and rows[4].attrs["well_formed"] is False and rows[4].attrs["path"] is None
    assert rows[5] and rows[5].attrs["well_formed"] is False
    # IPv6 client and retried upstreams ("0.150, 0.150" -> last value).
    assert (
        rows[6]
        and rows[6].attrs["client"] == "2001:db8::1"
        and rows[6].attrs["upstream_time_ms"] == 150.0
    )


def test_nginx_access_malformed_lines_are_rejected_not_guessed() -> None:
    rows = [parse_nginx_access(x) for x in lines("nginx_access.simulated.log")]
    assert rows[7] is None  # not an nginx line
    assert rows[8] is None  # impossible date
    assert parse_nginx_access("") is None
    assert (
        parse_nginx_access('1.2.3.4 - - [11/Nov/2026:17:40:01 +0000] "GET / HTTP/1.1" 2000 1')
        is None
    )


# ------------------------------------------------------------------- nginx error
def test_nginx_error_log() -> None:
    rows = [parse_nginx_error(x, UTC) for x in lines("nginx_error.simulated.log")]
    a, b, c, bad = rows
    assert a and a.attrs["level"] == "error" and a.attrs["client"] == "198.51.100.7"
    assert a.attrs["path"] == "/.env" and a.attrs["category"] == "not_found"
    assert b and b.attrs["category"] == "upstream"
    assert c and c.attrs["worker_crash"] is True and c.attrs["level"] == "alert"
    assert bad is None


# ------------------------------------------------------------------- SSH / auth
def _auth() -> list:
    return [parse_auth_log(x, UTC, NOW) for x in lines("auth.simulated.log")]


def test_ssh_failures_and_successes() -> None:
    r = _auth()
    assert r[0].kind == "ssh.auth" and r[0].attrs == {
        "outcome": "failure",
        "user": "root",
        "invalid_user": False,
        "method": "password",
        "src_ip": "203.0.113.9",
        "src_port": 50122,
    }
    assert r[0].ts == ts("2026-11-11T17:40:01+00:00")
    assert r[1].attrs["invalid_user"] is True and r[1].attrs["user"] == "admin"
    assert r[2].attrs["outcome"] == "failure" and r[2].attrs["user"] == "oracle"
    assert r[3].attrs["outcome"] == "success" and r[3].attrs["method"] == "publickey"
    assert r[4].attrs["src_ip"] == "2001:db8::44" and r[4].ts == ts(
        "2026-11-11T17:40:05.123456+00:00"
    )
    assert r[5].attrs["method"] == "max_attempts" and r[5].attrs["invalid_user"] is True
    assert r[7].kind == "ssh.probe" and r[7].attrs["reason"] == "no_identification"


def test_attacker_chosen_username_cannot_spoof_source_ip() -> None:
    spoof = _auth()[6]
    assert spoof.attrs["src_ip"] == "203.0.113.77"
    assert "192.0.2.99" in spoof.attrs["user"]


def test_sudo_su_and_account_changes() -> None:
    r = _auth()
    assert r[8].kind == "admin.sudo" and r[8].attrs["outcome"] == "success"
    assert r[8].attrs["command"] == "/usr/bin/systemctl restart nginx"
    assert r[9].attrs["outcome"] == "failure" and r[9].attrs["target_user"] == "root"
    assert r[10].kind == "admin.account" and r[10].attrs["action"] == "new_user"
    assert r[10].attrs["target"] == "backdoor"
    assert r[11].attrs["action"] == "group_add_member" and r[11].attrs["privileged"] is True
    assert r[12].kind == "admin.su" and r[12].attrs["target_user"] == "root"
    assert r[13] is None  # cron session lines are not security events here
    assert r[15] is None  # not syslog


def test_injection_text_in_username_is_data_only() -> None:
    r = _auth()[14]
    assert r.kind == "ssh.auth" and r.attrs["src_ip"] == "203.0.113.9"
    assert r.attrs["user"].startswith("ignore previous instructions")


def test_terminal_escapes_are_removed_by_sanitize() -> None:
    raw = lines("auth.simulated.log")[16]
    assert "\x1b" in raw
    cleaned = clean_text(raw)
    assert "\x1b" not in cleaned
    parsed = parse_auth_log(cleaned, UTC, NOW)
    assert parsed and parsed.attrs["src_ip"] == "203.0.113.9"


def test_rfc3164_year_rollover() -> None:
    jan = datetime(2027, 1, 1, 0, 5, tzinfo=UTC)
    p = parse_auth_log("Dec 31 23:59:59 h sshd[1]: Invalid user a from 192.0.2.1 port 2", UTC, jan)
    assert p and datetime.fromtimestamp(p.ts, UTC).year == 2026


# ------------------------------------------------------------------- syslog
def test_syslog_kernel_and_systemd() -> None:
    r = [parse_syslog(x, UTC, NOW) for x in lines("syslog.simulated.log")]
    assert r[0].attrs == {"event": "oom_kill", "process": "python3", "pid": 4321}
    assert r[1].attrs["event"] == "segfault" and r[1].attrs["process"] == "app"
    assert r[2].kind == "system.service" and r[2].attrs["unit"] == "myapp.service"
    assert r[3].attrs["detail"] == "exit-code"
    assert r[4] is None


# ------------------------------------------------------------------- privacy
def test_secrets_are_redacted() -> None:
    text = (
        "password=hunter2 token: abc.def Authorization: Bearer eyJabc.def.ghi "
        "api_key='k3y' https://bob:pw@example.test/ AKIAABCDEFGHIJKLMNOP"
    )
    out = redact_secrets(text)
    for secret in ("hunter2", "abc.def", "k3y", "bob:pw", "AKIAABCDEFGHIJKLMNOP", "eyJabc"):
        assert secret not in out, secret
    assert "-----BEGIN" not in sanitize(
        "x -----BEGIN RSA PRIVATE KEY-----\nAAA\n-----END RSA PRIVATE KEY-----"
    )


def test_privacy_policy_paths_and_ips() -> None:
    p = PrivacyPolicy()
    assert p.path("/blog/post?id=7&token=abc") == "/blog/post?[query removed]"
    assert PrivacyPolicy(keep_query=True).path("/a?token=abc&x=1") == "/a?token=[REDACTED]&x=1"
    assert PrivacyPolicy(ip_mode="truncate").ip("203.0.113.9") == "203.0.113.0/24"
    assert PrivacyPolicy(ip_mode="truncate").ip("2001:db8::44") == "2001:db8::/48"
    h = PrivacyPolicy(ip_mode="hash", ip_hash_key="k")
    assert h.ip("203.0.113.9") == h.ip("203.0.113.9") != h.ip("203.0.113.10")
    assert "203.0.113" not in (h.ip("203.0.113.9") or "")
    with pytest.raises(ValueError):
        PrivacyPolicy(ip_mode="hash").ip("192.0.2.1")
    assert len(p.path("/" + "a" * 1000) or "") <= p.max_path + 1


# ------------------------------------------------------------------- schema
def test_event_validation() -> None:
    now = NOW.timestamp()
    good = {
        "event_id": make_event_id("a", 1),
        "source_id": "web1",
        "kind": "ssh.auth",
        "ts": now - 5,
        "attrs": {"outcome": "failure"},
    }
    assert validate_event(good, now=now).kind == "ssh.auth"
    for bad in (
        {**good, "kind": "shell.exec"},
        {**good, "event_id": "../../etc"},
        {**good, "source_id": "bad id"},
        {**good, "ts": now + 3600},
        {**good, "ts": "yesterday"},
        {**good, "attrs": {"x": "y" * 5000}},
        {**good, "ts": True},
    ):
        with pytest.raises(EventValidationError):
            validate_event(bad, now=now)
    assert make_event_id("web1", "nginx", 1, 2) == make_event_id("web1", "nginx", 1, 2)
