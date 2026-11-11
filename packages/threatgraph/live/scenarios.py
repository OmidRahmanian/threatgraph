"""Simulated event scenarios for tests and local demonstrations.

Every event produced here has `simulated=True`, uses RFC 5737 documentation addresses
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) that are never routed on the internet, and is
written straight to a local store: nothing is sent to, or attacks, any real system. The
dashboard labels simulated incidents, and their notifications are suppressed unless test
delivery is explicitly enabled.
"""

from __future__ import annotations

import random
from collections.abc import Callable

from threatgraph.live.events import LiveEvent, make_event_id

ATTACKER = "203.0.113.66"
SCANNER = "198.51.100.23"


def _ev(
    kind: str,
    ts: float,
    attrs: dict,
    source: str = "web1",
    service: str | None = None,
    msg: str | None = None,
) -> LiveEvent:
    return LiveEvent(
        event_id=make_event_id("simulated", kind, source, ts, sorted(attrs.items())),
        source_id=source,
        kind=kind,
        ts=ts,
        service=service,
        attrs=attrs,
        message=msg,
        simulated=True,
    )


def ssh_bruteforce(now: float, n: int = 25, success: bool = False) -> list[LiveEvent]:
    users = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "deploy"]
    out = [
        _ev(
            "ssh.auth",
            now - 240 + i * (200 / n),
            {
                "outcome": "failure",
                "user": users[i % len(users)],
                "invalid_user": users[i % len(users)] not in ("root", "deploy"),
                "method": "password",
                "src_ip": ATTACKER,
                "src_port": 40000 + i,
            },
            service="sshd",
        )
        for i in range(n)
    ]
    if success:
        out.append(
            _ev(
                "ssh.auth",
                now - 20,
                {
                    "outcome": "success",
                    "user": "deploy",
                    "invalid_user": False,
                    "method": "password",
                    "src_ip": ATTACKER,
                    "src_port": 41000,
                },
                service="sshd",
            )
        )
    return out


def http_recon(now: float, exposed: bool = False) -> list[LiveEvent]:
    paths = [
        "/.env",
        "/.git/config",
        "/wp-login.php",
        "/phpmyadmin/",
        "/xmlrpc.php",
        "/.aws/credentials",
    ]
    paths += [f"/old/backup{i}.php" for i in range(30)]
    out = []
    for i, p in enumerate(paths):
        status = 200 if exposed and p == "/.env" else 404
        out.append(
            _ev(
                "http.access",
                now - 200 + i * 4,
                {
                    "client": SCANNER,
                    "method": "GET",
                    "path": p,
                    "status": status,
                    "bytes": 153,
                    "user_agent": "scanner (simulated)",
                    "well_formed": True,
                },
                service="website",
            )
        )
    return out


def outage(
    now: float, target: str = "website", checks: int = 4, interval: float = 60
) -> list[LiveEvent]:
    return [
        _ev(
            "probe.http",
            now - (checks - 1 - i) * interval,
            {
                "target": target,
                "url": "https://site.example.test/",
                "ok": False,
                "status": None,
                "latency_ms": None,
                "error": "connection refused (simulated)",
            },
            source="probe-ext",
            service="website",
        )
        for i in range(checks)
    ]


def recovery(now: float, target: str = "website") -> list[LiveEvent]:
    return [
        _ev(
            "probe.http",
            now,
            {
                "target": target,
                "url": "https://site.example.test/",
                "ok": True,
                "status": 200,
                "latency_ms": 85.0,
                "cert_days_left": 60.0,
            },
            source="probe-ext",
            service="website",
        )
    ]


def benign_traffic(now: float, minutes: int = 30, seed: int = 7) -> list[LiveEvent]:
    """Ordinary activity: steady page views, an occasional 404, key-based admin logins,
    healthy probes and resource samples. Expected to create no incident."""
    rng = random.Random(seed)
    clients = [f"192.0.2.{i}" for i in range(10, 40)]
    pages = [
        "/",
        "/about",
        "/blog/",
        "/blog/post-1",
        "/blog/post-2",
        "/contact",
        "/static/app.css",
        "/static/app.js",
    ]
    out = []
    t = now - minutes * 60
    while t < now:
        c = rng.choice(clients)
        path = rng.choice(pages) if rng.random() > 0.02 else "/favicon.ico"
        status = 404 if path == "/favicon.ico" else 200
        out.append(
            _ev(
                "http.access",
                t,
                {
                    "client": c,
                    "method": "GET",
                    "path": path,
                    "status": status,
                    "bytes": 2048,
                    "user_agent": "browser (simulated)",
                    "well_formed": True,
                    "request_time_ms": round(rng.uniform(5, 60), 1),
                },
                service="website",
            )
        )
        t += rng.uniform(1, 6)
    for i in range(3):
        out.append(
            _ev(
                "ssh.auth",
                now - 600 * (i + 1),
                {
                    "outcome": "success",
                    "user": "deploy",
                    "invalid_user": False,
                    "method": "publickey",
                    "src_ip": "192.0.2.44",
                    "src_port": 50000 + i,
                },
                service="sshd",
            )
        )
    out.append(
        _ev(
            "ssh.auth",
            now - 900,
            {
                "outcome": "failure",
                "user": "deploy",
                "invalid_user": False,
                "method": "publickey",
                "src_ip": "192.0.2.44",
                "src_port": 50010,
            },
            service="sshd",
        )
    )
    out.append(
        _ev(
            "admin.sudo",
            now - 500,
            {
                "user": "deploy",
                "target_user": "root",
                "outcome": "success",
                "tty": "pts/0",
                "command": "/usr/bin/systemctl reload nginx",
            },
            service="sudo",
        )
    )
    for i in range(minutes):
        ts = now - (minutes - i) * 60
        out.append(
            _ev(
                "system.metrics",
                ts,
                {
                    "cpu_percent": round(rng.uniform(3, 25), 1),
                    "mem_percent": round(rng.uniform(40, 60), 1),
                    "disks": [
                        {"path": "/", "used_percent": 41.0, "free_gb": 30.0, "total_gb": 50.0}
                    ],
                    "uptime_seconds": 86400 + ts % 1000,
                },
                service="host",
            )
        )
        out.append(
            _ev(
                "probe.http",
                ts,
                {
                    "target": "website",
                    "url": "https://site.example.test/",
                    "ok": True,
                    "status": 200,
                    "latency_ms": round(rng.uniform(40, 120), 1),
                    "cert_days_left": 60.0,
                },
                source="probe-ext",
                service="website",
            )
        )
    return out


SCENARIOS: dict[str, Callable[[float], list[LiveEvent]]] = {
    "benign": benign_traffic,
    "ssh_bruteforce": ssh_bruteforce,
    "ssh_bruteforce_success": lambda now: ssh_bruteforce(now, success=True),
    "http_recon": http_recon,
    "http_recon_exposed": lambda now: http_recon(now, exposed=True),
    "outage": outage,
    "recovery": recovery,
}
