"""External availability probe. Standard library only.

Run it somewhere *other* than the monitored server (a second VPS, a home machine, or the
GitHub Actions template in deploy/external-probe/): an outage of the whole VPS also takes down
anything running on it, including ThreatGraph itself, so on-host collectors cannot report it.

    python -m threatgraph.live.probe --config probe.toml            # loop
    python -m threatgraph.live.probe --config probe.toml --once     # cron / CI

Each check records status, latency, an optional expected text and the TLS certificate's
remaining days. The probe can:
- **alert directly** (Telegram/SMTP from environment variables) after `consecutive_failures`
  failed checks, and send one recovery message when the site is back. It keeps its own small
  state file, so it alerts once per outage rather than on every check;
- **report** each result to the ThreatGraph ingestion API as a `probe.http` event (with a
  probe-only credential), where the `availability` rule and the dashboard use it. Reports
  that cannot be delivered are kept (bounded) and sent later.
Both are optional and independent.
"""

from __future__ import annotations

import argparse
import gzip
import http.client
import json
import logging
import os
import ssl
import sys
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from threatgraph.live.channels import Channel, DeliveryError, EmailChannel, TelegramChannel
from threatgraph.live.events import ID_RE, LiveEvent, make_event_id

log = logging.getLogger("threatgraph.probe")
MAX_PENDING_REPORTS = 500


@dataclass
class Target:
    name: str
    url: str
    expect_status: list[int] = field(default_factory=lambda: [200])
    expect_text: str | None = None
    timeout_seconds: float = 10.0
    service: str | None = None


@dataclass
class ProbeConfig:
    probe_id: str
    targets: list[Target]
    interval_seconds: float = 60.0
    consecutive_failures: int = 2
    state_file: str = "probe-state.json"
    report_url: str | None = None  # ThreatGraph server, e.g. https://monitor.example.com
    report_token: str = ""
    ca_file: str | None = None
    direct_alerts: bool = True


def load_probe_config(path: Path) -> ProbeConfig:
    raw = tomllib.loads(path.read_text())
    targets = [Target(**t) for t in raw.pop("targets", [])]
    token = os.environ.get("TG_PROBE_TOKEN") or ""
    if not token and raw.get("report_token_file"):
        token = Path(raw["report_token_file"]).read_text().strip()
    raw.pop("report_token_file", None)
    cfg = ProbeConfig(**raw, targets=targets, report_token=token)
    if not ID_RE.match(cfg.probe_id):
        raise ValueError("probe_id: 1-64 characters from [A-Za-z0-9._-]")
    if cfg.report_url and not cfg.report_url.startswith("https://"):
        raise ValueError("report_url must use https://")
    return cfg


def check(t: Target, now: float | None = None) -> dict[str, Any]:
    """One HTTP(S) GET without following redirects. Never raises."""
    u = urlparse(t.url)
    started = time.perf_counter()
    res: dict[str, Any] = {
        "target": t.name,
        "url": t.url,
        "ok": False,
        "status": None,
        "latency_ms": None,
        "error": None,
        "cert_days_left": None,
    }
    conn: http.client.HTTPConnection
    try:
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(
                u.hostname or "",
                u.port or 443,
                timeout=t.timeout_seconds,
                context=ssl.create_default_context(),
            )
        else:
            conn = http.client.HTTPConnection(
                u.hostname or "", u.port or 80, timeout=t.timeout_seconds
            )
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        conn.request(
            "GET", path, headers={"User-Agent": "threatgraph-probe/0.1", "Connection": "close"}
        )
        r = conn.getresponse()
        body = r.read(256_000)
        res["status"] = r.status
        res["latency_ms"] = round(1000 * (time.perf_counter() - started), 1)
        sock = conn.sock
        if isinstance(sock, ssl.SSLSocket):
            cert = sock.getpeercert()
            if cert and cert.get("notAfter"):
                expiry = ssl.cert_time_to_seconds(str(cert["notAfter"]))
                res["cert_days_left"] = round((expiry - (now or time.time())) / 86_400, 2)
        conn.close()
        ok = r.status in t.expect_status
        if ok and t.expect_text and t.expect_text.encode() not in body:
            ok, res["error"] = False, "expected text not found"
        if not ok and res["error"] is None:
            res["error"] = f"unexpected status {r.status}"
        res["ok"] = ok
    except ssl.SSLCertVerificationError as exc:
        res["error"] = f"TLS certificate invalid: {exc.verify_message}"
    except (TimeoutError, OSError, http.client.HTTPException) as exc:
        res["error"] = f"{type(exc).__name__}: {exc}"[:200]
    return res


def _channels() -> list[Channel]:
    out: list[Channel] = []
    env = os.environ
    if env.get("TG_TELEGRAM_BOT_TOKEN") and env.get("TG_TELEGRAM_CHAT_ID"):
        out.append(
            TelegramChannel(
                env["TG_TELEGRAM_BOT_TOKEN"],
                env["TG_TELEGRAM_CHAT_ID"],
                api_base=env.get("TG_TELEGRAM_API_BASE", "https://api.telegram.org"),
            )
        )
    if env.get("TG_SMTP_HOST") and env.get("TG_SMTP_TO"):
        out.append(
            EmailChannel(
                host=env["TG_SMTP_HOST"],
                port=int(env.get("TG_SMTP_PORT", "587")),
                sender=env.get("TG_SMTP_FROM", "threatgraph-probe@localhost"),
                recipients=[a.strip() for a in env["TG_SMTP_TO"].split(",") if a.strip()],
                username=env.get("TG_SMTP_USER"),
                password=env.get("TG_SMTP_PASSWORD"),
                security=env.get("TG_SMTP_SECURITY", "starttls"),
            )
        )
    return out


def _utc(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


class Prober:
    def __init__(
        self,
        cfg: ProbeConfig,
        channels: list[Channel] | None = None,
        checker: Any = check,
        reporter: Any = None,
    ) -> None:
        self.cfg = cfg
        self.channels = _channels() if channels is None else channels
        self.check = checker
        self.reporter = reporter or self._report
        self.path = Path(cfg.state_file)
        self.state: dict[str, Any] = {"targets": {}, "pending_reports": []}
        if self.path.exists():
            try:
                self.state.update(json.loads(self.path.read_text()))
            except ValueError:
                log.warning("probe state unreadable; starting fresh")

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state))
        os.replace(tmp, self.path)

    def _alert(self, subject: str, body: str) -> list[str]:
        sent = []
        for c in self.channels:
            try:
                c.send(subject, body)
                sent.append(c.name)
            except DeliveryError as exc:
                log.error("alert via %s failed: %s", c.name, exc)
        return sent

    def run_once(self, now: float | None = None) -> list[dict[str, Any]]:
        now = time.time() if now is None else now
        results = []
        for t in self.cfg.targets:
            r = self.check(t)
            results.append(r)
            st = self.state["targets"].setdefault(
                t.name, {"failures": 0, "down_since": None, "alerted": False}
            )
            if r["ok"]:
                if st["alerted"] and self.cfg.direct_alerts:
                    dur = now - (st["down_since"] or now)
                    self._alert(
                        f"ThreatGraph AI · Recovered: {t.name}",
                        f"ThreatGraph AI · Recovered\n\nTarget: {t.name} ({t.url})\n"
                        f"Down since: {_utc(st['down_since'] or now)}\nRecovered: {_utc(now)}\n"
                        f"Duration: {int(dur // 60)} min\nChecked from: {self.cfg.probe_id}",
                    )
                st.update(failures=0, down_since=None, alerted=False)
            else:
                st["failures"] += 1
                st["down_since"] = st["down_since"] or now
                if (
                    st["failures"] >= self.cfg.consecutive_failures
                    and not st["alerted"]
                    and self.cfg.direct_alerts
                ):
                    sent = self._alert(
                        f"ThreatGraph AI · HIGH · Website unavailable · {t.name}",
                        "ThreatGraph AI Availability Alert\n\nSeverity: HIGH\n"
                        f"Service: {t.name}\nDetection: Website unavailable\nTime: {_utc(now)}\n\n"
                        f"Evidence:\n- {st['failures']} consecutive failed checks of {t.url}\n"
                        f"- Last error: {r['error']}\n- Checked from: {self.cfg.probe_id} "
                        "(external probe, independent of the monitored server)\n\n"
                        "Assessment:\nThe site did not respond as expected. The cause is not "
                        "known from this check alone.\n\nRecommended action:\nOpen the site "
                        "yourself; check the server, the hosting provider status and DNS.",
                    )
                    st["alerted"] = bool(sent) or not self.channels
            ev = LiveEvent(
                event_id=make_event_id(self.cfg.probe_id, "probe", t.name, round(now, 3)),
                source_id=self.cfg.probe_id,
                kind="probe.http",
                ts=now,
                service=t.service or t.name,
                attrs=r,
            )
            self.state["pending_reports"].append(ev.to_dict())
        self.state["pending_reports"] = self.state["pending_reports"][-MAX_PENDING_REPORTS:]
        if self.cfg.report_url and self.state["pending_reports"]:
            try:
                self.reporter(self.state["pending_reports"])
                self.state["pending_reports"] = []
            except (OSError, urllib.error.URLError, ValueError) as exc:
                log.warning("could not report to ThreatGraph (kept for later): %s", exc)
        elif not self.cfg.report_url:
            self.state["pending_reports"] = []
        self.save()
        return results

    def _report(self, events: list[dict[str, Any]]) -> None:
        assert self.cfg.report_url
        body = gzip.compress(
            json.dumps({"source_id": self.cfg.probe_id, "events": events}).encode()
        )
        req = urllib.request.Request(
            self.cfg.report_url.rstrip("/") + "/ingest/v1/events",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.cfg.report_token}",
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        ctx = ssl.create_default_context(cafile=self.cfg.ca_file)
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            json.loads(r.read() or b"{}")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="threatgraph-probe")
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr
    )
    cfg = load_probe_config(args.config)
    prober = Prober(cfg)
    if not prober.channels and cfg.direct_alerts:
        log.warning(
            "no alert channel configured (TG_TELEGRAM_* or TG_SMTP_*): outages are only reported"
        )
    while True:
        for r in prober.run_once():
            log.info(
                "%s ok=%s status=%s latency=%s error=%s",
                r["target"],
                r["ok"],
                r["status"],
                r["latency_ms"],
                r["error"],
            )
        if args.once:
            return
        time.sleep(cfg.interval_seconds)


if __name__ == "__main__":
    main()
