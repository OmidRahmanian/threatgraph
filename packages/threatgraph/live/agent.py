"""ThreatGraph collector agent. Standard library only; runs as an unprivileged user.

    python -m threatgraph.live.agent --config /etc/threatgraph-agent/agent.toml
    python -m threatgraph.live.agent --config agent.toml --dry-run --once   # print, send nothing

Design (docs/live/collector.md):
- **Tailing with rotation.** Each log is followed by (device, inode, byte offset). When the
  file is renamed by logrotate, the old file is drained to its end before the new one is
  opened; truncation (copytruncate) restarts at offset 0. Partial last lines wait for their
  newline.
- **At-least-once, deduplicated.** A log position is committed to the state file only after
  the server acknowledged the batch that contained it. After a crash or a network outage the
  agent re-reads from the last committed position; event ids are derived from (file identity,
  offset, line hash), so the server stores each line once.
- **Bounded memory and backpressure.** The send buffer holds at most `buffer_max_events`.
  When it is full, log tailers stop reading (lines stay safely in the log file) and periodic
  samples are dropped and counted in the heartbeat. The server can push back with 429/503.
- **Retry with exponential backoff and jitter**, honouring `Retry-After`.
- **Privacy first.** Lines are cleaned and redacted on the host (see `redact.py`); unparsed
  lines are counted, never shipped.
- **TLS.** `https://` is required unless the server is on loopback and
  `allow_insecure_http = true`. A private CA file can be configured for a private network.
"""

from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import logging
import os
import random
import signal
import ssl
import sys
import time
import tomllib
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import tzinfo
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from threatgraph.live.collectors import (
    DockerCollector,
    FileIntegrityCollector,
    MetricsCollector,
    SystemdCollector,
)
from threatgraph.live.events import ID_RE, LiveEvent, make_event_id
from threatgraph.live.parsers import (
    Parsed,
    parse_auth_log,
    parse_nginx_access,
    parse_nginx_error,
    parse_syslog,
)
from threatgraph.live.redact import PrivacyPolicy, clean_text

AGENT_VERSION = "0.1.0"
log = logging.getLogger("threatgraph.agent")
LOG_TYPES = ("nginx_access", "nginx_error", "auth", "syslog")
MAX_LINE = 16_384


# =========================================================================== config
@dataclass
class LogSpec:
    type: str
    path: str
    service: str | None = None


@dataclass
class AgentConfig:
    source_id: str
    server_url: str
    token: str = ""
    ca_file: str | None = None
    state_dir: str = "/var/lib/threatgraph-agent"
    log_timezone: str = "UTC"
    batch_max_events: int = 500
    flush_interval_seconds: float = 5.0
    buffer_max_events: int = 20_000
    http_timeout_seconds: float = 10.0
    allow_insecure_http: bool = False
    heartbeat_interval_seconds: float = 60.0
    start_at_end: bool = True
    privacy: PrivacyPolicy = field(default_factory=PrivacyPolicy)
    logs: list[LogSpec] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=lambda: {"enabled": True})
    systemd: dict[str, Any] = field(default_factory=lambda: {"enabled": False})
    docker: dict[str, Any] = field(default_factory=lambda: {"enabled": False})
    fim: dict[str, Any] = field(default_factory=lambda: {"enabled": False})

    @property
    def tz(self) -> tzinfo:
        return ZoneInfo(self.log_timezone)


def _secret(value: str | None, file: str | None, env: str) -> str:
    if os.environ.get(env):
        return os.environ[env].strip()
    if file:
        return Path(file).read_text().strip()
    return (value or "").strip()


def load_config(path: Path) -> AgentConfig:
    raw = tomllib.loads(path.read_text())
    priv = raw.pop("privacy", {})
    privacy = PrivacyPolicy(
        ip_mode=priv.get("ip_mode", "keep"),
        ip_hash_key=_secret(
            priv.get("ip_hash_key"), priv.get("ip_hash_key_file"), "TG_AGENT_IP_HASH_KEY"
        ),
        keep_query=bool(priv.get("keep_query", False)),
    )
    logs = [LogSpec(**spec) for spec in raw.pop("logs", [])]
    token = _secret(raw.pop("token", None), raw.pop("token_file", None), "TG_AGENT_TOKEN")
    cfg = AgentConfig(**raw, token=token, privacy=privacy, logs=logs)
    validate_config(cfg)
    return cfg


def validate_config(cfg: AgentConfig) -> None:
    if not ID_RE.match(cfg.source_id):
        raise ValueError("source_id: 1-64 characters from [A-Za-z0-9._-]")
    for spec in cfg.logs:
        if spec.type not in LOG_TYPES:
            raise ValueError(f"log type {spec.type!r} not in {LOG_TYPES}")
    url = urlparse(cfg.server_url)
    if url.scheme == "http":
        host = url.hostname or ""
        try:
            loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not (loopback and cfg.allow_insecure_http):
            raise ValueError(
                "server_url must use https:// (plain http is accepted only for a loopback "
                "server with allow_insecure_http = true)"
            )
    elif url.scheme != "https":
        raise ValueError("server_url must be an https:// URL")
    if cfg.buffer_max_events < cfg.batch_max_events:
        raise ValueError("buffer_max_events must be >= batch_max_events")
    ZoneInfo(cfg.log_timezone)


# =========================================================================== tailing
@dataclass
class Position:
    dev: int
    ino: int
    offset: int


class Tailer:
    """Follows one log file across rotation and truncation; yields complete lines with the
    byte position just after each line, so positions can be committed after acknowledgment."""

    def __init__(self, path: str, committed: Position | None, start_at_end: bool) -> None:
        self.path = path
        self.fh: Any = None
        self.ident: tuple[int, int] | None = None
        self.offset = 0
        self.partial = b""
        self.draining: list[tuple[Any, tuple[int, int], int]] = []
        self._open(committed, start_at_end)

    def _stat(self, p: str) -> os.stat_result | None:
        try:
            return os.stat(p)
        except OSError:
            return None

    def _open(self, committed: Position | None, start_at_end: bool) -> None:
        st = self._stat(self.path)
        if st is None:
            return
        ident = (st.st_dev, st.st_ino)
        if committed and (committed.dev, committed.ino) != ident:
            # Rotated while we were stopped: finish the old file if logrotate kept it as .1.
            rotated = self._stat(self.path + ".1")
            if rotated and (rotated.st_dev, rotated.st_ino) == (committed.dev, committed.ino):
                fh = open(self.path + ".1", "rb")  # noqa: SIM115 - kept open while draining
                fh.seek(min(committed.offset, rotated.st_size))
                self.draining.append((fh, (committed.dev, committed.ino), fh.tell()))
        self.fh = open(self.path, "rb")  # noqa: SIM115 - long-lived handle
        self.ident = ident
        if committed and (committed.dev, committed.ino) == ident:
            self.offset = committed.offset if committed.offset <= st.st_size else 0
        elif committed:
            self.offset = 0  # a file created after our last position: all of it is unseen
        else:
            self.offset = st.st_size if start_at_end else 0
        self.fh.seek(self.offset)

    def _check_rotation(self) -> None:
        st = self._stat(self.path)
        if self.fh is None:
            if st is not None:
                self._open(None, start_at_end=False)  # a log that appears later is read whole
            return
        if st is None:
            return  # renamed and not yet recreated: keep reading the open handle
        if (st.st_dev, st.st_ino) != self.ident:
            assert self.ident is not None
            self.draining.append((self.fh, self.ident, self.offset))
            self.fh, self.ident, self.offset = open(self.path, "rb"), (st.st_dev, st.st_ino), 0  # noqa: SIM115
            self.partial = b""
        elif st.st_size < self.offset:  # copytruncate
            self.fh.seek(0)
            self.offset, self.partial = 0, b""

    def _read_from(
        self, fh: Any, offset: int, limit: int, final: bool
    ) -> tuple[list[tuple[str, Position]], int, bool]:
        """Read up to `limit` complete lines. Returns (lines, new_offset, reached_eof)."""
        out: list[tuple[str, Position]] = []
        st = os.fstat(fh.fileno())
        while len(out) < limit:
            raw = fh.readline(MAX_LINE)
            if not raw:
                return out, offset, True
            if not raw.endswith(b"\n") and len(raw) < MAX_LINE:
                if final:  # rotated file: a last line without newline is still complete
                    offset += len(raw)
                    out.append(
                        (raw.decode("utf-8", "replace"), Position(st.st_dev, st.st_ino, offset))
                    )
                    return out, offset, True
                fh.seek(offset)  # wait for the rest of the line
                return out, offset, True
            offset += len(raw)
            out.append(
                (
                    raw.rstrip(b"\r\n").decode("utf-8", "replace"),
                    Position(st.st_dev, st.st_ino, offset),
                )
            )
        return out, offset, False

    def read(self, limit: int) -> list[tuple[str, Position]]:
        lines: list[tuple[str, Position]] = []
        self._check_rotation()  # first, so a just-rotated file is drained before the new one
        while self.draining and len(lines) < limit:
            fh, ident, off = self.draining[0]
            got, off, eof = self._read_from(fh, off, limit - len(lines), final=True)
            lines.extend(got)
            if eof:
                fh.close()
                self.draining.pop(0)
            else:
                self.draining[0] = (fh, ident, off)
        if len(lines) >= limit or self.draining:
            return lines
        if self.fh is not None:
            got, self.offset, _ = self._read_from(
                self.fh, self.offset, limit - len(lines), final=False
            )
            lines.extend(got)
        return lines

    def close(self) -> None:
        for fh, *_ in self.draining:
            fh.close()
        if self.fh:
            self.fh.close()


# =========================================================================== state
class StateStore:
    """Committed log positions and the integrity baseline, written atomically."""

    def __init__(self, directory: Path) -> None:
        self.path = directory / "state.json"
        directory.mkdir(parents=True, exist_ok=True)
        self.data: dict[str, Any] = {"positions": {}, "fim_baseline": None}
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text()))
            except (OSError, ValueError):
                log.warning("state file unreadable; starting fresh")

    def position(self, path: str) -> Position | None:
        p = self.data["positions"].get(path)
        return Position(**p) if p else None

    def commit(self, positions: dict[str, Position]) -> None:
        for path, pos in positions.items():
            self.data["positions"][path] = pos.__dict__
        self.save()

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data))
        os.replace(tmp, self.path)


# =========================================================================== normalization
def normalize(
    p: Parsed, spec: LogSpec, pos: Position, line: str, source_id: str, privacy: PrivacyPolicy
) -> LiveEvent:
    a = dict(p.attrs)
    for key in ("client", "src_ip"):
        if key in a:
            a[key] = privacy.ip(a[key])
    if "path" in a:
        a["path"] = privacy.path(a["path"])
    if "referer" in a:
        a["referer"] = privacy.path(a["referer"])
    if "user_agent" in a:
        a["user_agent"] = privacy.user_agent(a["user_agent"])
    for key in ("user", "target_user", "target", "remote_user", "process", "unit"):
        if isinstance(a.get(key), str):
            a[key] = clean_text(a[key], 64)
    if isinstance(a.get("command"), str):
        a["command"] = privacy.message(a["command"])
    msg = privacy.message(p.message)
    if msg and "client" in p.attrs and p.attrs.get("client") and privacy.ip_mode != "keep":
        msg = msg.replace(str(p.attrs["client"]), str(a.get("client")))
    if msg and p.attrs.get("src_ip") and privacy.ip_mode != "keep":
        msg = msg.replace(str(p.attrs["src_ip"]), str(a.get("src_ip")))
    line_hash = make_event_id(line)
    return LiveEvent(
        event_id=make_event_id(
            source_id, spec.type, spec.path, pos.dev, pos.ino, pos.offset, line_hash
        ),
        source_id=source_id,
        kind=p.kind,
        ts=p.ts,
        service=spec.service or p.service,
        attrs=a,
        message=msg,
    )


def parse_line(spec: LogSpec, line: str, tz: tzinfo) -> Parsed | None:
    line = clean_text(line, MAX_LINE)
    if spec.type == "nginx_access":
        return parse_nginx_access(line)
    if spec.type == "nginx_error":
        return parse_nginx_error(line, tz)
    if spec.type == "auth":
        return parse_auth_log(line, tz)
    return parse_syslog(line, tz)


# =========================================================================== sending
class SendError(Exception):
    def __init__(self, msg: str, retry_after: float | None = None, permanent: bool = False):
        super().__init__(msg)
        self.retry_after = retry_after
        self.permanent = permanent


Transport = Callable[[list[dict[str, Any]]], dict[str, Any]]


def http_transport(cfg: AgentConfig) -> Transport:
    url = cfg.server_url.rstrip("/") + "/ingest/v1/events"
    ctx = ssl.create_default_context(cafile=cfg.ca_file) if url.startswith("https") else None

    def send(events: list[dict[str, Any]]) -> dict[str, Any]:
        body = gzip.compress(json.dumps({"source_id": cfg.source_id, "events": events}).encode())
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {cfg.token}",
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "User-Agent": f"threatgraph-agent/{AGENT_VERSION}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=cfg.http_timeout_seconds, context=ctx) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            ra = exc.headers.get("Retry-After") if exc.headers else None
            retry_after = float(ra) if ra and ra.isdigit() else None
            if exc.code in (408, 429) or exc.code >= 500:
                raise SendError(f"server busy ({exc.code})", retry_after) from exc
            if exc.code == 413:
                raise SendError("batch too large", permanent=False) from exc
            raise SendError(
                f"rejected ({exc.code})", retry_after=None, permanent=exc.code != 401
            ) from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise SendError(f"unreachable: {exc}") from exc

    return send


class Backoff:
    def __init__(self, base: float = 1.0, cap: float = 300.0, rng: random.Random | None = None):
        self.base, self.cap, self.failures = base, cap, 0
        self.rng = rng or random.Random()
        self.not_before = 0.0

    def ready(self, now: float) -> bool:
        return now >= self.not_before

    def success(self) -> None:
        self.failures, self.not_before = 0, 0.0

    def failure(self, now: float, retry_after: float | None = None) -> float:
        self.failures += 1
        delay = min(self.cap, self.base * 2 ** (self.failures - 1))
        delay = self.rng.uniform(delay / 2, delay)  # jitter: agents do not retry in lockstep
        if retry_after is not None:
            delay = max(delay, min(retry_after, self.cap))
        self.not_before = now + delay
        return delay


# =========================================================================== agent
@dataclass
class Buffered:
    event: LiveEvent | None  # None: a position-only marker for unparsed lines
    commit: tuple[str, Position] | None = None


class Agent:
    def __init__(
        self,
        cfg: AgentConfig,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.time,
        mono: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cfg = cfg
        self.clock, self.mono = clock, mono
        self.transport = transport or http_transport(cfg)
        self.state = StateStore(Path(cfg.state_dir))
        self.tailers = {
            s.path: Tailer(s.path, self.state.position(s.path), cfg.start_at_end) for s in cfg.logs
        }
        self.specs = {s.path: s for s in cfg.logs}
        self.buffer: deque[Buffered] = deque()
        self.backoff = Backoff()
        self.started = mono()
        self.last_flush = mono()
        self.counters = {
            "sent": 0,
            "acked_duplicates": 0,
            "dropped_samples": 0,
            "rejected_by_server": 0,
            "send_failures": 0,
        }
        self.unparsed: dict[str, int] = {s.path: 0 for s in cfg.logs}
        self.parsed: dict[str, int] = {s.path: 0 for s in cfg.logs}
        self.last_send_ok: float | None = None
        self.last_error: str | None = None
        self.collectors: list[tuple[Any, float]] = []
        sid = cfg.source_id
        if cfg.metrics.get("enabled", True):
            self.collectors.append(
                (
                    MetricsCollector(sid, cfg.metrics.get("disk_paths", ["/"])),
                    cfg.metrics.get("interval_seconds", 60),
                )
            )
        if cfg.systemd.get("enabled"):
            self.collectors.append(
                (
                    SystemdCollector(sid, cfg.systemd.get("units", [])),
                    cfg.systemd.get("interval_seconds", 60),
                )
            )
        if cfg.docker.get("enabled"):
            self.collectors.append(
                (
                    DockerCollector(sid, cfg.docker.get("socket", "/var/run/docker.sock")),
                    cfg.docker.get("interval_seconds", 60),
                )
            )
        if cfg.fim.get("enabled"):
            fim = FileIntegrityCollector(sid, cfg.fim.get("paths", []))
            fim.baseline = self.state.data.get("fim_baseline")
            self.collectors.append((fim, cfg.fim.get("interval_seconds", 300)))
        self.next_run = {c.name: 0.0 for c, _ in self.collectors}
        self.next_heartbeat = 0.0

    # ---------------------------------------------------------------- collection
    def room(self) -> int:
        return self.cfg.buffer_max_events - len(self.buffer)

    def _add_samples(self, events: Iterable[LiveEvent]) -> None:
        for e in events:
            if self.room() <= 0:
                self.counters["dropped_samples"] += 1
            else:
                self.buffer.append(Buffered(e))

    def collect(self) -> None:
        now_m, now = self.mono(), self.clock()
        for c, interval in self.collectors:
            if now_m >= self.next_run[c.name]:
                self.next_run[c.name] = now_m + float(interval)
                self._add_samples(c.collect(now))
                if isinstance(c, FileIntegrityCollector):
                    self.state.data["fim_baseline"] = c.baseline
        if now_m >= self.next_heartbeat:
            self.next_heartbeat = now_m + self.cfg.heartbeat_interval_seconds
            self._add_samples([self.heartbeat(now)])
        tz = self.cfg.tz
        for path, tailer in self.tailers.items():
            if self.room() <= 0:
                break  # backpressure: lines stay in the log file until there is room
            spec = self.specs[path]
            for line, pos in tailer.read(self.room()):
                p = parse_line(spec, line, tz)
                if p is None:
                    # Unparsed lines are never shipped, but their position must still be
                    # committed in order: keep one position-only marker per run of them.
                    self.unparsed[path] += 1
                    last = self.buffer[-1] if self.buffer else None
                    if last and last.event is None and last.commit and last.commit[0] == path:
                        last.commit = (path, pos)
                    else:
                        self.buffer.append(Buffered(None, (path, pos)))
                    continue
                self.parsed[path] += 1
                ev = normalize(p, spec, pos, line, self.cfg.source_id, self.cfg.privacy)
                self.buffer.append(Buffered(ev, (path, pos)))

    def heartbeat(self, now: float) -> LiveEvent:
        return LiveEvent(
            event_id=make_event_id(self.cfg.source_id, "heartbeat", round(now, 3)),
            source_id=self.cfg.source_id,
            kind="agent.heartbeat",
            ts=now,
            service="agent",
            attrs={
                "version": AGENT_VERSION,
                "uptime_seconds": round(self.mono() - self.started),
                "buffered": len(self.buffer),
                "buffer_max": self.cfg.buffer_max_events,
                **self.counters,
                "last_send_ok": self.last_send_ok,
                "last_error": self.last_error,
                "logs": {
                    p: {
                        "type": self.specs[p].type,
                        "parsed": self.parsed[p],
                        "unparsed": self.unparsed[p],
                        "readable": os.access(p, os.R_OK),
                    }
                    for p in self.specs
                },
                "collectors": {c.name: c.status.as_dict() for c, _ in self.collectors},
            },
        )

    # ---------------------------------------------------------------- sending
    def flush(self, force: bool = False) -> bool:
        """Send one batch if due. Returns True when a batch was acknowledged."""
        now_m = self.mono()
        if not self.buffer or not self.backoff.ready(now_m):
            return False
        due = len(self.buffer) >= self.cfg.batch_max_events or (
            now_m - self.last_flush >= self.cfg.flush_interval_seconds
        )
        if not (due or force):
            return False
        batch = [self.buffer[i] for i in range(min(self.cfg.batch_max_events, len(self.buffer)))]
        payload = [b.event.to_dict() for b in batch if b.event is not None]
        if not payload:
            self._ack(len(batch))
            return True
        try:
            resp = self.transport(payload)
        except SendError as exc:
            self.counters["send_failures"] += 1
            self.last_error = str(exc)[:200]
            if exc.permanent:
                # The server will never accept this batch (e.g. 403/422): drop it so it does
                # not block everything behind it, and record why.
                log.error("batch rejected permanently: %s", exc)
                self._ack(len(batch))
                self.counters["rejected_by_server"] += len(payload)
                return False
            delay = self.backoff.failure(now_m, exc.retry_after)
            log.warning("send failed (%s); retrying in %.1fs", exc, delay)
            return False
        self.backoff.success()
        self.last_flush = now_m
        self.last_send_ok = self.clock()
        self.last_error = None
        self.counters["sent"] += int(resp.get("accepted", len(payload)))
        self.counters["acked_duplicates"] += int(resp.get("duplicates", 0))
        self.counters["rejected_by_server"] += int(resp.get("rejected", 0))
        self._ack(len(batch))
        return True

    def _ack(self, n: int) -> None:
        commits: dict[str, Position] = {}
        for _ in range(n):
            b = self.buffer.popleft()
            if b.commit:
                commits[b.commit[0]] = b.commit[1]
        self.state.commit(commits)  # also persists the integrity baseline

    def run(self, once: bool = False) -> None:
        stop = False

        def _stop(*_: Any) -> None:
            nonlocal stop
            stop = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        while not stop:
            self.collect()
            while self.flush(force=once):
                pass
            if once:
                break
            time.sleep(0.5)
        self.flush(force=True)
        for t in self.tailers.values():
            t.close()


def stdout_transport(events: list[dict[str, Any]]) -> dict[str, Any]:
    for e in events:
        print(json.dumps(e, sort_keys=True))
    return {"accepted": len(events)}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="threatgraph-agent", description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--once", action="store_true", help="collect and send one round, then exit")
    ap.add_argument("--dry-run", action="store_true", help="print events to stdout; send nothing")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    cfg = load_config(args.config)
    if not args.dry_run and not cfg.token:
        sys.exit("no agent token: set TG_AGENT_TOKEN, token_file or token")
    agent = Agent(cfg, transport=stdout_transport if args.dry_run else None)
    agent.run(once=args.once)


if __name__ == "__main__":
    main()
