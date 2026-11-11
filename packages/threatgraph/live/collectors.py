"""Periodic collectors: system metrics, systemd failures, Docker health, file integrity.

Standard library only. Each collector is optional and returns `[]` (with a recorded status)
when its data source does not exist on this host, so the same agent runs on servers without
systemd, Docker or Linux /proc. Nothing here changes system state: commands are read-only
(`systemctl list-units`), the Docker API is only queried with GET, and files are only read.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from threatgraph.live.events import LiveEvent, make_event_id

Emit = Callable[[str, float, dict[str, Any], str | None, str | None], LiveEvent]


class CollectorStatus:
    def __init__(self) -> None:
        self.ok = True
        self.detail: str | None = None
        self.last_run: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "detail": self.detail, "last_run": self.last_run}


# --------------------------------------------------------------------------- metrics
def _read(path: str) -> str | None:
    try:
        return Path(path).read_text()
    except OSError:
        return None


class MetricsCollector:
    name = "metrics"

    def __init__(self, source_id: str, disk_paths: list[str], proc_root: str = "/proc") -> None:
        self.source_id = source_id
        self.disk_paths = disk_paths
        self.proc = proc_root
        self._cpu_prev: tuple[int, int] | None = None
        self.status = CollectorStatus()

    def _cpu_percent(self) -> float | None:
        text = _read(f"{self.proc}/stat")
        if not text:
            return None
        fields = [int(x) for x in text.splitlines()[0].split()[1:]]
        idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
        total = sum(fields[:8])
        prev, self._cpu_prev = self._cpu_prev, (idle, total)
        if prev is None or total == prev[1]:
            return None  # first sample establishes the baseline
        return round(100.0 * (1 - (idle - prev[0]) / (total - prev[1])), 1)

    def _memory(self) -> dict[str, Any]:
        text = _read(f"{self.proc}/meminfo")
        if not text:
            return {}
        kv = {}
        for line in text.splitlines():
            k, _, v = line.partition(":")
            kv[k] = int(v.split()[0]) if v.split() else 0
        total, avail = kv.get("MemTotal"), kv.get("MemAvailable")
        out: dict[str, Any] = {}
        if total and avail is not None:
            out["mem_total_mb"] = round(total / 1024)
            out["mem_percent"] = round(100.0 * (1 - avail / total), 1)
        if kv.get("SwapTotal"):
            out["swap_percent"] = round(100.0 * (1 - kv.get("SwapFree", 0) / kv["SwapTotal"]), 1)
        return out

    def collect(self, now: float) -> list[LiveEvent]:
        attrs: dict[str, Any] = {"cpu_percent": self._cpu_percent(), **self._memory()}
        with contextlib.suppress(OSError):
            attrs["load_1m"], attrs["load_5m"], attrs["load_15m"] = (
                round(x, 2) for x in os.getloadavg()
            )
        attrs["cpu_count"] = os.cpu_count()
        up = _read(f"{self.proc}/uptime")
        attrs["uptime_seconds"] = round(float(up.split()[0])) if up else None
        disks = []
        for p in self.disk_paths:
            try:
                du = shutil.disk_usage(p)
            except OSError:
                continue
            disks.append(
                {
                    "path": p,
                    "used_percent": round(100.0 * du.used / du.total, 1) if du.total else None,
                    "free_gb": round(du.free / 1e9, 2),
                    "total_gb": round(du.total / 1e9, 2),
                }
            )
        attrs["disks"] = disks
        self.status.last_run = now
        self.status.detail = None if attrs.get("mem_percent") is not None else "no /proc/meminfo"
        return [
            LiveEvent(
                event_id=make_event_id(self.source_id, "metrics", round(now, 3)),
                source_id=self.source_id,
                kind="system.metrics",
                ts=now,
                service="host",
                attrs=attrs,
            )
        ]


# --------------------------------------------------------------------------- systemd
class SystemdCollector:
    """Reports units entering and leaving the `failed` state (read-only `systemctl`)."""

    name = "systemd"

    def __init__(self, source_id: str, units: list[str], runner: Callable[[], str] | None = None):
        self.source_id = source_id
        self.units = set(units)
        self.failed: set[str] | None = None  # None until the first successful poll
        self.status = CollectorStatus()
        self._runner = runner or self._systemctl

    @staticmethod
    def _systemctl() -> str:
        exe = shutil.which("systemctl")
        if not exe:
            raise FileNotFoundError("systemctl not found")
        return subprocess.run(
            [exe, "list-units", "--state=failed", "--no-legend", "--plain", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout

    def collect(self, now: float) -> list[LiveEvent]:
        self.status.last_run = now
        try:
            out = self._runner()
        except (OSError, subprocess.SubprocessError) as exc:
            self.status.ok, self.status.detail = False, f"{type(exc).__name__}: {exc}"[:200]
            return []
        self.status.ok, self.status.detail = True, None
        failed = {ln.split()[0].lstrip("●").strip() for ln in out.splitlines() if ln.strip()}
        failed = {u for u in failed if u and (not self.units or u in self.units)}
        prev = self.failed if self.failed is not None else set()
        self.failed = failed
        events = []
        for unit, state in [(u, "failed") for u in sorted(failed - prev)] + [
            (u, "active") for u in sorted(prev - failed)
        ]:
            events.append(
                LiveEvent(
                    event_id=make_event_id(self.source_id, "systemd", unit, state, now),
                    source_id=self.source_id,
                    kind="system.service",
                    ts=now,
                    service="systemd",
                    attrs={"unit": unit, "state": state, "source": "systemctl"},
                )
            )
        return events


# --------------------------------------------------------------------------- docker
class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 5.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


class DockerCollector:
    """Container state and health via GET /containers/json on the Docker API socket.

    Point `socket` at a read-only Docker socket proxy where possible: direct access to the
    Docker socket is equivalent to root on the host (docs/live/collector.md).
    """

    name = "docker"

    def __init__(
        self, source_id: str, socket_path: str, fetch: Callable[[], list[dict]] | None = None
    ):
        self.source_id = source_id
        self.socket_path = socket_path
        self.state: dict[str, tuple[str, str | None, int]] = {}
        self.status = CollectorStatus()
        self._fetch = fetch or self._get

    def _get(self) -> list[dict]:
        conn = _UnixHTTPConnection(self.socket_path)
        try:
            conn.request("GET", "/containers/json?all=1")
            resp = conn.getresponse()
            if resp.status != 200:
                raise OSError(f"docker API returned {resp.status}")
            return json.loads(resp.read())
        finally:
            conn.close()

    def collect(self, now: float) -> list[LiveEvent]:
        self.status.last_run = now
        try:
            containers = self._fetch()
        except (OSError, ValueError) as exc:
            self.status.ok, self.status.detail = False, f"{type(exc).__name__}: {exc}"[:200]
            return []
        self.status.ok, self.status.detail = True, None
        events = []
        seen = set()
        for c in containers:
            name = (c.get("Names") or ["?"])[0].lstrip("/")
            seen.add(name)
            state = c.get("State", "unknown")
            status_text = c.get("Status", "")
            health = None
            for h in ("healthy", "unhealthy", "starting"):
                if f"({h})" in status_text or f"(health: {h})" in status_text:
                    health = h
            restarts = int(c.get("RestartCount", 0) or 0)
            cur = (state, health, restarts)
            if self.state.get(name) != cur:
                events.append(
                    LiveEvent(
                        event_id=make_event_id(self.source_id, "docker", name, *cur, now),
                        source_id=self.source_id,
                        kind="container.health",
                        ts=now,
                        service="docker",
                        attrs={
                            "name": name,
                            "image": str(c.get("Image", ""))[:120],
                            "state": state,
                            "health": health,
                            "restart_count": restarts,
                            "previous_state": self.state.get(name, (None,))[0],
                        },
                    )
                )
                self.state[name] = cur
        for gone in sorted(set(self.state) - seen):
            del self.state[gone]
            events.append(
                LiveEvent(
                    event_id=make_event_id(self.source_id, "docker", gone, "removed", now),
                    source_id=self.source_id,
                    kind="container.health",
                    ts=now,
                    service="docker",
                    attrs={"name": gone, "state": "removed", "health": None},
                )
            )
        return events


# --------------------------------------------------------------------------- file integrity
class FileIntegrityCollector:
    """SHA-256 of explicitly configured files (directories: up to `max_files` regular files).

    The first run records a baseline and reports nothing; later runs report modified, added
    and removed files. The baseline is kept in the agent state directory.
    """

    name = "fim"

    def __init__(self, source_id: str, paths: list[str], max_files: int = 2000) -> None:
        self.source_id = source_id
        self.paths = paths
        self.max_files = max_files
        self.baseline: dict[str, str] | None = None
        self.status = CollectorStatus()

    def _files(self) -> list[Path]:
        out: list[Path] = []
        for p in map(Path, self.paths):
            if p.is_file():
                out.append(p)
            elif p.is_dir():
                for f in sorted(p.rglob("*")):
                    if f.is_file() and not f.is_symlink():
                        out.append(f)
                    if len(out) >= self.max_files:
                        break
        return out[: self.max_files]

    def snapshot(self) -> tuple[dict[str, str], list[str]]:
        hashes, errors = {}, []
        for f in self._files():
            try:
                h = hashlib.sha256()
                with f.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                hashes[str(f)] = h.hexdigest()
            except OSError as exc:
                errors.append(f"{f}: {exc.strerror}")
        return hashes, errors

    def collect(self, now: float) -> list[LiveEvent]:
        self.status.last_run = now
        cur, errors = self.snapshot()
        self.status.ok = not errors
        self.status.detail = "; ".join(errors[:3]) or None
        if self.baseline is None:
            self.baseline = cur
            return []
        events = []
        for path in sorted(set(cur) | set(self.baseline)):
            before, after = self.baseline.get(path), cur.get(path)
            if before == after:
                continue
            change = "added" if before is None else "removed" if after is None else "modified"
            events.append(
                LiveEvent(
                    event_id=make_event_id(self.source_id, "fim", path, before, after),
                    source_id=self.source_id,
                    kind="fim.change",
                    ts=now,
                    service="fim",
                    attrs={
                        "path": path,
                        "change": change,
                        "sha256_before": before,
                        "sha256_after": after,
                    },
                )
            )
        self.baseline = cur
        return events


def monotonic() -> float:
    return time.monotonic()
