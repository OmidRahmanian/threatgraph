"""Structured live-event schema shared by the agent, the ingestion API and the detectors.

Standard library only (imported by the collector agent).

Every event carries:
- `event_id`: deterministic hash of where the event came from (source, collector, file
  identity and byte offset, or a sample timestamp), so a batch that is re-sent after a timeout
  is stored once (idempotent ingestion).
- `ts`: event time as UTC epoch seconds. Text logs without a time zone are interpreted in the
  agent's configured `log_timezone`.
- `source_id`: the agent (host) that observed it; the server checks it against the agent's
  credential, so one agent cannot write events for another.
- `simulated`: true only for clearly labeled test fixtures. Simulated events are stored apart
  from real telemetry in every query and never trigger real notifications.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

SCHEMA_VERSION = 1

# Event kinds and what `attrs` holds for each. The ingestion API rejects other kinds.
KINDS: dict[str, str] = {
    "http.access": "one web request: method, path, status, bytes, client, request_time",
    "http.error": "one web-server error log line: level, message, client",
    "ssh.auth": "an SSH authentication step: outcome, user, src_ip, method, invalid_user",
    "ssh.probe": "an SSH connection that never attempted authentication: src_ip, reason",
    "admin.sudo": "a sudo command or failed sudo attempt: user, target_user, command, outcome",
    "admin.su": "a switch-user session: user, target_user, outcome",
    "admin.account": "user or group management: action, target, group, privileged",
    "system.metrics": "a resource sample: cpu_percent, mem_percent, disk usage, load, uptime",
    "system.service": "a service state: unit, state (failed/active), detail",
    "system.kernel": "a kernel event: event (oom_kill, segfault), process",
    "container.health": "a container state: name, image, state, health, restart_count",
    "fim.change": "a monitored file changed: path, change (modified/added/removed), sha256",
    "probe.http": "an availability check: target, ok, status, latency_ms, error, cert_days_left",
    "agent.heartbeat": "collector health: version, uptime, buffered, dropped, collectors",
}

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make_event_id(*parts: object) -> str:
    """Deterministic 128-bit id from the event's origin (not from wall-clock receive time)."""
    blob = "\x1f".join(str(p) for p in parts).encode("utf-8", "replace")
    return hashlib.sha256(blob).hexdigest()[:32]


@dataclass
class LiveEvent:
    event_id: str
    source_id: str
    kind: str
    ts: float
    service: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)
    message: str | None = None
    simulated: bool = False
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


class EventValidationError(ValueError):
    pass


MAX_ATTRS_BYTES = 4096
MAX_MESSAGE = 1024


def validate_event(raw: dict[str, Any], *, now: float, max_skew: float = 86_400) -> LiveEvent:
    """Strict server-side validation of one event received from an agent."""
    if not isinstance(raw, dict):
        raise EventValidationError("event must be an object")
    kind = raw.get("kind")
    if kind not in KINDS:
        raise EventValidationError(f"unknown kind {kind!r}")
    eid = raw.get("event_id")
    if not isinstance(eid, str) or not re.fullmatch(r"[0-9a-f]{32}", eid):
        raise EventValidationError("event_id must be 32 lowercase hex characters")
    src = raw.get("source_id")
    if not isinstance(src, str) or not ID_RE.match(src):
        raise EventValidationError("invalid source_id")
    ts = raw.get("ts")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool) or ts != ts:
        raise EventValidationError("ts must be a number")
    if ts > now + 300:
        raise EventValidationError("ts is in the future")
    if ts < now - max_skew * 30:
        raise EventValidationError("ts is older than the accepted backfill window")
    attrs = raw.get("attrs") or {}
    if not isinstance(attrs, dict):
        raise EventValidationError("attrs must be an object")
    if len(json.dumps(attrs, default=str)) > MAX_ATTRS_BYTES:
        raise EventValidationError("attrs too large")
    service = raw.get("service")
    if service is not None and (not isinstance(service, str) or len(service) > 64):
        raise EventValidationError("invalid service")
    msg = raw.get("message")
    if msg is not None and not isinstance(msg, str):
        raise EventValidationError("message must be a string")
    return LiveEvent(
        event_id=eid,
        source_id=src,
        kind=kind,
        ts=float(ts),
        service=service,
        attrs=attrs,
        message=msg[:MAX_MESSAGE] if msg else None,
        simulated=bool(raw.get("simulated", False)),
    )
