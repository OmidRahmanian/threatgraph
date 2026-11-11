"""Telemetry ingestion API (agents and external probes → storage).

    uvicorn threatgraph_live.ingest:app --host 10.8.0.1 --port 8443 \
        --ssl-certfile cert.pem --ssl-keyfile key.pem

Bind it to a private interface (WireGuard/Tailscale) or put it behind the TLS reverse proxy;
never expose it unauthenticated. Every request needs `Authorization: Bearer <agent token>`;
the token identifies the agent, and every event in the batch must carry that agent's
`source_id`, so one compromised agent cannot write another host's telemetry.

Protections: body size cap before reading, streaming gzip decompression with an output cap
(no decompression bombs), per-agent event-rate limit (429 + Retry-After), strict per-event
validation, idempotent inserts (`INSERT OR IGNORE` on (source_id, event_id)), and 503 +
Retry-After when the database is busy, which the agent treats as backpressure.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import zlib
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from threatgraph.live.config import LiveConfig
from threatgraph.live.events import EventValidationError, LiveEvent, validate_event
from threatgraph.live.store import LiveStore
from threatgraph_live.settings import LiveSettings

log = logging.getLogger("threatgraph.ingest")
MAX_REJECTION_EXAMPLES = 5


class EventRateLimiter:
    """Token bucket per agent, measured in events rather than requests."""

    def __init__(self, per_minute: int) -> None:
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0
        self.buckets: dict[str, tuple[float, float]] = {}
        self.lock = threading.Lock()

    def take(self, key: str, n: int, now: float) -> float:
        """Consume n tokens; returns 0 when allowed, otherwise seconds to wait."""
        with self.lock:
            tokens, last = self.buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if n > tokens:
                self.buckets[key] = (tokens, now)
                return max(1.0, (n - tokens) / self.rate)
            self.buckets[key] = (tokens - n, now)
            return 0.0


def _decompress(body: bytes, limit: int) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(body, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        raise ValueError("decompressed body too large")
    return out


def create_ingest_app(
    settings: LiveSettings | None = None,
    store: LiveStore | None = None,
    config: LiveConfig | None = None,
) -> FastAPI:
    settings = settings or LiveSettings()
    cfg = config or settings.live_config()
    db = store or LiveStore(settings.db_path)
    limiter = EventRateLimiter(cfg.ingest.max_events_per_minute_per_agent)
    app = FastAPI(
        title="ThreatGraph Live ingestion",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,  # no public schema for a private endpoint
    )
    app.state.store = db

    def err(status: int, detail: str, retry_after: float | None = None) -> JSONResponse:
        headers = {"Retry-After": str(int(retry_after + 0.999))} if retry_after else None
        return JSONResponse({"detail": detail}, status_code=status, headers=headers)

    @app.get("/ingest/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/ingest/v1/events")
    async def ingest(request: Request) -> JSONResponse:
        auth = request.headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        agent = db.agent_for_token(token.strip()) if scheme.lower() == "bearer" and token else None
        if agent is None:
            return err(401, "invalid or missing agent token")
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > cfg.ingest.max_body_bytes:
            return err(413, "body too large")
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > cfg.ingest.max_body_bytes:
                return err(413, "body too large")
        try:
            if request.headers.get("content-encoding", "").lower() == "gzip":
                body = _decompress(body, cfg.ingest.max_decompressed_bytes)
            payload = json.loads(body)
        except (ValueError, zlib.error):
            return err(400, "body must be JSON (optionally gzip-encoded)")
        if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
            return err(422, "expected {source_id, events: [...]}")
        source = agent["source_id"]
        if payload.get("source_id") != source:
            return err(403, "source_id does not match the agent token")
        raw_events: list[Any] = payload["events"]
        if len(raw_events) > cfg.ingest.max_batch_events:
            return err(413, f"at most {cfg.ingest.max_batch_events} events per batch")
        now = time.time()
        wait = limiter.take(source, len(raw_events), now)
        if wait:
            return err(429, "event rate limit exceeded", wait)

        good: list[LiveEvent] = []
        reasons: dict[str, int] = {}
        examples: list[str] = []
        for raw in raw_events:
            try:
                ev = validate_event(raw, now=now, max_skew=cfg.ingest.max_clock_skew_seconds)
                if ev.source_id != source:
                    raise EventValidationError("event source_id does not match the agent token")
                if agent["role"] == "probe" and ev.kind not in ("probe.http", "agent.heartbeat"):
                    raise EventValidationError("a probe credential may only send probe results")
                good.append(ev)
            except EventValidationError as exc:
                reasons[str(exc)] = reasons.get(str(exc), 0) + 1
                if len(examples) < MAX_REJECTION_EXAMPLES:
                    examples.append(str(exc))
        try:
            res = db.insert_events(good, received_at=now)
        except sqlite3.OperationalError as exc:  # locked/busy: ask the agent to back off
            log.warning("database busy: %s", exc)
            return err(503, "storage busy", 5)
        rejected = len(raw_events) - len(good)
        if rejected:
            log.info("agent %s: %d events rejected: %s", source, rejected, reasons)
        return JSONResponse(
            {
                "accepted": res.accepted,
                "duplicates": res.duplicates,
                "rejected": rejected,
                "rejection_reasons": reasons,
            }
        )

    return app


def __getattr__(name: str) -> Any:  # lazy, so importing the module does not open a database
    if name == "app":
        return create_ingest_app()
    raise AttributeError(name)
