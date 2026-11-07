"""ThreatGraph AI read-only API (v1).

Run:  uvicorn threatgraph_api.main:app --port 8000
Docs: http://localhost:8000/api/docs  (OpenAPI at /api/v1/openapi.json)

The API only serves persisted artifacts: it never trains models, accepts uploads or
scans raw data on request.
"""

from __future__ import annotations

import logging
import math
import os
import threading
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path as PathLib
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Path, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from threatgraph.config import load_dataset_config, load_models_config
from threatgraph.pipeline import MissingInputError
from threatgraph.provenance import PIPELINE_VERSION
from threatgraph.serving import schemas as S
from threatgraph.serving.payloads import NotFoundError, ServingContext

log = logging.getLogger("threatgraph.api")

ModelId = Annotated[str, Path(pattern=r"^[a-z0-9_]{1,64}$")]
WindowId = Annotated[str, Path(pattern=r"^w:[A-Za-z0-9@$._\-]{1,128}:\d{1,12}$")]
IncidentId = Annotated[str, Path(pattern=r"^inc:[A-Za-z0-9@$._\-]{1,128}:\d{1,12}$")]
EntityId = Annotated[str, Path(pattern=r"^(principal|computer):[A-Za-z0-9@$._\-]{1,128}$")]
Split = Annotated[Literal["validation", "test"], Query()]
MAX_GRAPH_RANGE_SECONDS = 2 * 86_400


class Settings:
    def __init__(self) -> None:
        self.dataset = os.environ.get("TG_DATASET", "demo")
        self.datasets_config = os.environ.get("TG_DATASETS_CONFIG")  # optional alternate YAML
        self.public_ids = os.environ.get("TG_PUBLIC_IDS", "true").lower() == "true"
        self.cors_origins = [
            o.strip()
            for o in os.environ.get("TG_CORS_ORIGINS", "http://localhost:3000").split(",")
            if o.strip()
        ]
        self.rate_limit_per_minute = int(os.environ.get("TG_RATE_LIMIT_PER_MINUTE", "240"))


class RateLimiter:
    """Small in-memory token bucket per client address (single-process deployments)."""

    def __init__(self, per_minute: int) -> None:
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0
        self.buckets: dict[str, tuple[float, float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            tokens, last = self.buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self.buckets[key] = (tokens, now)
                return False
            self.buckets[key] = (tokens - 1.0, now)
            if len(self.buckets) > 10_000:  # bound memory under many distinct clients
                self.buckets.clear()
            return True


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    state: dict[str, object] = {}

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        alt = settings.datasets_config
        cfg = load_dataset_config(settings.dataset, PathLib(alt) if alt else None)
        state["cfg"] = cfg
        try:
            state["ctx"] = ServingContext(cfg, load_models_config(), public_ids=settings.public_ids)
        except MissingInputError as exc:
            state["error"] = str(exc)
            log.warning("artifacts missing: %s", exc)
        yield

    app = FastAPI(
        title="ThreatGraph AI API",
        version=PIPELINE_VERSION,
        description="Read-only access to persisted ThreatGraph AI artifacts.",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET"],
        allow_headers=[],
    )
    limiter = RateLimiter(settings.rate_limit_per_minute)

    @app.middleware("http")
    async def rate_limit(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        client = request.client.host if request.client else "unknown"
        if request.url.path.startswith("/api/v1/") and not limiter.allow(client):
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
        response = await call_next(request)
        if request.method == "GET" and response.status_code == 200:
            response.headers.setdefault("Cache-Control", "public, max-age=300")
        return response

    @app.exception_handler(NotFoundError)
    async def not_found(_: Request, __: NotFoundError) -> JSONResponse:
        return JSONResponse({"detail": "not found"}, status_code=404)

    @app.exception_handler(Exception)
    async def internal(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", exc_info=exc)
        return JSONResponse({"detail": "internal error"}, status_code=500)

    def ctx() -> ServingContext:
        c = state.get("ctx")
        if not isinstance(c, ServingContext):
            raise HTTPException(503, "artifacts not built; run scripts/run_pipeline.py")
        return c

    @app.get("/api/v1/health", response_model=S.Health)
    def health() -> S.Health:
        cfg = state["cfg"]
        ok = isinstance(state.get("ctx"), ServingContext)
        return S.Health(
            status="ok" if ok else "degraded",
            version=PIPELINE_VERSION,
            dataset=cfg.name,  # type: ignore[attr-defined]
            mode=cfg.mode,  # type: ignore[attr-defined]
            detail=None if ok else "artifacts not built",
        )

    @app.get("/api/v1/metadata", response_model=S.Metadata)
    def metadata() -> S.Metadata:
        return ctx().metadata()

    @app.get("/api/v1/summary", response_model=S.Summary)
    def summary() -> S.Summary:
        return ctx().summary()

    @app.get("/api/v1/models", response_model=S.ModelList)
    def models() -> S.ModelList:
        return ctx().model_list()

    @app.get("/api/v1/models/{model_id}/metrics", response_model=S.ModelMetrics)
    def model_metrics(model_id: ModelId) -> S.ModelMetrics:
        return ctx().model_metrics(model_id)

    @app.get("/api/v1/models/{model_id}/scores", response_model=S.ScoreTable)
    def scores(model_id: ModelId, split: Split = "test") -> S.ScoreTable:
        return ctx().score_table(model_id, split)

    @app.get("/api/v1/models/{model_id}/predictions", response_model=S.PredictionPage)
    def predictions(
        model_id: ModelId,
        split: Split = "test",
        threshold: Annotated[float | None, Query(ge=-1e6, le=1e6)] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    ) -> S.PredictionPage:
        if threshold is not None and not math.isfinite(threshold):
            raise HTTPException(422, "threshold must be finite")
        return ctx().predictions_page(model_id, split, threshold, limit, offset)

    @app.get("/api/v1/models/{model_id}/explanations/{window_id}", response_model=S.Explanation)
    def explanation(model_id: ModelId, window_id: WindowId) -> S.Explanation:
        return ctx().explanation(model_id, window_id)

    @app.get("/api/v1/events", response_model=S.EventPage)
    def events(
        start: Annotated[int | None, Query(ge=0, le=10**10)] = None,
        end: Annotated[int | None, Query(ge=0, le=10**10)] = None,
        principal: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9@$._\-]{1,128}$")] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        cursor: Annotated[int | None, Query(ge=0)] = None,
    ) -> S.EventPage:
        if start is not None and end is not None and end <= start:
            raise HTTPException(422, "end must be greater than start")
        return ctx().events_page(start, end, principal, limit, cursor)

    @app.get("/api/v1/graph", response_model=S.Subgraph)
    def graph(
        entity: Annotated[str, Query(pattern=r"^(principal|computer):[A-Za-z0-9@$._\-]{1,128}$")],
        start: Annotated[int, Query(ge=0, le=10**10)],
        end: Annotated[int, Query(ge=1, le=10**10)],
        hops: Annotated[int, Query(ge=1, le=2)] = 1,
        max_edges: Annotated[int, Query(ge=1, le=300)] = 60,
    ) -> S.Subgraph:
        if end <= start:
            raise HTTPException(422, "end must be greater than start")
        if end - start > MAX_GRAPH_RANGE_SECONDS:
            raise HTTPException(422, f"range is limited to {MAX_GRAPH_RANGE_SECONDS} seconds")
        return ctx().subgraph(entity, start, end, hops, max_edges)

    @app.get("/api/v1/graph/windows", response_model=S.GraphWindowIndex)
    def graph_windows(split: Split = "test") -> S.GraphWindowIndex:
        return ctx().graph_window_index(split)

    @app.get("/api/v1/graph/windows/{window_id}", response_model=S.GraphWindow)
    def graph_window(window_id: WindowId) -> S.GraphWindow:
        return ctx().graph_window(window_id)

    @app.get("/api/v1/network", response_model=S.NetworkMap)
    def network(split: Split = "test") -> S.NetworkMap:
        return ctx().network_map(split)

    @app.get("/api/v1/entities/{entity_id}", response_model=S.EntityDetail)
    def entity(entity_id: EntityId) -> S.EntityDetail:
        return ctx().entity(entity_id)

    @app.get("/api/v1/incidents", response_model=S.IncidentIndex)
    def incidents(
        scope: Annotated[Literal["evaluated", "all"], Query()] = "evaluated",
    ) -> S.IncidentIndex:
        return ctx().incident_index(scope)

    @app.get("/api/v1/incidents/{incident_id}", response_model=S.Incident)
    def incident(incident_id: IncidentId) -> S.Incident:
        return ctx().incident(incident_id)

    @app.get("/api/v1/drift", response_model=S.Drift)
    def drift() -> S.Drift:
        return ctx().drift()

    @app.get("/api/v1/benchmarks", response_model=S.Benchmarks)
    def benchmarks() -> S.Benchmarks:
        return ctx().benchmarks()

    return app


app = create_app()
