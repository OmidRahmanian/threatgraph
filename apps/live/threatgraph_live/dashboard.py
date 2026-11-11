"""Private dashboard API for Live Monitoring Mode (served under /live-api/v1).

    uvicorn threatgraph_live.dashboard:app --host 127.0.0.1 --port 8001

Deploy it behind the same TLS reverse proxy as the website (same origin), so the session
cookie is first-party and no CORS is needed. Every route except login requires a session;
state-changing routes also require the `X-TG-Request: 1` header. Responses are `no-store`.
The public read-only research API (apps/api) is unchanged and never serves live data.
"""

from __future__ import annotations

import time
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from threatgraph.live.behavior import load_report
from threatgraph.live.config import LiveConfig
from threatgraph.live.incidents import VERDICTS, IncidentManager
from threatgraph.live.llm import Investigator
from threatgraph.live.notify import channels_from_env
from threatgraph.live.store import LiveStore
from threatgraph.live.views import RANGES, incident_detail, incident_list, jsonable, overview
from threatgraph_live.auth import (
    COOKIE,
    LoginLimiter,
    create_session,
    end_session,
    session_user,
    verify_password,
)
from threatgraph_live.settings import LiveSettings

PREFIX = "/live-api/v1"
IncidentId = Annotated[str, Path(pattern=r"^TG-\d{6,9}$")]
Range = Annotated[Literal["15m", "1h", "24h", "7d"], Query()]
KINDS = r"^[a-z]+\.[a-z]+(,[a-z]+\.[a-z]+)*$"


class Login(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class Resolve(BaseModel):
    verdict: Literal["confirmed_malicious", "benign", "false_positive", "expected_activity"]
    note: str = Field(default="", max_length=2000)


def create_dashboard_app(
    settings: LiveSettings | None = None,
    store: LiveStore | None = None,
    config: LiveConfig | None = None,
    investigator: Investigator | None = None,
) -> FastAPI:
    settings = settings or LiveSettings()
    cfg = config or settings.live_config()
    db = store or LiveStore(settings.db_path)
    limiter = LoginLimiter(settings.login_attempts_per_15min)
    inv = investigator or Investigator(db, cfg)
    app = FastAPI(
        title="ThreatGraph Live dashboard API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def user(request: Request) -> str:
        u = session_user(db, request.cookies.get(COOKIE))
        if u is None:
            raise HTTPException(401, "login required")
        return u

    def writer(request: Request, u: str = Depends(user)) -> str:
        if request.headers.get("x-tg-request") != "1":
            raise HTTPException(403, "missing X-TG-Request header")
        return u

    # ------------------------------------------------------------------ auth
    @app.post(f"{PREFIX}/auth/login")
    def login(body: Login, request: Request, response: Response) -> dict[str, Any]:
        if not settings.admin_password_hash:
            raise HTTPException(
                503, "dashboard login is not configured (TG_LIVE_ADMIN_PASSWORD_HASH)"
            )
        if request.headers.get("x-tg-request") != "1":
            raise HTTPException(403, "missing X-TG-Request header")
        client = request.client.host if request.client else "unknown"
        now = time.time()
        if not limiter.allow(client, now):
            raise HTTPException(429, "too many login attempts; try again later")
        ok_user = body.username == settings.admin_user
        ok_pw = verify_password(body.password, settings.admin_password_hash)  # always computed
        if not (ok_user and ok_pw):
            limiter.failed(client, now)
            raise HTTPException(401, "invalid credentials")
        token = create_session(db, body.username, settings.session_hours)
        response.set_cookie(
            COOKIE,
            token,
            max_age=int(settings.session_hours * 3600),
            httponly=True,
            secure=settings.cookie_secure,
            samesite="strict",
            path="/live-api",
        )
        return {"username": body.username}

    @app.post(f"{PREFIX}/auth/logout")
    def logout(request: Request, response: Response) -> dict[str, bool]:
        end_session(db, request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/live-api")
        return {"ok": True}

    @app.get(f"{PREFIX}/auth/me")
    def me(u: str = Depends(user)) -> dict[str, Any]:
        return {
            "username": u,
            "channels": [c.name for c in channels_from_env()],
            "llm_enabled": cfg.llm.enabled,
            "ranges": list(RANGES),
        }

    # ------------------------------------------------------------------ reads
    @app.get(f"{PREFIX}/overview")
    def get_overview(
        range: Range = "1h", simulated: bool = False, _: str = Depends(user)
    ) -> JSONResponse:
        return JSONResponse(jsonable(overview(db, cfg, time.time(), range, simulated)))

    @app.get(f"{PREFIX}/incidents")
    def get_incidents(
        status: Annotated[
            Literal["active", "open", "acknowledged", "resolved"] | None, Query()
        ] = None,
        simulated: bool = False,
        _: str = Depends(user),
    ) -> JSONResponse:
        return JSONResponse(
            jsonable({"incidents": incident_list(db, status=status, simulated=simulated)})
        )

    @app.get(f"{PREFIX}/incidents/{{incident_id}}")
    def get_incident(incident_id: IncidentId, _: str = Depends(user)) -> JSONResponse:
        d = incident_detail(db, incident_id)
        if d is None:
            raise HTTPException(404, "not found")
        return JSONResponse(jsonable(d))

    @app.get(f"{PREFIX}/events")
    def get_events(
        range: Range = "1h",
        kinds: Annotated[str | None, Query(pattern=KINDS, max_length=300)] = None,
        source: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9._-]{1,64}$")] = None,
        simulated: bool = False,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        _: str = Depends(user),
    ) -> JSONResponse:
        now = time.time()
        rows = db.events(
            kinds=kinds.split(",") if kinds else None,
            since=now - RANGES[range][0],
            source_id=source,
            simulated=simulated,
            limit=limit,
            order="DESC",
        )
        return JSONResponse(jsonable({"events": rows, "limit": limit}))

    @app.get(f"{PREFIX}/model")
    def get_model(_: str = Depends(user)) -> JSONResponse:
        return JSONResponse(jsonable({"report": load_report(settings.db_path)}))

    # ------------------------------------------------------------------ actions
    mgr = IncidentManager(db, cfg, channels=[])

    @app.post(f"{PREFIX}/incidents/{{incident_id}}/ack")
    def ack(incident_id: IncidentId, u: str = Depends(writer)) -> dict[str, bool]:
        if mgr.get(incident_id) is None:
            raise HTTPException(404, "not found")
        return {"changed": mgr.acknowledge(incident_id, u)}

    @app.post(f"{PREFIX}/incidents/{{incident_id}}/resolve")
    def resolve(
        incident_id: IncidentId, body: Resolve, u: str = Depends(writer)
    ) -> dict[str, bool]:
        if mgr.get(incident_id) is None:
            raise HTTPException(404, "not found")
        assert body.verdict in VERDICTS
        return {"changed": mgr.resolve(incident_id, u, body.verdict, body.note)}

    @app.post(f"{PREFIX}/incidents/{{incident_id}}/investigate")
    def investigate(incident_id: IncidentId, _: str = Depends(writer)) -> JSONResponse:
        if mgr.get(incident_id) is None:
            raise HTTPException(404, "not found")
        return JSONResponse(jsonable(inv.investigate(incident_id)))

    return app


def __getattr__(name: str) -> Any:  # lazy: importing the module does not open the database
    if name == "app":
        return create_dashboard_app()
    raise AttributeError(name)
