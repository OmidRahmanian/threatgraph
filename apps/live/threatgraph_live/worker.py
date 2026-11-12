"""Detection and notification worker: one process, one loop.

Each cycle: run the on-server probes, evaluate the rules (and the behavioural model when one
is trained), update incidents, deliver due notifications, and (hourly) apply retention and
retrain the model when it is older than `ml.retrain_hours`. A failure in one step is logged
and recorded in `worker_status` without stopping the others: alerts do not depend on the
model or on the LLM.
"""

from __future__ import annotations

import logging
import signal
import time
import traceback
from typing import Any

from threatgraph.live import behavior
from threatgraph.live.config import LiveConfig
from threatgraph.live.detect import RuleEngine
from threatgraph.live.events import LiveEvent, make_event_id
from threatgraph.live.incidents import IncidentManager
from threatgraph.live.notify import Channel, channels_from_env, deliver_due
from threatgraph.live.probe import Target, check
from threatgraph.live.store import LiveStore

log = logging.getLogger("threatgraph.worker")
PROBE_SOURCE = "worker-probe"


class Worker:
    def __init__(
        self,
        store: LiveStore,
        cfg: LiveConfig,
        db_path: str,
        channels: list[Channel] | None = None,
        checker: Any = check,
    ) -> None:
        self.store, self.cfg, self.db_path = store, cfg, db_path
        self.channels = channels_from_env() if channels is None else channels
        self.manager = IncidentManager(store, cfg, [c.name for c in self.channels])
        self.engine = RuleEngine(store, cfg)
        self.checker = checker
        self.model = behavior.load_model(db_path)
        self.last_probe = 0.0
        self.last_hourly = 0.0

    def _probes(self, now: float) -> None:
        if not self.cfg.probes.targets or now - self.last_probe < self.cfg.probes.interval_seconds:
            return
        self.last_probe = now
        events = []
        for t in self.cfg.probes.targets:
            r = self.checker(
                Target(t.name, t.url, t.expect_status, t.expect_text, t.timeout_seconds, t.service)
            )
            events.append(
                LiveEvent(
                    make_event_id(PROBE_SOURCE, t.name, round(now, 3)),
                    PROBE_SOURCE,
                    "probe.http",
                    now,
                    t.service or t.name,
                    r,
                )
            )
        self.store.insert_events(events, received_at=now)

    def _hourly(self, now: float) -> dict[str, Any]:
        if now - self.last_hourly < 3600:
            return {}
        self.last_hourly = now
        r = self.cfg.retention
        out: dict[str, Any] = {
            "retention": self.store.apply_retention(
                now=now,
                event_days=r.event_days,
                metrics_days=r.metrics_days,
                incident_days=r.incident_days,
                notification_days=r.notification_days,
            )
        }
        if self.cfg.ml.enabled:
            rep = behavior.load_report(self.db_path)
            age_h = (now - rep["trained_at"]) / 3600 if rep else float("inf")
            untrained = (
                rep is None or rep.get("status") != "trained"
            )  # retry hourly until enough history
            if untrained or age_h >= self.cfg.ml.retrain_hours:
                rep = behavior.train(self.store, self.cfg, self.db_path, now=now)
                self.model = (
                    behavior.load_model(self.db_path) if rep["status"] == "trained" else None
                )
                out["model"] = rep["status"]
        return out

    def cycle(self, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        status: dict[str, Any] = {"last_run": now, "errors": {}}
        steps = [
            ("probes", lambda: self._probes(now)),
            ("detect", lambda: self._detect(now)),
            ("notify", lambda: deliver_due(self.store, self.channels, self.cfg, now)),
            ("hourly", lambda: self._hourly(now)),
        ]
        for name, fn in steps:
            try:
                result = fn()
                if result:
                    status[name] = result
            except Exception as exc:  # one failing step must not stop detection or alerts
                log.error("worker step %s failed: %s", name, traceback.format_exc())
                status["errors"][name] = f"{type(exc).__name__}: {str(exc)[:200]}"
        status["channels"] = [c.name for c in self.channels]
        status["model_loaded"] = self.model is not None
        self.store.kv_set("worker_status", status)
        return status

    def _detect(self, now: float) -> dict[str, int]:
        findings = self.engine.run(now)
        if self.model is not None and self.cfg.ml.enabled:
            try:
                findings += behavior.score_recent(self.store, self.cfg, self.model, now)
            except Exception:
                log.error("model scoring failed; rules continue: %s", traceback.format_exc())
        return self.manager.apply(findings, now)

    def run(self) -> None:
        stop = False

        def _stop(*_: Any) -> None:
            nonlocal stop
            stop = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        if not self.channels:
            log.warning("no notification channel configured: incidents are dashboard-only")
        while not stop:
            started = time.time()
            self.cycle(started)
            while not stop and time.time() - started < self.cfg.detection.interval_seconds:
                time.sleep(1)
