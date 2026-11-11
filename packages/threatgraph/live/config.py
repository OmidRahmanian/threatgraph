"""Server-side configuration for Live Monitoring Mode (configs/live.yaml).

Thresholds live here, not in code, and every rule documents its default severity in
docs/live/incidents.md. Secrets (agent tokens, bot tokens, SMTP passwords, the dashboard
password hash) never go in this file: they come from the environment or `*_FILE` secrets.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from threatgraph.config import CONFIG_DIR

Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITIES: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")


def severity_rank(s: str) -> int:
    return SEVERITIES.index(s)  # type: ignore[arg-type,unused-ignore]


class Retention(BaseModel):
    event_days: float = Field(default=30, gt=0)
    metrics_days: float = Field(default=14, gt=0)
    incident_days: float = Field(default=365, gt=0)
    notification_days: float = Field(default=90, gt=0)


class IngestLimits(BaseModel):
    max_batch_events: int = Field(default=2000, ge=1, le=20_000)
    max_body_bytes: int = Field(default=5_000_000, ge=10_000)
    max_decompressed_bytes: int = Field(default=25_000_000, ge=10_000)
    max_events_per_minute_per_agent: int = Field(default=60_000, ge=10)
    max_clock_skew_seconds: int = Field(default=86_400, ge=60)


class Rule(BaseModel):
    enabled: bool = True
    severity: Severity = "medium"
    params: dict[str, Any] = {}


class Detection(BaseModel):
    interval_seconds: int = Field(default=60, ge=5)
    lookback_seconds: int = Field(default=900, ge=60)
    agent_offline_after_seconds: int = Field(default=300, ge=60)
    sensitive_paths: list[str] = []
    allowlist_sources: list[str] = []
    rules: dict[str, Rule] = {}

    def rule(self, name: str) -> Rule:
        return self.rules.get(name, Rule(enabled=False))


class Notifications(BaseModel):
    min_severity: Severity = "medium"
    cooldown_seconds: int = Field(default=3600, ge=0)
    max_attempts: int = Field(default=6, ge=1, le=20)
    retry_base_seconds: float = Field(default=30, gt=0)
    retry_max_seconds: float = Field(default=3600, gt=0)
    recovery_notifications: bool = True
    dashboard_url: str | None = None


class ProbeTarget(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    url: str
    expect_status: list[int] = [200]
    expect_text: str | None = None
    timeout_seconds: float = Field(default=10, gt=0, le=60)
    service: str | None = None

    @field_validator("url")
    @classmethod
    def _http(cls, v: str) -> str:
        if not v.startswith(("https://", "http://")):
            raise ValueError("probe url must be http(s)")
        return v


class Probes(BaseModel):
    interval_seconds: int = Field(default=60, ge=10)
    targets: list[ProbeTarget] = []


class MlConfig(BaseModel):
    enabled: bool = True
    bucket_seconds: int = Field(default=300, ge=60)
    min_train_windows: int = Field(default=500, ge=50)
    alert_rate: float = Field(default=0.002, gt=0, lt=0.5)
    retrain_hours: float = Field(default=24, gt=0)
    train_days: float = Field(default=7, gt=0)
    validation_days: float = Field(default=1, gt=0)
    seed: int = 42


class LlmConfig(BaseModel):
    enabled: bool = False
    ollama_url: str = "http://ollama:11434"
    model: str = "llama3.2:3b"
    timeout_seconds: float = Field(default=120, gt=0)
    max_evidence_events: int = Field(default=40, ge=1, le=200)


class ServiceInfo(BaseModel):
    display_name: str


class LiveConfig(BaseModel):
    retention: Retention = Retention()
    ingest: IngestLimits = IngestLimits()
    detection: Detection = Detection()
    notifications: Notifications = Notifications()
    probes: Probes = Probes()
    ml: MlConfig = MlConfig()
    llm: LlmConfig = LlmConfig()
    services: dict[str, ServiceInfo] = {}

    def service_name(self, service: str | None) -> str:
        if not service:
            return "Unknown service"
        info = self.services.get(service)
        return info.display_name if info else service


def load_live_config(path: Path | None = None) -> LiveConfig:
    p = path or Path(os.environ.get("TG_LIVE_CONFIG", CONFIG_DIR / "live.yaml"))
    raw = yaml.safe_load(p.read_text()) or {}
    return LiveConfig(**raw)


def secret_env(name: str) -> str | None:
    """`NAME` or the contents of the file named by `NAME_FILE` (Docker/systemd secrets)."""
    v = os.environ.get(name)
    if v:
        return v.strip()
    f = os.environ.get(f"{name}_FILE")
    if f and Path(f).exists():
        return Path(f).read_text().strip()
    return None
