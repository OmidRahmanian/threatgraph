"""Environment settings shared by the live services. Secrets support `NAME_FILE`."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from threatgraph.config import REPO_ROOT
from threatgraph.live.config import LiveConfig, load_live_config, secret_env


@dataclass
class LiveSettings:
    db_path: str = field(
        default_factory=lambda: os.environ.get(
            "TG_LIVE_DB", str(REPO_ROOT / "data" / "live" / "live.db")
        )
    )
    config_path: str | None = field(default_factory=lambda: os.environ.get("TG_LIVE_CONFIG"))
    admin_user: str = field(default_factory=lambda: os.environ.get("TG_LIVE_ADMIN_USER", "admin"))
    admin_password_hash: str | None = field(
        default_factory=lambda: secret_env("TG_LIVE_ADMIN_PASSWORD_HASH")
    )
    session_hours: float = field(
        default_factory=lambda: float(os.environ.get("TG_LIVE_SESSION_HOURS", "12"))
    )
    cookie_secure: bool = field(
        default_factory=lambda: os.environ.get("TG_LIVE_COOKIE_SECURE", "true").lower() == "true"
    )
    login_attempts_per_15min: int = field(
        default_factory=lambda: int(os.environ.get("TG_LIVE_LOGIN_ATTEMPTS", "10"))
    )

    def live_config(self) -> LiveConfig:
        return load_live_config(Path(self.config_path) if self.config_path else None)
