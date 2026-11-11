"""Notification delivery: Telegram Bot API and SMTP e-mail, from a persistent outbox.

The incident manager queues rows in `notifications`; `deliver_due` sends the ones that are
due, retries failures with exponential backoff (`retry_base_seconds` · 2^attempt, capped) and
marks a row `failed` after `max_attempts`. Every attempt's outcome is stored, so delivery
status is visible in the dashboard. Credentials come from the environment only.

Message text is built from stored incident fields, which come from real events (or from
clearly labeled test fixtures, which carry a SIMULATED banner).
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any

from threatgraph.live.channels import Channel, DeliveryError, EmailChannel, TelegramChannel
from threatgraph.live.config import LiveConfig, secret_env
from threatgraph.live.store import LiveStore

__all__ = [
    "Channel",
    "DeliveryError",
    "EmailChannel",
    "TelegramChannel",
    "channels_from_env",
    "deliver_due",
    "format_message",
    "send_test",
]

ASSESSMENT_TEXT = {
    "unusual": "Unusual behaviour. No malicious intent or compromise is established.",
    "suspected_malicious": "Pattern typical of hostile activity. No confirmed compromise.",
    "confirmed": "Confirmed by an analyst.",
}
KIND_TEXT = {
    "alert": "Security Alert",
    "escalation": "Alert Escalated",
    "reminder": "Ongoing Incident",
    "recovery": "Recovered",
    "test": "Test Notification",
}


def _ts(t: float | None) -> str:
    return (
        "unknown" if t is None else datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    )


def format_message(inc: dict[str, Any], kind: str, cfg: LiveConfig) -> tuple[str, str]:
    """(subject, plain-text body) for one incident notification."""
    service = cfg.service_name(inc.get("service"))
    sev = str(inc["severity"]).upper()
    banner = "[SIMULATED TEST: not real telemetry] " if inc.get("simulated") else ""
    if kind == "recovery":
        subject = f"{banner}ThreatGraph AI · Recovered: {inc['title']} · {service}"
        lines = [
            f"{banner}ThreatGraph AI · Recovered",
            "",
            f"Service: {service}",
            f"Incident: {inc['title']}",
            f"Started: {_ts(inc['first_seen'])}",
            f"Recovered: {_ts(inc.get('resolved_at'))}",
            f"Duration: {_duration((inc.get('resolved_at') or time.time()) - inc['first_seen'])}",
            "",
            f"Incident ID: {inc['id']}",
        ]
    else:
        subject = f"{banner}ThreatGraph AI · {sev} · {inc['title']} · {service}"
        evidence = (
            inc["evidence"] if isinstance(inc["evidence"], list) else json.loads(inc["evidence"])
        )
        lines = [
            f"{banner}ThreatGraph AI {KIND_TEXT.get(kind, 'Security Alert')}",
            "",
            f"Severity: {sev}",
            f"Service: {service}" + (f" ({inc['source_id']})" if inc.get("source_id") else ""),
            f"Detection: {inc['title']}",
            f"Time: {_ts(inc['detected_at'])}",
            f"Detector: {inc['detector']} / {inc['rule_id']}",
            "",
            "Evidence:",
            *[f"- {e}" for e in evidence],
            "",
            "Assessment:",
            ASSESSMENT_TEXT.get(inc["assessment"], inc["assessment"]),
            f"Confidence: {inc['confidence']}",
            f"Limitations: {inc['limitations']}",
            "",
            "Recommended action:",
            inc["recommended_action"],
        ]
        if kind == "reminder":
            lines += [
                "",
                f"Still open: seen {inc['occurrences']} times, last at {_ts(inc['last_seen'])}.",
            ]
        lines += ["", f"Incident ID: {inc['id']}"]
    if cfg.notifications.dashboard_url:
        lines.append(f"Dashboard: {cfg.notifications.dashboard_url}")
    return subject, "\n".join(lines)


def _duration(s: float) -> str:
    s = max(0, int(s))
    h, rem = divmod(s, 3600)
    return f"{h} h {rem // 60} min" if h else f"{rem // 60} min {rem % 60} s"


def channels_from_env() -> list[Channel]:
    """Channels whose credentials are present in the environment (or *_FILE secrets)."""
    out: list[Channel] = []
    tok, chat = secret_env("TG_TELEGRAM_BOT_TOKEN"), secret_env("TG_TELEGRAM_CHAT_ID")
    if tok and chat:
        out.append(
            TelegramChannel(
                tok, chat, api_base=secret_env("TG_TELEGRAM_API_BASE") or "https://api.telegram.org"
            )
        )
    host, to = secret_env("TG_SMTP_HOST"), secret_env("TG_SMTP_TO")
    if host and to:
        out.append(
            EmailChannel(
                host=host,
                port=int(secret_env("TG_SMTP_PORT") or 587),
                sender=secret_env("TG_SMTP_FROM") or "threatgraph@localhost",
                recipients=[a.strip() for a in to.split(",") if a.strip()],
                username=secret_env("TG_SMTP_USER"),
                password=secret_env("TG_SMTP_PASSWORD"),
                security=secret_env("TG_SMTP_SECURITY") or "starttls",
            )
        )
    return out


# --------------------------------------------------------------------------- delivery
def deliver_due(
    store: LiveStore, channels: list[Channel], cfg: LiveConfig, now: float | None = None
) -> dict[str, int]:
    now = time.time() if now is None else now
    by_name = {c.name: c for c in channels}
    n = cfg.notifications
    stats = {"sent": 0, "retry": 0, "failed": 0}
    due = store.query(
        "SELECT n.*, i.id AS inc FROM notifications n LEFT JOIN incidents i ON i.id = n.incident_id "
        "WHERE n.status = 'pending' AND n.next_attempt_at <= ? ORDER BY n.id LIMIT 100",
        (now,),
    )
    for row in due:
        inc = store.query("SELECT * FROM incidents WHERE id = ?", (row["incident_id"],))
        channel = by_name.get(row["channel"])
        if not inc or channel is None:
            why = "incident no longer exists" if not inc else "channel not configured"
            _mark(store, row["id"], "failed", row["attempts"], now, why)
            stats["failed"] += 1
            continue
        subject, body = format_message(inc[0], row["kind"], cfg)
        try:
            channel.send(subject, body)
        except DeliveryError as exc:
            attempts = row["attempts"] + 1
            if attempts >= n.max_attempts:
                _mark(store, row["id"], "failed", attempts, now, str(exc), subject, body)
                stats["failed"] += 1
            else:
                delay = min(n.retry_max_seconds, n.retry_base_seconds * 2 ** (attempts - 1))
                _mark(store, row["id"], "pending", attempts, now + delay, str(exc), subject, body)
                stats["retry"] += 1
            continue
        with store.tx() as c:
            c.execute(
                "UPDATE notifications SET status = 'sent', attempts = attempts + 1, sent_at = ?, "
                "last_error = NULL, subject = ?, body = ? WHERE id = ?",
                (now, subject, body, row["id"]),
            )
        stats["sent"] += 1
    return stats


def _mark(
    store: LiveStore,
    nid: int,
    status: str,
    attempts: int,
    next_at: float,
    error: str,
    subject: str = "",
    body: str = "",
) -> None:
    with store.tx() as c:
        c.execute(
            "UPDATE notifications SET status = ?, attempts = ?, next_attempt_at = ?, "
            "last_error = ?, subject = COALESCE(NULLIF(?, ''), subject), "
            "body = COALESCE(NULLIF(?, ''), body) WHERE id = ?",
            (status, attempts, next_at, error[:300], subject, body, nid),
        )


def send_test(channels: list[Channel]) -> dict[str, str]:
    """Send a clearly labeled test message to every configured channel (operator command)."""
    out = {}
    body = (
        "ThreatGraph AI Test Notification\n\nThis is a test of the notification channel. "
        "It is not based on any event and does not indicate an incident."
    )
    for c in channels:
        try:
            c.send("ThreatGraph AI · Test notification (no incident)", body)
            out[c.name] = "sent"
        except DeliveryError as exc:
            out[c.name] = f"failed: {exc}"
    return out
