"""Notification channels: Telegram Bot API and SMTP e-mail. Standard library only, so the
external probe can alert directly even when the ThreatGraph server is unreachable."""

from __future__ import annotations

import json
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol


class DeliveryError(Exception):
    pass


class Channel(Protocol):
    name: str

    def send(self, subject: str, body: str) -> None: ...


# --------------------------------------------------------------------------- channels
@dataclass
class TelegramChannel:
    token: str
    chat_id: str
    api_base: str = "https://api.telegram.org"
    timeout: float = 15.0
    name: str = "telegram"

    def send(self, subject: str, body: str) -> None:
        url = f"{self.api_base.rstrip('/')}/bot{self.token}/sendMessage"
        text = body if len(body) <= 4000 else body[:3990] + "\n…"
        data = json.dumps(
            {"chat_id": self.chat_id, "text": text, "disable_web_page_preview": True}
        ).encode()
        req = urllib.request.Request(
            url, data=data, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            # Never include the URL (it contains the bot token) in stored errors.
            raise DeliveryError(f"telegram HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise DeliveryError(f"telegram unreachable: {type(exc).__name__}") from None
        if not resp.get("ok"):
            raise DeliveryError(f"telegram error: {str(resp.get('description'))[:120]}")


@dataclass
class EmailChannel:
    host: str
    port: int
    sender: str
    recipients: list[str]
    username: str | None = None
    password: str | None = None
    security: str = "starttls"  # starttls | ssl | none (none only for a local relay)
    timeout: float = 20.0
    name: str = "email"

    def send(self, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject.replace("\n", " ")[:200]
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(body)
        ctx = ssl.create_default_context()
        try:
            if self.security == "ssl":
                smtp: smtplib.SMTP = smtplib.SMTP_SSL(
                    self.host, self.port, timeout=self.timeout, context=ctx
                )
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            with smtp:
                if self.security == "starttls":
                    smtp.starttls(context=ctx)
                if self.username and self.password:
                    smtp.login(self.username, self.password)
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise DeliveryError(f"smtp: {type(exc).__name__}: {str(exc)[:120]}") from None
