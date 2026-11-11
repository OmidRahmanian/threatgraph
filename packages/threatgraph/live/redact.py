"""Privacy and safety filters applied by the agent *before* anything leaves the server.

Standard library only. Logs are untrusted text: they can carry credentials (query strings,
Authorization headers), personal data (client IPs) and attacker-chosen content (terminal
escape sequences, fake log lines, instructions aimed at an LLM). These helpers:

- strip control characters and ANSI escapes, and cap lengths;
- redact common secret shapes (passwords, tokens, API keys, bearer/basic auth, JWTs,
  private-key blocks, AWS access keys);
- drop URL query strings by default (they often hold tokens);
- optionally pseudonymize client IPs (`truncate` keeps the /24 or /48 network, `hash` keeps a
  keyed hash so repeated sources still correlate without storing the address).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

IpMode = Literal["keep", "truncate", "hash"]

_CONTROL = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|[\x00-\x08\x0b-\x1f\x7f]")
_SECRETS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(r"(?i)\b(authorization\s*[:=]\s*)(bearer|basic|token)\s+[^\s,;\"']+"),
        r"\1\2 [REDACTED]",
    ),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED]"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "[REDACTED_JWT]",
    ),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED_AWS_KEY]"),
    (
        re.compile(
            r"(?i)\b(pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|auth|session(id)?|"
            r"client[_-]?secret|private[_-]?key)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&,;\"']+)"
        ),
        r"\1\4[REDACTED]",
    ),
    (re.compile(r"(?i)\b(https?://)([^/\s:@]+):([^/\s@]+)@"), r"\1[REDACTED]@"),
]


def clean_text(text: str, limit: int = 512) -> str:
    """Remove terminal escapes and control characters, then cap the length."""
    text = _CONTROL.sub("", text)
    return text if len(text) <= limit else text[:limit] + "…"


def redact_secrets(text: str) -> str:
    for pattern, repl in _SECRETS:
        text = pattern.sub(repl, text)
    return text


def sanitize(text: str | None, limit: int = 512) -> str | None:
    if text is None:
        return None
    return clean_text(redact_secrets(text), limit)


def strip_query(target: str, keep_query: bool = False) -> str:
    """Request target without its query string (or with secrets in it redacted)."""
    path, sep, query = target.partition("?")
    if not sep:
        return path
    return f"{path}?{redact_secrets(query)}" if keep_query else f"{path}?[query removed]"


@dataclass(frozen=True)
class PrivacyPolicy:
    ip_mode: IpMode = "keep"
    ip_hash_key: str = ""
    keep_query: bool = False
    max_path: int = 256
    max_user_agent: int = 160
    max_message: int = 512

    def ip(self, addr: str | None) -> str | None:
        if not addr:
            return None
        if self.ip_mode == "keep":
            return clean_text(addr, 64)
        try:
            ip = ipaddress.ip_address(addr.strip())
        except ValueError:
            return "[invalid-ip]"
        if self.ip_mode == "truncate":
            prefix = 24 if ip.version == 4 else 48
            return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
        if not self.ip_hash_key:
            raise ValueError("ip_mode=hash needs ip_hash_key (keep it secret)")
        digest = hmac.new(self.ip_hash_key.encode(), ip.packed, hashlib.sha256).hexdigest()
        return f"ip-{digest[:16]}"

    def path(self, target: str | None) -> str | None:
        if target is None:
            return None
        return clean_text(strip_query(target, self.keep_query), self.max_path)

    def user_agent(self, ua: str | None) -> str | None:
        return None if ua is None else clean_text(ua, self.max_user_agent)

    def message(self, text: str | None) -> str | None:
        return sanitize(text, self.max_message)
