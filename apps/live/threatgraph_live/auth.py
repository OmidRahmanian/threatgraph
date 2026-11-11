"""Dashboard authentication: scrypt password hash from the environment, server-side sessions.

- The admin password is never stored in plain text: `threatgraph-live hash-password` prints a
  scrypt hash for `TG_LIVE_ADMIN_PASSWORD_HASH`. Without it, login is disabled.
- Sessions are random 256-bit tokens in an HttpOnly, SameSite=Strict cookie (Secure by
  default); only their SHA-256 is stored, and logout or expiry revokes them server side.
- Login attempts are rate limited per client address.
- State-changing requests also require the `X-TG-Request: 1` header, which a cross-site form
  cannot send (defence in depth on top of SameSite).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time

from threatgraph.live.store import LiveStore, token_hash

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
COOKIE = "tg_live_session"


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("use at least 12 characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(dk)}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        algo, n, r, p, salt, want = encoded.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(
            password.encode(),
            salt=base64.b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(base64.b64decode(want)),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, base64.b64decode(want))


class LoginLimiter:
    def __init__(self, attempts: int, window: float = 900.0) -> None:
        self.attempts, self.window = attempts, window
        self.log: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str, now: float) -> bool:
        with self.lock:
            recent = [t for t in self.log.get(key, []) if now - t < self.window]
            self.log[key] = recent
            if len(self.log) > 10_000:
                self.log.clear()
            return len(recent) < self.attempts

    def failed(self, key: str, now: float) -> None:
        with self.lock:
            self.log.setdefault(key, []).append(now)


def create_session(store: LiveStore, username: str, hours: float) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    with store.tx() as c:
        c.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?)",
            (token_hash(token), username, now, now + hours * 3600),
        )
    return token


def session_user(store: LiveStore, token: str | None) -> str | None:
    if not token:
        return None
    rows = store.query(
        "SELECT username FROM sessions WHERE token_hash = ? AND expires_at > ?",
        (token_hash(token), time.time()),
    )
    return rows[0]["username"] if rows else None


def end_session(store: LiveStore, token: str | None) -> None:
    if token:
        with store.tx() as c:
            c.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
