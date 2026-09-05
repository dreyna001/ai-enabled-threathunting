"""Argon2id local accounts and opaque, revocable browser sessions."""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.engine import Engine

from threat_hunting.services.workflow import sessions, users


SESSION_COOKIE = "threat_hunting_session"
CSRF_COOKIE = "threat_hunting_csrf"
SESSION_TTL = timedelta(hours=8)


def normalize_username(username: str) -> str:
    """Normalize and validate the immutable local account identifier."""

    normalized = " ".join(username.strip().split()).casefold()
    if not normalized or len(normalized) > 100:
        raise ValueError("username must contain 1 to 100 characters")
    if any(ord(char) < 32 for char in normalized):
        raise ValueError("username contains a control character")
    return normalized


@dataclass(frozen=True, slots=True)
class Session:
    """Opaque session material returned only at the login boundary."""

    token: str
    csrf_token: str
    user_id: str
    expires_at: datetime


class LoginRateLimiter:
    """Small process-local login limiter; failed attempts expire automatically."""

    def __init__(self, *, max_failures: int = 5, window: timedelta = timedelta(minutes=15)) -> None:
        self.max_failures = max_failures
        self.window = window
        self._failures: dict[str, list[datetime]] = {}
        self._lock = threading.Lock()

    def allowed(self, key: str, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            recent = [item for item in self._failures.get(key, []) if item + self.window > now]
            self._failures[key] = recent
            return len(recent) < self.max_failures

    def record_failure(self, key: str, *, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            recent = [item for item in self._failures.get(key, []) if item + self.window > now]
            recent.append(now)
            self._failures[key] = recent

    def clear(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


class AccountService:
    """Persistence-backed account creation and session authentication."""

    def __init__(self, engine: Engine, *, session_ttl: timedelta = SESSION_TTL, limiter: LoginRateLimiter | None = None) -> None:
        self.engine = engine
        self.session_ttl = session_ttl
        self.password_hasher = PasswordHasher()
        self.limiter = limiter or LoginRateLimiter()

    def create_account(self, username: str, password: str, *, display_name: str | None = None) -> dict[str, str]:
        normalized = normalize_username(username)
        if not password or len(password) > 200:
            raise ValueError("password must contain 1 to 200 characters")
        public = {"user_id": str(uuid4()), "username": normalized, "display_name": (display_name or normalized)[:200], "password_hash": self.password_hasher.hash(password)}
        with self.engine.begin() as connection:
            connection.execute(users.insert().values(**public))
        return {key: value for key, value in public.items() if key != "password_hash"}

    def login(self, username: str, password: str, *, client_key: str = "unknown") -> tuple[Session, dict[str, Any]]:
        normalized = normalize_username(username)
        key = f"{client_key}:{normalized}"
        if not self.limiter.allowed(key):
            raise PermissionError("too many login attempts; try again later")
        with self.engine.connect() as connection:
            user = connection.execute(select(users).where(users.c.username == normalized)).mappings().first()
        if user is None:
            self.limiter.record_failure(key)
            raise ValueError("invalid username or password")
        try:
            self.password_hasher.verify(str(user["password_hash"]), password)
        except (VerifyMismatchError, VerificationError):
            self.limiter.record_failure(key)
            raise ValueError("invalid username or password") from None
        self.limiter.clear(key)
        now = datetime.now(timezone.utc)
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        with self.engine.begin() as connection:
            connection.execute(sessions.insert().values(token_hash=_hash(token), user_id=user["user_id"], csrf_hash=_hash(csrf), expires_at_utc=now + self.session_ttl))
        return Session(token, csrf, str(user["user_id"]), now + self.session_ttl), {key: value for key, value in user.items() if key != "password_hash"}

    def authenticate(self, token: str, *, csrf_token: str | None = None) -> str:
        with self.engine.connect() as connection:
            row = connection.execute(select(sessions).where(sessions.c.token_hash == _hash(token))).mappings().first()
        if row is None:
            raise ValueError("invalid or expired session")
        expires = row["expires_at_utc"]
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= datetime.now(timezone.utc):
            raise ValueError("invalid or expired session")
        if csrf_token is not None and _hash(csrf_token) != row.get("csrf_hash"):
            raise PermissionError("CSRF validation failed")
        return str(row["user_id"])

    def logout(self, token: str) -> None:
        with self.engine.begin() as connection:
            connection.execute(sessions.delete().where(sessions.c.token_hash == _hash(token)))


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = ["AccountService", "CSRF_COOKIE", "LoginRateLimiter", "SESSION_COOKIE", "SESSION_TTL", "Session", "normalize_username"]
