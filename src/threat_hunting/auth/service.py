"""Argon2id local accounts and opaque, revocable browser sessions."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from sqlalchemy import case, delete, select
from sqlalchemy.engine import Engine
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from threat_hunting.services.workflow import login_rate_limits, sessions, users

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
    """Persistent client-and-account login failure limiter."""

    def __init__(
        self,
        engine: Engine,
        *,
        max_client_failures: int = 5,
        max_account_failures: int = 25,
        window: timedelta = timedelta(minutes=15),
    ) -> None:
        if max_client_failures <= 0 or max_account_failures < max_client_failures:
            raise ValueError("login rate limits are invalid")
        self.engine = engine
        self.max_client_failures = max_client_failures
        self.max_account_failures = max_account_failures
        self.window = window

    @staticmethod
    def _bucket_hash(dimension: str, value: str) -> str:
        return hashlib.sha256(f"{dimension}:{value}".encode("utf-8")).hexdigest()

    def _buckets(self, username: str, client_key: str) -> tuple[tuple[str, int], ...]:
        client = client_key or "unknown"
        return (
            (self._bucket_hash("account", username), self.max_account_failures),
            (self._bucket_hash("client", client), self.max_client_failures),
        )

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

    def _cleanup(self, connection: Any, *, now: datetime) -> None:
        cutoff = now - self.window
        connection.execute(
            delete(login_rate_limits).where(
                login_rate_limits.c.updated_at_utc <= cutoff,
                (login_rate_limits.c.blocked_until_utc.is_(None))
                | (login_rate_limits.c.blocked_until_utc <= now),
            )
        )

    def allowed(self, username: str, client_key: str, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        hashes = [bucket_hash for bucket_hash, _ in self._buckets(username, client_key)]
        with self.engine.begin() as connection:
            self._cleanup(connection, now=now)
            rows = connection.execute(
                select(login_rate_limits.c.blocked_until_utc).where(
                    login_rate_limits.c.bucket_hash.in_(hashes)
                )
            ).scalars().all()
        return not any(value is not None and self._as_utc(value) > now for value in rows)

    def _record_bucket(
        self, connection: Any, *, bucket_hash: str, max_failures: int, now: datetime
    ) -> None:
        if connection.dialect.name == "postgresql":
            insert = postgresql_insert
        elif connection.dialect.name == "sqlite":
            insert = sqlite_insert
        else:
            raise RuntimeError("login rate limiting requires PostgreSQL or SQLite")
        cutoff = now - self.window
        blocked_until = now + self.window
        expired = login_rate_limits.c.window_started_at_utc <= cutoff
        next_count = case((expired, 1), else_=login_rate_limits.c.failure_count + 1)
        next_block = case(
            (expired, blocked_until if max_failures == 1 else None),
            (login_rate_limits.c.failure_count + 1 >= max_failures, blocked_until),
            else_=login_rate_limits.c.blocked_until_utc,
        )
        statement = insert(login_rate_limits).values(
            bucket_hash=bucket_hash,
            failure_count=1,
            window_started_at_utc=now,
            blocked_until_utc=blocked_until if max_failures == 1 else None,
            updated_at_utc=now,
        )
        connection.execute(
            statement.on_conflict_do_update(
                index_elements=[login_rate_limits.c.bucket_hash],
                set_={
                    "failure_count": next_count,
                    "window_started_at_utc": case(
                        (expired, now), else_=login_rate_limits.c.window_started_at_utc
                    ),
                    "blocked_until_utc": next_block,
                    "updated_at_utc": now,
                },
            )
        )

    def record_failure(
        self, username: str, client_key: str, *, now: datetime | None = None
    ) -> None:
        now = now or datetime.now(timezone.utc)
        with self.engine.begin() as connection:
            self._cleanup(connection, now=now)
            for bucket_hash, max_failures in self._buckets(username, client_key):
                self._record_bucket(
                    connection,
                    bucket_hash=bucket_hash,
                    max_failures=max_failures,
                    now=now,
                )

    def clear(self, username: str, client_key: str) -> None:
        hashes = [bucket_hash for bucket_hash, _ in self._buckets(username, client_key)]
        with self.engine.begin() as connection:
            connection.execute(
                delete(login_rate_limits).where(login_rate_limits.c.bucket_hash.in_(hashes))
            )

class AccountService:
    """Persistence-backed account creation and session authentication."""

    def __init__(self, engine: Engine, *, session_ttl: timedelta = SESSION_TTL, limiter: LoginRateLimiter | None = None) -> None:
        self.engine = engine
        self.session_ttl = session_ttl
        self.password_hasher = PasswordHasher()
        self.limiter = limiter or LoginRateLimiter(engine)
        self._dummy_password_hash = self.password_hasher.hash(secrets.token_urlsafe(32))

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
        if not self.limiter.allowed(normalized, client_key):
            raise PermissionError("too many login attempts; try again later")
        with self.engine.connect() as connection:
            user = connection.execute(select(users).where(users.c.username == normalized)).mappings().first()
        if user is None:
            try:
                self.password_hasher.verify(self._dummy_password_hash, password)
            except (VerifyMismatchError, VerificationError):
                pass
            self.limiter.record_failure(normalized, client_key)
            raise ValueError("invalid username or password")
        try:
            self.password_hasher.verify(str(user["password_hash"]), password)
        except (VerifyMismatchError, VerificationError):
            self.limiter.record_failure(normalized, client_key)
            raise ValueError("invalid username or password") from None
        self.limiter.clear(normalized, client_key)
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
