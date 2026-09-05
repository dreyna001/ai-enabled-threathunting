from __future__ import annotations

from datetime import timedelta

import pytest
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from threat_hunting.api.workflow import _login_client_key
from threat_hunting.auth.service import AccountService, LoginRateLimiter
from threat_hunting.services.workflow import workflow_metadata


def _engine():
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    workflow_metadata.create_all(engine)
    return engine


def test_client_limit_persists_across_service_instances() -> None:
    engine = _engine()
    first = AccountService(
        engine,
        limiter=LoginRateLimiter(
            engine,
            max_client_failures=2,
            max_account_failures=10,
            window=timedelta(minutes=15),
        ),
    )
    first.create_account("analyst", "correct-password")
    for _ in range(2):
        with pytest.raises(ValueError, match="invalid username or password"):
            first.login("analyst", "wrong-password", client_key="192.0.2.10")

    replacement = AccountService(
        engine,
        limiter=LoginRateLimiter(
            engine,
            max_client_failures=2,
            max_account_failures=10,
            window=timedelta(minutes=15),
        ),
    )

    with pytest.raises(PermissionError, match="too many login attempts"):
        replacement.login("analyst", "correct-password", client_key="192.0.2.10")
    session, _ = replacement.login(
        "analyst", "correct-password", client_key="192.0.2.11"
    )
    assert session.user_id


def test_account_limit_aggregates_failures_across_clients() -> None:
    engine = _engine()
    limiter = LoginRateLimiter(
        engine,
        max_client_failures=2,
        max_account_failures=3,
        window=timedelta(minutes=15),
    )
    service = AccountService(engine, limiter=limiter)
    service.create_account("analyst", "correct-password")
    for index in range(3):
        with pytest.raises(ValueError, match="invalid username or password"):
            service.login(
                "analyst",
                "wrong-password",
                client_key=f"192.0.2.{index + 1}",
            )

    with pytest.raises(PermissionError, match="too many login attempts"):
        service.login("analyst", "correct-password", client_key="192.0.2.50")


def test_unknown_user_runs_dummy_argon2_verification() -> None:
    engine = _engine()
    service = AccountService(engine)
    calls: list[tuple[str, str]] = []

    class ProbeHasher:
        def verify(self, encoded: str, password: str) -> None:
            calls.append((encoded, password))
            raise VerifyMismatchError

    service.password_hasher = ProbeHasher()  # type: ignore[assignment]

    with pytest.raises(ValueError, match="invalid username or password"):
        service.login("missing", "supplied-password", client_key="192.0.2.10")

    assert calls == [(service._dummy_password_hash, "supplied-password")]


def test_login_client_key_accepts_only_valid_proxy_address() -> None:
    proxy_request = Request(
        {
            "type": "http",
            "headers": [(b"x-real-ip", b"2001:db8::1")],
            "client": ("127.0.0.1", 1234),
        }
    )
    invalid_proxy_request = Request(
        {
            "type": "http",
            "headers": [(b"x-real-ip", b"not-an-address")],
            "client": ("192.0.2.20", 1234),
        }
    )

    assert _login_client_key(proxy_request) == "2001:db8::1"
    assert _login_client_key(invalid_proxy_request) == "192.0.2.20"
