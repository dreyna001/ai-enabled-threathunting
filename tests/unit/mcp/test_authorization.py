"""Focused database authorization tests for the MCP execution boundary."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, MetaData, String, Table, create_engine

from threat_hunting.db import action_digest
from threat_hunting.mcp.authorization import (
    AuthorizationCode,
    AuthorizationDenied,
    MCPToolRequest,
    ReplayStatus,
    authorize_mcp_tool_request,
    check_mcp_request_replay,
    reserve_mcp_request,
)


NOW = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


@pytest.fixture()
def database() -> tuple[object, dict[str, Table], dict[str, str]]:
    """Create a small SQLite representation of the persisted auth graph."""

    metadata = MetaData()

    def table(name: str, *columns: Column[str | int | bool | dict[str, object]]) -> Table:
        return Table(name, metadata, *columns)

    tables = {
        "execution_jobs": table(
            "execution_jobs",
            Column("job_id", String, primary_key=True),
            Column("execution_id", String, nullable=False),
            Column("hunt_id", String, nullable=False),
            Column("deployment_scope_id", String, nullable=False),
            Column("worker_id", String, nullable=False),
            Column("lease_expires_at_utc", DateTime(timezone=True), nullable=False),
            Column("status", String, nullable=False),
        ),
        "hunt_executions": table(
            "hunt_executions",
            Column("execution_id", String, primary_key=True),
            Column("hunt_id", String, nullable=False),
            Column("deployment_scope_id", String, nullable=False),
            Column("status", String, nullable=False),
            Column("policy_version", String, nullable=False),
            Column("policy_hash", String, nullable=False),
            Column("expires_at_utc", DateTime(timezone=True), nullable=False),
        ),
        "hunts": table(
            "hunts",
            Column("hunt_id", String, primary_key=True),
            Column("owner_id", String, nullable=False),
            Column("deployment_scope_id", String, nullable=False),
            Column("status", String, nullable=False),
        ),
        "plan_approvals": table(
            "plan_approvals",
            Column("approval_id", String, primary_key=True),
            Column("hunt_id", String, nullable=False),
            Column("plan_id", String, nullable=False),
            Column("plan_version", Integer, nullable=False),
            Column("plan_sha256", String, nullable=False),
            Column("execution_config_snapshot_id", String, nullable=False),
            Column("execution_config_sha256", String, nullable=False),
            Column("deployment_scope_id", String, nullable=False),
            Column("status", String, nullable=False),
        ),
        "plans": table(
            "plans",
            Column("plan_id", String, primary_key=True),
            Column("hunt_id", String, nullable=False),
            Column("plan_version", Integer, nullable=False),
            Column("plan_sha256", String, nullable=False),
            Column("execution_config_snapshot_id", String, nullable=False),
            Column("discovery_snapshot_id", String, nullable=False),
            Column("deployment_scope_id", String, nullable=False),
        ),
        "execution_config_snapshots": table(
            "execution_config_snapshots",
            Column("execution_config_snapshot_id", String, primary_key=True),
            Column("execution_config_sha256", String, nullable=False),
            Column("deployment_scope_id", String, nullable=False),
            Column("policy_version", String, nullable=False),
            Column("policy_hash", String, nullable=False),
            Column("status", String, nullable=False),
        ),
        "discovery_snapshots": table(
            "discovery_snapshots",
            Column("discovery_snapshot_id", String, primary_key=True),
            Column("hunt_id", String, nullable=False),
            Column("deployment_scope_id", String, nullable=False),
            Column("policy_version", String, nullable=False),
            Column("policy_hash", String, nullable=False),
        ),
        "query_ledger": table(
            "query_ledger",
            Column("query_id", String, primary_key=True),
            Column("hunt_id", String, nullable=False),
            Column("execution_id", String, nullable=False),
            Column("approval_id", String, nullable=False),
            Column("deployment_scope_id", String, nullable=False),
            Column("question_id", String, nullable=False),
            Column("purpose", String, nullable=False),
            Column("expected_information_gain", String, nullable=False),
            Column("query_sha256", String, nullable=False),
            Column("policy_version", String, nullable=False),
            Column("policy_hash", String, nullable=False),
            Column("scope", JSON, nullable=False),
            Column("limits", JSON, nullable=False),
            Column("status", String, nullable=False),
        ),
        "mcp_tool_requests": table(
            "mcp_tool_requests",
            Column("request_id", String, primary_key=True),
            Column("authenticated_subject", String, nullable=False),
            Column("idempotency_key", String, nullable=False),
            Column("action_digest", String, nullable=False),
            Column("tool", String, nullable=False),
            Column("status", String, nullable=False),
            Column("deployment_scope_id", String, nullable=False),
            Column("hunt_id", String, nullable=False),
            Column("execution_id", String),
            Column("query_id", String),
            Column("approval_id", String, nullable=False),
            Column("execution_config_snapshot_id", String, nullable=False),
            Column("deterministic_sid", String, nullable=False),
            Column("created_at_utc", DateTime(timezone=True), nullable=False),
            Column("updated_at_utc", DateTime(timezone=True), nullable=False),
        ),
        "execution_authorization_revocations": table(
            "execution_authorization_revocations",
            Column("revocation_id", String, primary_key=True),
            Column("deployment_scope_id", String, nullable=False),
            Column("execution_id", String),
            Column("hunt_id", String, nullable=False),
            Column("approval_id", String, nullable=False),
            Column("reason_code", String, nullable=False),
            Column("revoked_by_subject", String, nullable=False),
            Column("revoked_at_utc", DateTime(timezone=True), nullable=False),
        ),
        "audit_records": table(
            "audit_records",
            Column("audit_id", String, primary_key=True),
            Column("hunt_id", String),
            Column("request_id", String),
            Column("actor_type", String, nullable=False),
            Column("actor_id", String),
            Column("action", String, nullable=False),
            Column("object_type", String),
            Column("object_id", String),
            Column("outcome", String, nullable=False),
            Column("detail", String),
            Column("timestamp_utc", DateTime(timezone=True), nullable=False),
        ),
    }
    engine = create_engine("sqlite://")
    metadata.create_all(engine)
    ids = {name: str(uuid4()) for name in ("job", "execution", "hunt", "approval", "plan", "config", "discovery", "query")}
    scope = {
        "earliest_utc": "2025-12-01T00:00:00+00:00",
        "latest_utc": "2025-12-31T23:59:59+00:00",
        "indexes": ["main"],
        "sourcetypes": ["sysmon"],
    }
    policy_hash = "d" * 64
    with engine.begin() as conn:
        conn.execute(tables["execution_jobs"].insert(), {"job_id": ids["job"], "execution_id": ids["execution"], "hunt_id": ids["hunt"], "deployment_scope_id": "customer-a", "worker_id": "worker-a", "lease_expires_at_utc": NOW + timedelta(minutes=10), "status": "claimed"})
        conn.execute(tables["hunt_executions"].insert(), {"execution_id": ids["execution"], "hunt_id": ids["hunt"], "deployment_scope_id": "customer-a", "status": "running", "policy_version": "policy-1", "policy_hash": policy_hash, "expires_at_utc": NOW + timedelta(hours=1)})
        conn.execute(tables["hunts"].insert(), {"hunt_id": ids["hunt"], "owner_id": "analyst-a", "deployment_scope_id": "customer-a", "status": "investigating"})
        conn.execute(tables["plan_approvals"].insert(), {"approval_id": ids["approval"], "hunt_id": ids["hunt"], "plan_id": ids["plan"], "plan_version": 2, "plan_sha256": "a" * 64, "execution_config_snapshot_id": ids["config"], "execution_config_sha256": "b" * 64, "deployment_scope_id": "customer-a", "status": "approved"})
        conn.execute(tables["plans"].insert(), {"plan_id": ids["plan"], "hunt_id": ids["hunt"], "plan_version": 2, "plan_sha256": "a" * 64, "execution_config_snapshot_id": ids["config"], "discovery_snapshot_id": ids["discovery"], "deployment_scope_id": "customer-a"})
        conn.execute(tables["execution_config_snapshots"].insert(), {"execution_config_snapshot_id": ids["config"], "execution_config_sha256": "b" * 64, "deployment_scope_id": "customer-a", "policy_version": "policy-1", "policy_hash": policy_hash, "status": "active"})
        conn.execute(tables["discovery_snapshots"].insert(), {"discovery_snapshot_id": ids["discovery"], "hunt_id": ids["hunt"], "deployment_scope_id": "customer-a", "policy_version": "policy-1", "policy_hash": policy_hash})
        conn.execute(tables["query_ledger"].insert(), {"query_id": ids["query"], "hunt_id": ids["hunt"], "execution_id": ids["execution"], "approval_id": ids["approval"], "deployment_scope_id": "customer-a", "question_id": "q1", "purpose": "find process", "expected_information_gain": "high", "query_sha256": "c" * 64, "policy_version": "policy-1", "policy_hash": policy_hash, "scope": scope, "limits": {"max_results": 100, "max_bytes": 10000, "timeout_seconds": 30}, "status": "validated"})
    return engine, tables, ids


def _request(ids: dict[str, str], **updates: object) -> MCPToolRequest:
    """Build a complete generic assertion envelope."""

    values: dict[str, object] = {
        "request_id": "req-1",
        "tool": "generic_spl",
        "authenticated_subject": "worker/customer-a",
        "worker_id": "worker-a",
        "idempotency_key": "idem-1",
        "action_digest": "e" * 64,
        "deployment_scope_id": "customer-a",
        "hunt_id": ids["hunt"],
        "execution_id": ids["execution"],
        "approval_id": ids["approval"],
        "plan_id": ids["plan"],
        "plan_version": 2,
        "plan_sha256": "a" * 64,
        "execution_config_snapshot_id": ids["config"],
        "execution_config_sha256": "b" * 64,
        "discovery_snapshot_id": ids["discovery"],
        "query_id": ids["query"],
        "query_sha256": "c" * 64,
        "question_id": "q1",
        "purpose": "find process",
        "expected_information_gain": "high",
        "earliest_utc": "2025-12-01T00:00:00Z",
        "latest_utc": "2025-12-31T23:59:59Z",
        "indexes": ["main"],
        "sourcetypes": ["sysmon"],
        "max_results": 100,
        "max_bytes": 10000,
        "timeout_seconds": 30,
        "policy_version": "policy-1",
        "policy_hash": "d" * 64,
    }
    values.update(updates)
    return MCPToolRequest.model_validate(values)


def _authorize(engine: object, request: MCPToolRequest) -> object:
    return authorize_mcp_tool_request(engine, request, configured_service_subject="worker/customer-a", envelope_worker_id="worker-a", now=NOW)


def test_valid_generic_request_returns_frozen_server_context(database: tuple[object, dict[str, Table], dict[str, str]]) -> None:
    engine, _, ids = database
    result = _authorize(engine, _request(ids))
    assert result.owner_id == "analyst-a"
    assert result.scope["indexes"] == ["main"]
    with pytest.raises(TypeError):
        result.scope["indexes"] = ["other"]  # type: ignore[index]


@pytest.mark.parametrize(
    ("updates", "code"),
    [
        ({"authenticated_subject": "worker/customer-b"}, AuthorizationCode.UNAUTHENTICATED_SUBJECT),
        ({"hunt_id": str(uuid4())}, AuthorizationCode.HUNT_MISMATCH),
        ({"plan_sha256": "f" * 64}, AuthorizationCode.HASH_MISMATCH),
        ({"worker_id": "worker-b"}, AuthorizationCode.LEASE_OWNER_MISMATCH),
        ({"deployment_scope_id": "customer-b"}, AuthorizationCode.DEPLOYMENT_SCOPE_MISMATCH),
    ],
)
def test_assertion_mismatches_are_denied(
    database: tuple[object, dict[str, Table], dict[str, str]], updates: dict[str, object], code: AuthorizationCode
) -> None:
    engine, _, ids = database
    with pytest.raises(AuthorizationDenied) as error:
        _authorize(engine, _request(ids, **updates))
    assert error.value.code is code


def test_expired_lease_cancelled_execution_and_revocation_are_denied(database: tuple[object, dict[str, Table], dict[str, str]]) -> None:
    engine, tables, ids = database
    with engine.begin() as conn:
        conn.execute(tables["execution_jobs"].update().values(lease_expires_at_utc=NOW - timedelta(seconds=1)).where(tables["execution_jobs"].c.job_id == ids["job"]))
    with pytest.raises(AuthorizationDenied) as error:
        _authorize(engine, _request(ids))
    assert error.value.code is AuthorizationCode.LEASE_EXPIRED
    with engine.begin() as conn:
        conn.execute(tables["execution_jobs"].update().values(lease_expires_at_utc=NOW + timedelta(minutes=10)).where(tables["execution_jobs"].c.job_id == ids["job"]))
        conn.execute(tables["hunts"].update().values(status="cancelled").where(tables["hunts"].c.hunt_id == ids["hunt"]))
    with pytest.raises(AuthorizationDenied) as error:
        _authorize(engine, _request(ids))
    assert error.value.code is AuthorizationCode.EXECUTION_CANCELLED
    with engine.begin() as conn:
        conn.execute(tables["hunts"].update().values(status="investigating").where(tables["hunts"].c.hunt_id == ids["hunt"]))
        conn.execute(tables["execution_authorization_revocations"].insert(), {"revocation_id": str(uuid4()), "deployment_scope_id": "customer-a", "execution_id": ids["execution"], "hunt_id": ids["hunt"], "approval_id": ids["approval"], "reason_code": "manual", "revoked_by_subject": "analyst-a", "revoked_at_utc": NOW})
    with pytest.raises(AuthorizationDenied) as error:
        _authorize(engine, _request(ids))
    assert error.value.code is AuthorizationCode.AUTHORIZATION_REVOKED


def test_replay_exact_digest_and_conflict_are_distinct(database: tuple[object, dict[str, Table], dict[str, str]]) -> None:
    engine, _, ids = database
    request = _request(ids, action_digest="1" * 64)
    reserved = reserve_mcp_request(engine, request, now=NOW)
    assert reserved.status is ReplayStatus.NEW
    assert check_mcp_request_replay(engine, request).status is ReplayStatus.REPLAY
    conflicting = _request(ids, request_id="req-2", action_digest="2" * 64)
    with pytest.raises(AuthorizationDenied) as error:
        reserve_mcp_request(engine, conflicting, now=NOW)
    assert error.value.code is AuthorizationCode.REPLAY_CONFLICT


def test_semantic_request_requires_selected_pinned_skill_and_usable_capability(database: tuple[object, dict[str, Table], dict[str, str]]) -> None:
    engine, _, ids = database
    semantic = _request(ids, tool="search_authentication", operation_type="semantic", capability="authentication")
    with pytest.raises(AuthorizationDenied) as error:
        _authorize(engine, semantic)
    assert error.value.code is AuthorizationCode.SEMANTIC_SKILL_REQUIRED


def test_lease_expiry_at_current_time_is_denied(database: tuple[object, dict[str, Table], dict[str, str]]) -> None:
    engine, tables, ids = database
    with engine.begin() as conn:
        conn.execute(tables["execution_jobs"].update().values(lease_expires_at_utc=NOW).where(tables["execution_jobs"].c.job_id == ids["job"]))

    with pytest.raises(AuthorizationDenied) as error:
        _authorize(engine, _request(ids))

    assert error.value.code is AuthorizationCode.LEASE_EXPIRED
