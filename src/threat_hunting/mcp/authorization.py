"""Database-authoritative authorization for MCP execution requests.

The MCP client envelope is an assertion, never an authority.  This module
loads the approved execution context from the database, checks every binding
again immediately before submission, and returns an immutable context for the
provider adapter.  It intentionally uses SQLAlchemy Core and small schema
adapters so the authorization boundary remains usable while the execution
schema evolves between migrations.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import MetaData, Table, and_, inspect, select
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from threat_hunting.db import action_digest, deterministic_sid


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_DETAIL = 256
_TERMINAL_STATES = {
    "cancelled",
    "canceled",
    "completed",
    "failed",
    "budget_exhausted",
    "succeeded",
    "success",
    "stopped",
    "terminal",
    "closed",
}
_RUNNING_STATES = {
    "active",
    "claimed",
    "in_progress",
    "investigating",
    "running",
}
_APPROVED_STATES = {"approved", "active", "valid", "current"}
_USABLE_CAPABILITY_STATES = {"available", "usable", "verified", "active", "selected"}


class AuthorizationCode(StrEnum):
    """Bounded, machine-readable authorization denial categories."""

    INVALID_REQUEST = "invalid_request"
    UNAUTHENTICATED_SUBJECT = "unauthenticated_subject"
    SCHEMA_UNAVAILABLE = "authorization_schema_unavailable"
    DATABASE_FAILURE = "authorization_database_failure"
    EXECUTION_NOT_FOUND = "execution_not_found"
    HUNT_MISMATCH = "hunt_mismatch"
    OWNER_MISMATCH = "owner_mismatch"
    DEPLOYMENT_SCOPE_MISMATCH = "deployment_scope_mismatch"
    APPROVAL_MISSING = "approval_missing"
    APPROVAL_MISMATCH = "approval_mismatch"
    PLAN_MISSING = "plan_missing"
    PLAN_MISMATCH = "plan_mismatch"
    CONFIG_MISSING = "execution_config_missing"
    CONFIG_MISMATCH = "execution_config_mismatch"
    DISCOVERY_MISSING = "discovery_missing"
    DISCOVERY_MISMATCH = "discovery_mismatch"
    QUERY_MISSING = "query_missing"
    QUERY_MISMATCH = "query_mismatch"
    QUESTION_MISMATCH = "question_mismatch"
    PURPOSE_MISMATCH = "purpose_mismatch"
    INFORMATION_GAIN_MISMATCH = "expected_information_gain_mismatch"
    POLICY_MISMATCH = "query_policy_mismatch"
    HASH_MISMATCH = "content_hash_mismatch"
    SCOPE_MISMATCH = "approved_scope_mismatch"
    LIMIT_MISMATCH = "approved_limits_mismatch"
    LEASE_MISSING = "worker_lease_missing"
    LEASE_EXPIRED = "worker_lease_expired"
    LEASE_OWNER_MISMATCH = "worker_lease_owner_mismatch"
    EXECUTION_CANCELLED = "execution_cancelled"
    EXECUTION_TERMINAL = "execution_terminal"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUTHORIZATION_REVOKED = "authorization_revoked"
    IDEMPOTENCY_MISMATCH = "idempotency_mismatch"
    REPLAY = "request_replay"
    REPLAY_CONFLICT = "request_replay_conflict"
    AUDIT_UNAVAILABLE = "pre_submit_audit_unavailable"
    SEMANTIC_SKILL_REQUIRED = "semantic_skill_not_selected"
    SEMANTIC_CAPABILITY_MISSING = "semantic_capability_missing"
    SEMANTIC_CAPABILITY_AMBIGUOUS = "semantic_capability_ambiguous"
    SEMANTIC_NO_MATCH = "semantic_no_match_not_allowed"


class AuthorizationDenied(PermissionError):
    """A safe, bounded authorization failure.

    ``detail`` is deliberately short and never contains SQL errors, request
    payloads, SPL, credentials, or provider responses.
    """

    code: AuthorizationCode
    detail: str
    request_id: str | None

    def __init__(
        self,
        code: AuthorizationCode | str,
        detail: str = "request denied",
        *,
        request_id: str | None = None,
    ) -> None:
        self.code = AuthorizationCode(code)
        self.detail = str(detail)[:_MAX_DETAIL]
        self.request_id = request_id
        super().__init__(self.detail)

    def as_dict(self) -> dict[str, str]:
        """Return the bounded error shape exposed at the MCP boundary."""

        result = {"code": self.code.value, "detail": self.detail}
        if self.request_id:
            result["request_id"] = self.request_id[:128]
        return result

    @property
    def error_code(self) -> str:
        """Compatibility accessor for transport error serializers."""

        return self.code.value


class MCPToolRequest(BaseModel):
    """Strictly bounded MCP assertions used by the authorization boundary.

    The model permits phase-specific assertion extensions so older workers can
    interoperate while the authorization function still ignores unknown
    fields.  Every value that controls execution is checked against persisted
    rows before an authorized context is returned.
    """

    model_config = ConfigDict(extra="allow", frozen=True, populate_by_name=True)

    request_id: str = Field(default="", max_length=128)
    tool: str | None = Field(default=None, max_length=100)
    operation: str | None = Field(default=None, max_length=100)
    operation_type: str | None = Field(default=None, max_length=32)
    authenticated_subject: str | None = Field(default=None, max_length=200)
    worker_id: str | None = Field(default=None, max_length=200)
    idempotency_key: str | None = Field(default=None, max_length=200)
    action_digest: str | None = Field(default=None, max_length=64)
    deployment_scope_id: str | None = Field(default=None, max_length=200)
    hunt_id: str | None = Field(default=None, max_length=36)
    execution_id: str | None = Field(default=None, max_length=36)
    execution_job_id: str | None = Field(default=None, max_length=36)
    approval_id: str | None = Field(default=None, max_length=36)
    plan_id: str | None = Field(default=None, max_length=36)
    plan_version: int | None = None
    plan_sha256: str | None = Field(default=None, max_length=64)
    execution_config_snapshot_id: str | None = Field(default=None, max_length=36)
    execution_config_sha256: str | None = Field(default=None, max_length=64)
    discovery_snapshot_id: str | None = Field(default=None, max_length=36)
    query_id: str | None = Field(default=None, max_length=36)
    query_sha256: str | None = Field(default=None, max_length=64)
    question_id: str | None = Field(default=None, max_length=200)
    purpose: str | None = Field(default=None, max_length=2000)
    expected_information_gain: str | None = Field(default=None, max_length=2000)
    earliest_utc: datetime | str | None = None
    latest_utc: datetime | str | None = None
    indexes: list[str] | None = None
    sourcetypes: list[str] | None = None
    requested_fields: list[str] | None = None
    max_results: int | None = None
    max_bytes: int | None = None
    timeout_seconds: int | None = None
    policy_version: str | None = Field(default=None, max_length=200)
    policy_hash: str | None = Field(default=None, max_length=64)
    capability_id: str | None = Field(default=None, max_length=200)
    capability: str | None = Field(default=None, max_length=200)
    capability_name: str | None = Field(default=None, max_length=200)
    skill_id: str | None = Field(default=None, max_length=200)
    skill_version: str | None = Field(default=None, max_length=100)
    skill_sha256: str | None = Field(default=None, max_length=64)
    no_match: bool = False


@dataclass(frozen=True, slots=True)
class ReplayCheck:
    """Result of checking subject-scoped MCP idempotency."""

    status: "ReplayStatus"
    request_id: str | None = None
    action_digest: str | None = None

    @property
    def is_new(self) -> bool:
        """Whether no request currently owns this idempotency key."""

        return self.status is ReplayStatus.NEW

    @property
    def is_replay(self) -> bool:
        """Whether the same action was already reserved/submitted."""

        return self.status is ReplayStatus.REPLAY

    @property
    def is_conflict(self) -> bool:
        """Whether the key exists for a different action digest."""

        return self.status is ReplayStatus.CONFLICT


class ReplayStatus(StrEnum):
    """Replay outcomes for an MCP idempotency key."""

    NEW = "new"
    REPLAY = "replay"
    CONFLICT = "conflict"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class AuthorizedMCPContext:
    """Server-resolved, immutable execution context for one MCP call."""

    request_id: str
    tool: str
    authenticated_subject: str
    worker_id: str
    deployment_scope_id: str
    owner_id: str
    hunt_id: str
    execution_id: str
    execution_job_id: str | None
    approval_id: str
    plan_id: str
    plan_version: int | None
    plan_sha256: str
    execution_config_snapshot_id: str
    execution_config_sha256: str
    discovery_snapshot_id: str
    query_id: str
    question_id: str
    purpose: str
    expected_information_gain: str
    scope: Mapping[str, Any] = field(default_factory=dict)
    policy: Mapping[str, Any] = field(default_factory=dict)
    limits: Mapping[str, Any] = field(default_factory=dict)
    query: Mapping[str, Any] = field(default_factory=dict)
    capability_bindings: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        """Defensively freeze nested mappings returned to provider code."""

        for name in ("scope", "policy", "limits", "query"):
            value = getattr(self, name)
            if not isinstance(value, MappingProxyType):
                object.__setattr__(self, name, MappingProxyType(dict(value)))
        bindings = tuple(MappingProxyType(dict(item)) for item in self.capability_bindings)
        object.__setattr__(self, "capability_bindings", bindings)

    @property
    def operation(self) -> str:
        """Return the selected MCP tool name."""

        return self.tool


def _request_value(request: MCPToolRequest | Mapping[str, Any], *names: str, default: Any = None) -> Any:
    """Read a request assertion, including common nested envelope sections."""

    values: Mapping[str, Any]
    if isinstance(request, MCPToolRequest):
        values = request.model_dump(mode="python")
    elif isinstance(request, Mapping):
        values = request
    else:
        values = {
            key: getattr(request, key)
            for key in dir(request)
            if not key.startswith("_") and not callable(getattr(request, key, None))
        }
    for name in names:
        if name in values and values[name] is not None:
            return values[name]
        for section_name in ("scope", "query", "policy", "limits", "capability", "authorization"):
            section = values.get(section_name)
            if isinstance(section, Mapping) and name in section and section[name] is not None:
                return section[name]
    return default


def _row_value(row: Mapping[Any, Any], *names: str, default: Any = None) -> Any:
    """Return the first populated persisted value matching column aliases."""

    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return default


def _json(value: Any, *, default: Any = None) -> Any:
    """Decode a JSON column without accepting malformed persisted content."""

    if value is None:
        return default
    if isinstance(value, (Mapping, list, tuple)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return default
    return default


def _utc(value: Any) -> datetime | None:
    """Normalize a persisted or client timestamp to aware UTC."""

    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _same_time(left: Any, right: Any) -> bool:
    """Compare two timestamps safely after UTC normalization."""

    l_value, r_value = _utc(left), _utc(right)
    return l_value is not None and r_value is not None and l_value == r_value


def _norm_list(value: Any) -> tuple[str, ...] | None:
    """Normalize bounded scope lists while preserving exact membership."""

    if value is None:
        return None
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        return None
    return tuple(sorted({str(item) for item in value}))


def _scope(row: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve the canonical scope object from a plan or query row."""

    source = _json(_row_value(row, "scope", "approved_scope", "time_scope"), default={})
    if not isinstance(source, Mapping):
        source = {}
    result = dict(source)
    aliases = {
        "earliest_utc": ("earliest_utc", "earliest", "start_time_utc", "start_utc"),
        "latest_utc": ("latest_utc", "latest", "end_time_utc", "end_utc"),
        "indexes": ("indexes", "approved_indexes", "index_scope"),
        "sourcetypes": ("sourcetypes", "approved_sourcetypes", "sourcetype_scope"),
        "requested_fields": ("requested_fields", "fields", "approved_fields"),
    }
    for target, names in aliases.items():
        value = _row_value(row, *names)
        if value is not None:
            result[target] = _json(value, default=value)
    return result


def _limits(row: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve persisted result and execution limits."""

    source = _json(_row_value(row, "limits", "enforced_limits", "query_limits"), default={})
    result = dict(source) if isinstance(source, Mapping) else {}
    for target, names in {
        "max_results": ("max_results", "result_limit", "row_limit"),
        "max_bytes": ("max_bytes", "byte_limit", "result_byte_limit"),
        "timeout_seconds": ("timeout_seconds", "query_timeout_seconds", "timeout"),
    }.items():
        value = _row_value(row, *names)
        if value is not None:
            result[target] = value
    return result


def _policy(row: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve persisted query-policy identity."""

    source = _json(_row_value(row, "policy", "query_policy", "policy_snapshot"), default={})
    result = dict(source) if isinstance(source, Mapping) else {}
    for target, names in {
        "version": ("policy_version", "query_policy_version"),
        "hash": ("policy_hash", "query_policy_hash", "policy_sha256", "query_policy_sha256"),
    }.items():
        value = _row_value(row, *names)
        if value is not None:
            result[target] = value
    return result


def _table(conn: Connection, candidates: Sequence[str]) -> Table | None:
    """Reflect the first existing table from a fixed allowlist."""

    names = set(inspect(conn).get_table_names())
    for name in candidates:
        if name in names:
            try:
                return Table(name, MetaData(), autoload_with=conn)
            except SQLAlchemyError as exc:
                raise AuthorizationDenied(AuthorizationCode.SCHEMA_UNAVAILABLE) from exc
    return None


def _lookup(
    conn: Connection,
    table: Table,
    values: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Fetch one row using persisted identifier columns and bounded results."""

    conditions = []
    for key, value in values.items():
        if value is None:
            continue
        column = table.c.get(key)
        if column is not None:
            conditions.append(column == value)
    if not conditions:
        return None
    try:
        stmt = select(table).where(and_(*conditions)).limit(2)
        rows = conn.execute(stmt).mappings().all()
    except SQLAlchemyError as exc:
        raise AuthorizationDenied(AuthorizationCode.DATABASE_FAILURE) from exc
    if len(rows) != 1:
        return None
    return dict(rows[0])


def _lookup_any(
    conn: Connection,
    table: Table,
    values: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Fetch one row when a table uses one of several identifier names."""

    available = {key: value for key, value in values.items() if key in table.c and value is not None}
    return _lookup(conn, table, available)


def _required_request(request: MCPToolRequest | Mapping[str, Any], request_id: str | None) -> None:
    """Reject missing identifiers before touching provider-facing state."""

    required = {
        "request_id": _request_value(request, "request_id"),
        "hunt_id": _request_value(request, "hunt_id"),
        "execution_id": _request_value(request, "execution_id"),
        "approval_id": _request_value(request, "approval_id"),
        "plan_id": _request_value(request, "plan_id"),
        "execution_config_snapshot_id": _request_value(
            request, "execution_config_snapshot_id", "config_snapshot_id"
        ),
        "discovery_snapshot_id": _request_value(request, "discovery_snapshot_id"),
        "query_id": _request_value(request, "query_id"),
    }
    if request_id:
        required["request_id"] = request_id
    missing = [key for key, value in required.items() if value in (None, "") and key != "execution_id"]
    if _request_value(request, "execution_id", "execution_job_id") in (None, ""):
        missing.append("execution_job_id")
    if missing:
        raise AuthorizationDenied(AuthorizationCode.INVALID_REQUEST, "required assertion missing", request_id=request_id)


def _deny_if_not_equal(
    request: MCPToolRequest | Mapping[str, Any],
    server: Mapping[str, Any],
    names: Sequence[str],
    code: AuthorizationCode,
    *,
    request_id: str,
    server_names: Sequence[str] | None = None,
) -> Any:
    """Compare a client assertion with a server value and return that value."""

    assertion = _request_value(request, *names)
    if server_names is None:
        server_names = names
    persisted = _row_value(server, *server_names)
    if assertion is not None and persisted is not None and str(assertion) != str(persisted):
        raise AuthorizationDenied(code, "persisted authorization mismatch", request_id=request_id)
    return persisted if persisted is not None else assertion


def _check_hash(
    request: MCPToolRequest | Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    request_names: Sequence[str],
    row_names: Sequence[str],
    code: AuthorizationCode,
    *,
    request_id: str,
) -> str:
    """Require one valid lowercase SHA-256 hash to bind all persisted rows."""

    assertion = _request_value(request, *request_names)
    values = [_row_value(row, *row_names) for row in rows]
    values = [str(value) for value in values if value not in (None, "")]
    if assertion in (None, "") and not values:
        raise AuthorizationDenied(code, "authorization hash missing", request_id=request_id)
    selected = str(assertion or values[0])
    if not _HASH_RE.fullmatch(selected):
        raise AuthorizationDenied(code, "authorization hash invalid", request_id=request_id)
    if any(value != selected for value in values):
        raise AuthorizationDenied(code, "persisted authorization hash mismatch", request_id=request_id)
    return selected


def _check_scope(
    request: MCPToolRequest | Mapping[str, Any],
    source: Mapping[str, Any],
    *,
    request_id: str,
) -> dict[str, Any]:
    """Require exact approved time and telemetry scope assertions."""

    scope = _scope(source)
    for name in ("earliest_utc", "latest_utc"):
        assertion = _request_value(request, name)
        persisted = scope.get(name)
        if assertion is None or persisted is None or not _same_time(assertion, persisted):
            raise AuthorizationDenied(AuthorizationCode.SCOPE_MISMATCH, "approved time scope mismatch", request_id=request_id)
    for name in ("indexes", "sourcetypes"):
        assertion = _norm_list(_request_value(request, name))
        persisted = _norm_list(scope.get(name))
        if assertion is None or persisted is None or assertion != persisted:
            raise AuthorizationDenied(AuthorizationCode.SCOPE_MISMATCH, "approved telemetry scope mismatch", request_id=request_id)
    requested_fields = _request_value(request, "requested_fields")
    persisted_fields = scope.get("requested_fields")
    if requested_fields is not None and persisted_fields is not None and _norm_list(requested_fields) != _norm_list(persisted_fields):
        raise AuthorizationDenied(AuthorizationCode.SCOPE_MISMATCH, "approved field scope mismatch", request_id=request_id)
    return scope


def _check_limits(
    request: MCPToolRequest | Mapping[str, Any],
    source: Mapping[str, Any],
    *,
    request_id: str,
) -> dict[str, Any]:
    """Require exact server-enforced query limits."""

    limits = _limits(source)
    for name in ("max_results", "max_bytes", "timeout_seconds"):
        assertion = _request_value(request, name)
        persisted = limits.get(name)
        if assertion is None or persisted is None or int(assertion) != int(persisted):
            raise AuthorizationDenied(AuthorizationCode.LIMIT_MISMATCH, "enforced limit mismatch", request_id=request_id)
        if int(assertion) <= 0:
            raise AuthorizationDenied(AuthorizationCode.LIMIT_MISMATCH, "invalid enforced limit", request_id=request_id)
    return limits


def _check_policy(
    request: MCPToolRequest | Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    *,
    request_id: str,
) -> dict[str, Any]:
    """Require one exact policy version/hash across execution rows."""

    policies = [_policy(row) for row in rows]
    policies = [policy for policy in policies if policy]
    if not policies:
        raise AuthorizationDenied(AuthorizationCode.POLICY_MISMATCH, "query policy missing", request_id=request_id)
    version = _request_value(request, "policy_version", "query_policy_version")
    hash_value = _request_value(request, "policy_hash", "query_policy_hash", "policy_sha256")
    server_version = next((item.get("version") for item in policies if item.get("version") is not None), None)
    server_hash = next((item.get("hash") for item in policies if item.get("hash") is not None), None)
    if version is None or server_version is None or str(version) != str(server_version):
        raise AuthorizationDenied(AuthorizationCode.POLICY_MISMATCH, "query policy mismatch", request_id=request_id)
    if hash_value is not None or server_hash is not None:
        if hash_value is None or server_hash is None or not _HASH_RE.fullmatch(str(hash_value)) or str(hash_value) != str(server_hash):
            raise AuthorizationDenied(AuthorizationCode.POLICY_MISMATCH, "query policy hash mismatch", request_id=request_id)
    if any(item.get("version") not in (None, server_version) or item.get("hash") not in (None, server_hash) for item in policies):
        raise AuthorizationDenied(AuthorizationCode.POLICY_MISMATCH, "persisted query policy mismatch", request_id=request_id)
    return {"version": server_version, **({"hash": server_hash} if server_hash else {})}


def _is_cancelled(row: Mapping[str, Any]) -> bool:
    """Read common persisted cancellation flags and states."""

    value = _row_value(row, "cancelled", "canceled", "cancellation_requested", "cancel_requested")
    if bool(value):
        return True
    state = _row_value(row, "status", "state", "phase")
    return str(state).lower() in {"cancelled", "canceled", "cancellation_requested"}


def _check_execution_state(
    execution: Mapping[str, Any],
    hunt: Mapping[str, Any],
    *,
    request_id: str,
    now: datetime,
) -> None:
    """Require nonterminal investigating execution and hunt state."""

    if _is_cancelled(execution) or _is_cancelled(hunt):
        raise AuthorizationDenied(AuthorizationCode.EXECUTION_CANCELLED, "execution cancelled", request_id=request_id)
    statuses = []
    for row in (execution, hunt):
        status = _row_value(row, "status", "state", "phase")
        if status is not None:
            normalized = str(status).lower()
            if normalized in _TERMINAL_STATES:
                raise AuthorizationDenied(AuthorizationCode.EXECUTION_TERMINAL, "execution is terminal", request_id=request_id)
            statuses.append(normalized)
    if not statuses or any(status not in _RUNNING_STATES for status in statuses):
        raise AuthorizationDenied(AuthorizationCode.EXECUTION_TERMINAL, "execution is not investigating", request_id=request_id)
    for row in (execution, hunt):
        expiry = _row_value(row, "authorization_expires_at_utc", "expires_at_utc", "execution_expires_at_utc")
        if expiry is not None:
            expiry_utc = _utc(expiry)
            if expiry_utc is None or expiry_utc <= now:
                raise AuthorizationDenied(AuthorizationCode.AUTHORIZATION_EXPIRED, "authorization expired", request_id=request_id)


def _check_lease(
    job: Mapping[str, Any],
    worker_id: str | None,
    *,
    request_id: str,
    now: datetime,
) -> None:
    """Require the current worker to own an unexpired execution lease."""

    if not worker_id:
        raise AuthorizationDenied(AuthorizationCode.LEASE_OWNER_MISMATCH, "worker identity missing", request_id=request_id)
    owner = _row_value(job, "lease_owner", "worker_id", "claimed_by", "owner_id")
    if owner is None:
        raise AuthorizationDenied(AuthorizationCode.LEASE_MISSING, "worker lease missing", request_id=request_id)
    if str(owner) != str(worker_id):
        raise AuthorizationDenied(AuthorizationCode.LEASE_OWNER_MISMATCH, "worker lease owner mismatch", request_id=request_id)
    expiry = _row_value(job, "lease_expires_at_utc", "lease_expires_at", "expires_at_utc", "lease_deadline_utc")
    expiry_utc = _utc(expiry)
    if expiry_utc is None:
        raise AuthorizationDenied(AuthorizationCode.LEASE_MISSING, "worker lease expiry missing", request_id=request_id)
    if expiry_utc <= now:
        raise AuthorizationDenied(AuthorizationCode.LEASE_EXPIRED, "worker lease expired", request_id=request_id)
    status = _row_value(job, "status", "state")
    if status is not None and str(status).lower() not in _RUNNING_STATES:
        raise AuthorizationDenied(AuthorizationCode.LEASE_MISSING, "worker lease is not claimed", request_id=request_id)


def _check_revocation(
    conn: Connection,
    table: Table | None,
    *,
    deployment_scope_id: str,
    hunt_id: str,
    execution_id: str,
    execution_job_id: str,
    approval_id: str,
    request_id: str,
    now: datetime,
) -> None:
    """Deny any matching append-only revocation event."""

    if table is None:
        return
    conditions = []
    for key, value in {
        "deployment_scope_id": deployment_scope_id,
        "hunt_id": hunt_id,
        "approval_id": approval_id,
    }.items():
        if key in table.c:
            conditions.append(table.c[key] == value)
    if "execution_job_id" in table.c:
        conditions.append((table.c.execution_job_id == execution_job_id) | table.c.execution_job_id.is_(None))
    elif "execution_id" in table.c:
        conditions.append((table.c.execution_id == execution_id) | table.c.execution_id.is_(None))
    if not conditions:
        raise AuthorizationDenied(AuthorizationCode.SCHEMA_UNAVAILABLE, "revocation schema incomplete", request_id=request_id)
    try:
        rows = conn.execute(select(table).where(and_(*conditions)).limit(2)).mappings().all()
    except SQLAlchemyError as exc:
        raise AuthorizationDenied(AuthorizationCode.DATABASE_FAILURE) from exc
    for row in rows:
        revoked_at = _utc(_row_value(row, "revoked_at_utc", "created_at_utc", "timestamp_utc"))
        if revoked_at is None or revoked_at <= now:
            raise AuthorizationDenied(AuthorizationCode.AUTHORIZATION_REVOKED, "authorization revoked", request_id=request_id)


def _semantic_capabilities(
    conn: Connection,
    request: MCPToolRequest | Mapping[str, Any],
    *,
    hunt_id: str,
    discovery_id: str,
    request_id: str,
) -> tuple[Mapping[str, Any], ...]:
    """Resolve selected skill and exactly usable persisted capability bindings."""

    selection_table = _table(conn, ("hunt_skill_selections", "skill_selections", "plan_skill_selections"))
    selection: dict[str, Any] | None = None
    if selection_table is not None:
        selection = _lookup_any(conn, selection_table, {"hunt_id": hunt_id, "discovery_snapshot_id": discovery_id})
        if selection is None:
            selection = _lookup_any(conn, selection_table, {"hunt_id": hunt_id})
    if selection is None:
        raise AuthorizationDenied(AuthorizationCode.SEMANTIC_SKILL_REQUIRED, "selected pinned skill missing", request_id=request_id)
    status = str(_row_value(selection, "selection_status", "status", default="")).lower()
    pinned = _row_value(selection, "pinned", "is_pinned", "selected")
    if status not in {"selected", "pinned", "approved", "active"} or pinned is False:
        raise AuthorizationDenied(AuthorizationCode.SEMANTIC_SKILL_REQUIRED, "selected pinned skill missing", request_id=request_id)
    for request_name, row_names in (
        ("skill_id", ("skill_id", "primary_skill_id")),
        ("skill_version", ("skill_version", "version")),
        ("skill_sha256", ("skill_sha256", "content_sha256", "skill_hash")),
    ):
        assertion = _request_value(request, request_name)
        persisted = _row_value(selection, *row_names)
        if assertion is not None and persisted is not None and str(assertion) != str(persisted):
            raise AuthorizationDenied(AuthorizationCode.SEMANTIC_SKILL_REQUIRED, "selected skill mismatch", request_id=request_id)
    capability_table = _table(conn, ("capability_bindings", "hunt_capability_bindings", "capabilities", "telemetry_capabilities"))
    if capability_table is None:
        raise AuthorizationDenied(AuthorizationCode.SEMANTIC_CAPABILITY_MISSING, "usable capability missing", request_id=request_id)
    requested = _request_value(request, "capability_id", "capability", "capability_name", "required_capability")
    if requested in (None, ""):
        requested = _request_value(request, "tool", "operation")
    rows: list[dict[str, Any]] = []
    for candidate in conn.execute(select(capability_table).limit(100)).mappings().all():
        row = dict(candidate)
        row_hunt = _row_value(row, "hunt_id")
        row_discovery = _row_value(row, "discovery_snapshot_id", "snapshot_id")
        if row_hunt not in (None, hunt_id) or row_discovery not in (None, discovery_id):
            continue
        capability_value = _row_value(row, "capability_id", "capability", "capability_name", "name")
        if requested is not None and str(capability_value) != str(requested):
            continue
        usable = _row_value(row, "usable", "is_usable", "available")
        row_status = str(_row_value(row, "status", "state", default="")).lower()
        ambiguous = _row_value(row, "ambiguous", "is_ambiguous")
        if bool(ambiguous):
            raise AuthorizationDenied(AuthorizationCode.SEMANTIC_CAPABILITY_AMBIGUOUS, "capability mapping ambiguous", request_id=request_id)
        if usable is False or (usable is None and row_status not in _USABLE_CAPABILITY_STATES):
            continue
        if row_status and row_status not in _USABLE_CAPABILITY_STATES and usable is not True:
            continue
        rows.append(row)
    if len(rows) > 1:
        raise AuthorizationDenied(AuthorizationCode.SEMANTIC_CAPABILITY_AMBIGUOUS, "capability mapping ambiguous", request_id=request_id)
    if not rows:
        raise AuthorizationDenied(AuthorizationCode.SEMANTIC_CAPABILITY_MISSING, "usable capability missing", request_id=request_id)
    return tuple(rows)


def _is_semantic(request: MCPToolRequest | Mapping[str, Any]) -> bool:
    """Classify a request without letting a client choose a broader scope."""

    operation_type = str(_request_value(request, "operation_type", default="")).lower()
    if operation_type in {"semantic", "capability"}:
        return True
    tool = str(_request_value(request, "tool", "operation", default="")).lower()
    return tool not in {"", "generic", "generic_spl", "execute_spl", "run_spl", "search_spl"} and "generic" not in tool and "spl" not in tool


def _connection_call(bind: Engine | Connection, callback: Callable[[Connection], Any]) -> Any:
    """Run a read/write callback with one transaction when given an engine."""

    if isinstance(bind, Engine):
        try:
            with bind.begin() as conn:
                return callback(conn)
        except AuthorizationDenied:
            raise
        except SQLAlchemyError as exc:
            raise AuthorizationDenied(AuthorizationCode.DATABASE_FAILURE) from exc
    if isinstance(bind, Connection):
        return callback(bind)
    engine = getattr(bind, "engine", None)
    if isinstance(engine, Engine):
        return _connection_call(engine, callback)
    raise TypeError("authorization requires a SQLAlchemy Engine or Connection")


def _configured_subject(settings: Any, explicit: str | None) -> str | None:
    """Resolve the configured service subject without exposing configuration."""

    if explicit:
        return explicit
    if settings is None:
        return None
    for candidate in (
        getattr(settings, "mcp_service_subject", None),
        getattr(getattr(settings, "execution", None), "mcp_service_subject", None),
        getattr(settings, "service_subject", None),
    ):
        if candidate:
            return str(candidate)
    return None


def authorize_mcp_tool_request(
    bind: Engine | Connection,
    request: MCPToolRequest | Mapping[str, Any],
    *,
    authenticated_subject: str | None = None,
    configured_service_subject: str | None = None,
    service_subject: str | None = None,
    settings: Any = None,
    envelope_worker_id: str | None = None,
    worker_id: str | None = None,
    now: datetime | None = None,
) -> AuthorizedMCPContext:
    """Authorize one MCP request against one consistent database snapshot.

    All provider-facing scope, policy, limits, query, and capability values in
    the return value come from persisted rows.  Client values are only used as
    equality assertions and identifiers to locate those rows.
    """

    request_id = str(_request_value(request, "request_id", default="") or "")[:128] or None
    subject = authenticated_subject or _request_value(request, "authenticated_subject")
    configured = _configured_subject(settings, configured_service_subject or service_subject)
    if not subject or not configured or str(subject) != str(configured):
        raise AuthorizationDenied(AuthorizationCode.UNAUTHENTICATED_SUBJECT, "service subject not authorized", request_id=request_id)
    asserted_subject = _request_value(request, "authenticated_subject")
    if authenticated_subject is not None and asserted_subject not in (None, authenticated_subject):
        raise AuthorizationDenied(AuthorizationCode.UNAUTHENTICATED_SUBJECT, "service subject assertion mismatch", request_id=request_id)
    _required_request(request, request_id)
    request_id = str(_request_value(request, "request_id"))
    effective_worker = envelope_worker_id or worker_id or _request_value(request, "worker_id")
    asserted_worker = _request_value(request, "worker_id", "lease_owner")
    if (envelope_worker_id or worker_id) is not None and asserted_worker not in (None, effective_worker):
        raise AuthorizationDenied(AuthorizationCode.LEASE_OWNER_MISMATCH, "worker lease assertion mismatch", request_id=request_id)
    effective_now = _utc(now) or datetime.now(timezone.utc)

    def _authorize(conn: Connection) -> AuthorizedMCPContext:
        asserted_execution_id = _request_value(request, "execution_id")
        execution_job_id = _request_value(request, "execution_job_id")
        execution_id = str(asserted_execution_id or execution_job_id)
        hunt_id = str(_request_value(request, "hunt_id"))
        approval_id = str(_request_value(request, "approval_id"))
        plan_id = str(_request_value(request, "plan_id"))
        config_id = str(_request_value(request, "execution_config_snapshot_id", "config_snapshot_id"))
        discovery_id = str(_request_value(request, "discovery_snapshot_id"))
        query_id = str(_request_value(request, "query_id"))
        job_table = _table(conn, ("execution_jobs", "execution_job", "hunt_execution_jobs"))
        execution_table = _table(conn, ("hunt_executions", "executions", "hunt_execution"))
        hunt_table = _table(conn, ("hunts", "hunt"))
        approval_table = _table(conn, ("plan_approvals", "approvals", "hunt_approvals", "approval"))
        plan_table = _table(conn, ("plans", "hunt_plans", "hunt_plan"))
        config_table = _table(conn, ("execution_config_snapshots", "execution_configs", "execution_configuration_snapshots"))
        discovery_table = _table(conn, ("discovery_snapshots", "discovery_snapshot"))
        query_table = _table(conn, ("query_ledger", "queries", "query_records", "hunt_queries"))
        revocation_table = _table(conn, ("execution_authorization_revocations", "authorization_revocations"))
        required_tables = (job_table, execution_table, hunt_table, approval_table, plan_table, config_table, discovery_table, query_table)
        if any(table is None for table in required_tables):
            raise AuthorizationDenied(AuthorizationCode.SCHEMA_UNAVAILABLE, "authorization schema incomplete", request_id=request_id)
        assert job_table is not None
        assert execution_table is not None
        assert hunt_table is not None
        assert approval_table is not None
        assert plan_table is not None
        assert config_table is not None
        assert discovery_table is not None
        assert query_table is not None

        job = _lookup_any(
            conn,
            job_table,
            {
                "execution_job_id": execution_job_id,
                "job_id": execution_job_id or _request_value(request, "execution_job_id"),
                "execution_id": asserted_execution_id,
            },
        )
        if job is not None:
            persisted_execution_id = _row_value(job, "execution_id", "hunt_execution_id")
            if persisted_execution_id is not None:
                execution_id = str(persisted_execution_id)
        execution_lookup: dict[str, Any] = {}
        if execution_job_id and "execution_job_id" in execution_table.c:
            execution_lookup["execution_job_id"] = execution_job_id
        elif "execution_id" in execution_table.c:
            execution_lookup["execution_id"] = execution_id
        elif "hunt_execution_id" in execution_table.c:
            execution_lookup["hunt_execution_id"] = execution_id
        elif "hunt_id" in execution_table.c:
            execution_lookup["hunt_id"] = hunt_id
        execution = _lookup_any(conn, execution_table, execution_lookup)
        if execution is not None:
            persisted_execution_id = _row_value(execution, "execution_id", "hunt_execution_id")
            if persisted_execution_id is not None:
                execution_id = str(persisted_execution_id)
        hunt = _lookup_any(conn, hunt_table, {"hunt_id": hunt_id, "id": hunt_id})
        approval = _lookup_any(conn, approval_table, {"approval_id": approval_id, "id": approval_id})
        plan = _lookup_any(conn, plan_table, {"plan_id": plan_id, "id": plan_id})
        config = _lookup_any(conn, config_table, {"execution_config_snapshot_id": config_id, "config_snapshot_id": config_id, "id": config_id})
        discovery = _lookup_any(conn, discovery_table, {"discovery_snapshot_id": discovery_id, "snapshot_id": discovery_id, "id": discovery_id})
        query = _lookup_any(conn, query_table, {"query_id": query_id, "id": query_id})
        if job is None or execution is None:
            raise AuthorizationDenied(AuthorizationCode.EXECUTION_NOT_FOUND, "execution not found", request_id=request_id)
        if hunt is None:
            raise AuthorizationDenied(AuthorizationCode.HUNT_MISMATCH, "hunt not found", request_id=request_id)
        for row, code, text in ((approval, AuthorizationCode.APPROVAL_MISSING, "approval missing"), (plan, AuthorizationCode.PLAN_MISSING, "plan missing"), (config, AuthorizationCode.CONFIG_MISSING, "execution config missing"), (discovery, AuthorizationCode.DISCOVERY_MISSING, "discovery missing"), (query, AuthorizationCode.QUERY_MISSING, "query missing")):
            if row is None:
                raise AuthorizationDenied(code, text, request_id=request_id)
        assert approval and plan and config and discovery and query

        for row in (job, execution, hunt, approval, plan, config, discovery, query):
            persisted_scope = _row_value(row, "deployment_scope_id", "customer_scope_id", "scope_id")
            asserted_scope = _request_value(request, "deployment_scope_id")
            if asserted_scope is None or persisted_scope is None or str(asserted_scope) != str(persisted_scope):
                raise AuthorizationDenied(AuthorizationCode.DEPLOYMENT_SCOPE_MISMATCH, "deployment scope mismatch", request_id=request_id)
        owner = _row_value(hunt, "owner_id", "user_id", "account_id")
        if owner is None:
            raise AuthorizationDenied(AuthorizationCode.OWNER_MISMATCH, "hunt owner missing", request_id=request_id)
        if (
            _row_value(job, "hunt_id") not in (None, hunt_id)
            or _row_value(execution, "hunt_id") not in (None, hunt_id)
            or _row_value(query, "hunt_id") not in (None, hunt_id)
        ):
            raise AuthorizationDenied(AuthorizationCode.HUNT_MISMATCH, "cross-hunt authorization", request_id=request_id)
        _check_lease(job, str(effective_worker) if effective_worker else None, request_id=request_id, now=effective_now)
        _check_execution_state(execution, hunt, request_id=request_id, now=effective_now)
        for row, names, code in (
            (approval, ("approval_id", "id"), AuthorizationCode.APPROVAL_MISMATCH),
            (plan, ("plan_id", "id"), AuthorizationCode.PLAN_MISMATCH),
            (config, ("execution_config_snapshot_id", "config_snapshot_id", "id"), AuthorizationCode.CONFIG_MISMATCH),
            (discovery, ("discovery_snapshot_id", "snapshot_id", "id"), AuthorizationCode.DISCOVERY_MISMATCH),
            (query, ("query_id", "id"), AuthorizationCode.QUERY_MISMATCH),
        ):
            persisted = _row_value(row, *names)
            assertion_name = names[0]
            asserted = _request_value(request, assertion_name)
            if persisted is not None and asserted is not None and str(persisted) != str(asserted):
                raise AuthorizationDenied(code, "authorization identifier mismatch", request_id=request_id)
        plan_version = _deny_if_not_equal(request, plan, ("plan_version",), AuthorizationCode.PLAN_MISMATCH, request_id=request_id)
        plan_hash = _check_hash(request, (approval, plan), ("plan_sha256", "approved_plan_sha256"), ("plan_sha256", "approved_plan_sha256", "content_sha256"), AuthorizationCode.HASH_MISMATCH, request_id=request_id)
        config_hash = _check_hash(request, (approval, config), ("execution_config_sha256", "config_sha256"), ("execution_config_sha256", "config_sha256", "content_sha256"), AuthorizationCode.HASH_MISMATCH, request_id=request_id)
        _check_hash(request, (query,), ("query_sha256", "query_hash"), ("query_sha256", "query_hash", "normalized_query_sha256", "spl_sha256", "cache_key"), AuthorizationCode.QUERY_MISMATCH, request_id=request_id)
        if _row_value(plan, "execution_config_snapshot_id", "config_snapshot_id") not in (None, config_id) or _row_value(plan, "discovery_snapshot_id") not in (None, discovery_id):
            raise AuthorizationDenied(AuthorizationCode.PLAN_MISMATCH, "plan snapshot mismatch", request_id=request_id)
        if _row_value(approval, "hunt_id") not in (None, hunt_id) or _row_value(approval, "plan_id") not in (None, plan_id):
            raise AuthorizationDenied(AuthorizationCode.APPROVAL_MISMATCH, "approval binding mismatch", request_id=request_id)
        if _row_value(query, "execution_id") not in (None, execution_id) or _row_value(query, "approval_id") not in (None, approval_id):
            raise AuthorizationDenied(AuthorizationCode.QUERY_MISMATCH, "query execution mismatch", request_id=request_id)
        for name, code, row_names in (("question_id", AuthorizationCode.QUESTION_MISMATCH, ("question_id", "approved_question_id")), ("purpose", AuthorizationCode.PURPOSE_MISMATCH, ("purpose", "query_purpose")), ("expected_information_gain", AuthorizationCode.INFORMATION_GAIN_MISMATCH, ("expected_information_gain", "eig"))):
            assertion = _request_value(request, name)
            persisted = _row_value(query, *row_names)
            if assertion is None or persisted is None or str(assertion) != str(persisted):
                raise AuthorizationDenied(code, "query assertion mismatch", request_id=request_id)
        policy = _check_policy(request, (execution, approval, plan, config, discovery, query), request_id=request_id)
        scope = _check_scope(request, query if _scope(query) else plan, request_id=request_id)
        limits = _check_limits(request, query if _limits(query) else config, request_id=request_id)
        _check_revocation(
            conn,
            revocation_table,
            deployment_scope_id=str(_request_value(request, "deployment_scope_id")),
            hunt_id=hunt_id,
            execution_id=execution_id,
            execution_job_id=str(execution_job_id or _row_value(job, "execution_job_id", "job_id", default="")),
            approval_id=approval_id,
            request_id=request_id,
            now=effective_now,
        )
        capability_bindings = _semantic_capabilities(conn, request, hunt_id=hunt_id, discovery_id=discovery_id, request_id=request_id) if _is_semantic(request) else ()
        tool = str(_request_value(request, "tool", "operation", default="generic_spl"))
        query_value = dict(query)
        return AuthorizedMCPContext(
            request_id=request_id,
            tool=tool,
            authenticated_subject=str(subject),
            worker_id=str(effective_worker),
            deployment_scope_id=str(_request_value(request, "deployment_scope_id")),
            owner_id=str(owner),
            hunt_id=hunt_id,
            execution_id=execution_id,
            execution_job_id=str(execution_job_id or _row_value(job, "execution_job_id", "job_id", default="")) or None,
            approval_id=approval_id,
            plan_id=plan_id,
            plan_version=int(plan_version) if plan_version is not None else None,
            plan_sha256=plan_hash,
            execution_config_snapshot_id=config_id,
            execution_config_sha256=config_hash,
            discovery_snapshot_id=discovery_id,
            query_id=query_id,
            question_id=str(_request_value(request, "question_id")),
            purpose=str(_request_value(request, "purpose")),
            expected_information_gain=str(_request_value(request, "expected_information_gain")),
            scope=scope,
            policy=policy,
            limits=limits,
            query=query_value,
            capability_bindings=capability_bindings,
        )

    return _connection_call(bind, _authorize)


def _request_digest(request: MCPToolRequest | Mapping[str, Any]) -> str:
    """Resolve an asserted action digest, deriving only safe identifiers."""

    digest = _request_value(request, "action_digest")
    if digest:
        if not _HASH_RE.fullmatch(str(digest)):
            raise AuthorizationDenied(AuthorizationCode.INVALID_REQUEST, "action digest invalid", request_id=_request_value(request, "request_id"))
        return str(digest)
    values: dict[str, Any] = {}
    for key in ("tool", "operation", "hunt_id", "execution_id", "query_id", "approval_id", "idempotency_key", "plan_sha256", "execution_config_sha256", "policy_version"):
        value = _request_value(request, key)
        if value is not None:
            values[key] = value
    return action_digest(values)


def check_mcp_request_replay(
    bind: Engine | Connection,
    request: MCPToolRequest | Mapping[str, Any] | None = None,
    *,
    authenticated_subject: str | None = None,
    idempotency_key: str | None = None,
    action_digest_value: str | None = None,
) -> ReplayCheck:
    """Classify a request as new, exact replay, or idempotency conflict."""

    subject = authenticated_subject or _request_value(request, "authenticated_subject") if request is not None else authenticated_subject
    key = idempotency_key or (_request_value(request, "idempotency_key") if request is not None else None)
    digest = action_digest_value or (_request_digest(request) if request is not None else None)
    if not subject or not key or not digest:
        raise AuthorizationDenied(AuthorizationCode.INVALID_REQUEST, "replay assertions missing", request_id=_request_value(request, "request_id") if request is not None else None)

    def _check(conn: Connection) -> ReplayCheck:
        table = _table(conn, ("mcp_tool_requests",))
        if table is None:
            return ReplayCheck(ReplayStatus.UNAVAILABLE)
        if "authenticated_subject" not in table.c or "idempotency_key" not in table.c:
            raise AuthorizationDenied(AuthorizationCode.SCHEMA_UNAVAILABLE, "request ledger schema incomplete")
        try:
            row = conn.execute(select(table).where(and_(table.c.authenticated_subject == subject, table.c.idempotency_key == key)).limit(1)).mappings().first()
        except SQLAlchemyError as exc:
            raise AuthorizationDenied(AuthorizationCode.DATABASE_FAILURE) from exc
        if row is None:
            return ReplayCheck(ReplayStatus.NEW)
        existing_digest = _row_value(row, "action_digest")
        status = ReplayStatus.REPLAY if str(existing_digest) == str(digest) else ReplayStatus.CONFLICT
        return ReplayCheck(status, str(_row_value(row, "request_id", default="")) or None, str(existing_digest) if existing_digest else None)

    return _connection_call(bind, _check)


def reserve_mcp_request(
    bind: Engine | Connection,
    request: MCPToolRequest | Mapping[str, Any],
    *,
    context: AuthorizedMCPContext | None = None,
    audit_writer: Callable[[Connection, MCPToolRequest | Mapping[str, Any], AuthorizedMCPContext | None], None] | None = None,
    now: datetime | None = None,
) -> ReplayCheck:
    """Atomically audit and reserve a request before external submission.

    A missing or failed audit write aborts the reservation.  An existing exact
    digest is reported as a replay; a different digest for the same subject
    and idempotency key is a conflict.
    """

    subject = _request_value(request, "authenticated_subject")
    key = _request_value(request, "idempotency_key")
    request_id = str(_request_value(request, "request_id", default="") or "")
    digest = _request_digest(request)
    if not subject or not key or not request_id:
        raise AuthorizationDenied(AuthorizationCode.INVALID_REQUEST, "reservation assertions missing", request_id=request_id or None)

    def _reserve(conn: Connection) -> ReplayCheck:
        ledger = _table(conn, ("mcp_tool_requests",))
        audit = _table(conn, ("audit_records",))
        if ledger is None or audit is None:
            raise AuthorizationDenied(AuthorizationCode.AUDIT_UNAVAILABLE, "pre-submit audit unavailable", request_id=request_id)
        existing = check_mcp_request_replay(conn, request, action_digest_value=digest)
        if existing.status is not ReplayStatus.NEW:
            if existing.status is ReplayStatus.REPLAY:
                return existing
            raise AuthorizationDenied(AuthorizationCode.REPLAY_CONFLICT, "idempotency key conflict", request_id=request_id)
        try:
            if audit_writer is not None:
                audit_writer(conn, request, context)
            else:
                audit_data = {
                    "audit_id": str(uuid4()),
                    "hunt_id": _request_value(request, "hunt_id"),
                    "request_id": request_id,
                    "actor_type": "worker",
                    "actor_id": str(subject),
                    "action": str(_request_value(request, "tool", "operation", default="mcp_tool")),
                    "object_type": "mcp_tool_request",
                    "object_id": request_id,
                    "outcome": "success",
                    "detail": "pre-submit authorization reservation",
                    "timestamp_utc": _utc(now) or datetime.now(timezone.utc),
                }
                available = {key: value for key, value in audit_data.items() if key in audit.c}
                conn.execute(audit.insert().values(**available))
            data: dict[str, Any] = {
                "request_id": request_id,
                "authenticated_subject": str(subject),
                "idempotency_key": str(key),
                "action_digest": digest,
                "tool": str(_request_value(request, "tool", "operation", default="mcp_tool")),
                "status": "reserved",
                "deployment_scope_id": str(_request_value(request, "deployment_scope_id", default="")),
                "hunt_id": str(_request_value(request, "hunt_id", default="")),
                "execution_id": _request_value(request, "execution_id"),
                "query_id": _request_value(request, "query_id"),
                "approval_id": str(_request_value(request, "approval_id", default="")),
                "execution_config_snapshot_id": str(_request_value(request, "execution_config_snapshot_id", "config_snapshot_id", default="")),
                "deterministic_sid": deterministic_sid(request_id),
                "created_at_utc": _utc(now) or datetime.now(timezone.utc),
                "updated_at_utc": _utc(now) or datetime.now(timezone.utc),
            }
            conn.execute(ledger.insert().values(**{key: value for key, value in data.items() if key in ledger.c}))
        except IntegrityError:
            existing = check_mcp_request_replay(conn, request, action_digest_value=digest)
            if existing.status is ReplayStatus.REPLAY:
                return existing
            raise AuthorizationDenied(AuthorizationCode.REPLAY_CONFLICT, "idempotency key conflict", request_id=request_id)
        except AuthorizationDenied:
            raise
        except SQLAlchemyError as exc:
            raise AuthorizationDenied(AuthorizationCode.AUDIT_UNAVAILABLE, "pre-submit audit failed", request_id=request_id) from exc
        return ReplayCheck(ReplayStatus.NEW, request_id=request_id, action_digest=digest)

    return _connection_call(bind, _reserve)


# Short aliases retained for transport and worker callers that use the terms
# "request" and "replay" rather than the full MCP names.
authorize_mcp_request = authorize_mcp_tool_request
check_replay = check_mcp_request_replay
reserve_request = reserve_mcp_request
AuthorizationError = AuthorizationDenied


__all__ = [
    "AuthorizationCode",
    "AuthorizationDenied",
    "AuthorizationError",
    "AuthorizedMCPContext",
    "MCPToolRequest",
    "ReplayCheck",
    "ReplayStatus",
    "authorize_mcp_request",
    "authorize_mcp_tool_request",
    "check_mcp_request_replay",
    "check_replay",
    "reserve_mcp_request",
    "reserve_request",
]
