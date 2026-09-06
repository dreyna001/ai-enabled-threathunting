"""Bounded client adapter for the internal threat-hunting MCP service.

The worker talks to MCP through this small application-owned adapter rather
than depending on a particular MCP SDK.  The default transport uses stdlib
HTTPS and mTLS.  Tests (and local component harnesses) can inject a callable
transport, which keeps certificate material and a live MCP service out of
unit tests.

Only request metadata and hashes are persisted.  Query arguments and provider
responses are passed through the transport but are never written to the MCP
request ledger.
"""

from __future__ import annotations

import inspect
import json
import re
import ssl
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import MetaData, Table, and_, or_, select
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from threat_hunting.db import action_digest, deterministic_sid
from threat_hunting.domain.errors import FailureCategory

from .errors import AdapterError


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_JOB_KEYS = ("job_id", "splunk_sid", "sid", "name", "id")
_TERMINAL_STATES = {
    "cancelled",
    "canceled",
    "completed",
    "failed",
    "succeeded",
    "success",
    "stopped",
    "terminal",
}


class MCPTransport(Protocol):
    """Minimal injected transport contract used by :class:`MCPConnector`."""

    def call_tool(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        *,
        request_id: str | None = None,
        timeout_seconds: float = 30.0,
        cancellation_token: Any = None,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class MCPConnectionConfig:
    """Validated MCP endpoint and mTLS settings.

    Certificate paths are deliberately not opened during construction.  This
    permits injected transports to run without certificate files while still
    making the default transport fail closed when it needs them.
    """

    endpoint: str
    ca_bundle_path: Path | str | None = None
    client_cert_path: Path | str | None = None
    client_key_path: Path | str | None = None
    service_subject: str | None = None
    verify_tls: bool = True
    lab_only_allow_insecure: bool = False
    timeout_seconds: float = 30.0
    max_response_bytes: int = 8 * 1024 * 1024
    submit_tool: str = "search_splunk"

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("MCP endpoint must be an absolute http(s) URL")
        if parsed.username or parsed.password:
            raise ValueError("MCP endpoint must not embed credentials")
        if parsed.scheme == "http" and self.verify_tls and not self.lab_only_allow_insecure:
            raise ValueError("TLS verification requires an https MCP endpoint")
        if not self.verify_tls and not self.lab_only_allow_insecure:
            raise ValueError("TLS verification can be disabled only in an explicitly enabled lab")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 300:
            raise ValueError("timeout_seconds must be greater than 0 and at most 300")
        if self.max_response_bytes <= 0 or self.max_response_bytes > 64 * 1024 * 1024:
            raise ValueError("max_response_bytes is outside the supported bound")
        if not self.submit_tool or len(self.submit_tool) > 100:
            raise ValueError("submit_tool must be a non-empty short identifier")
        for field_name in ("ca_bundle_path", "client_cert_path", "client_key_path"):
            value = getattr(self, field_name)
            if value is not None:
                path = Path(value)
                if not path.is_absolute():
                    raise ValueError(f"{field_name} must be absolute")
                object.__setattr__(self, field_name, path)
        if self.service_subject is not None and not self.service_subject.strip():
            raise ValueError("service_subject must not be blank")

    @property
    def url(self) -> str:
        """Return the configured MCP endpoint without credentials."""

        return self.endpoint


@dataclass(frozen=True, slots=True)
class MCPRequestRecord:
    """Safe, durable request metadata reconstructed from the request ledger."""

    request_id: str
    authenticated_subject: str
    idempotency_key: str
    action_digest: str
    tool: str
    status: str
    deployment_scope_id: str
    hunt_id: str
    execution_id: str | None
    query_id: str | None
    approval_id: str
    execution_config_snapshot_id: str
    deterministic_sid: str
    splunk_sid: str | None = None
    attempt_count: int = 0
    retry_count: int = 0
    result_count: int | None = None
    result_bytes: int | None = None
    result_truncated: bool = False
    error_code: str | None = None

    @property
    def job_id(self) -> str:
        """Return the provider job ID, or the deterministic pending ID."""

        return self.splunk_sid or self.deterministic_sid

    def as_dict(self) -> dict[str, Any]:
        """Return only persisted, non-sensitive request metadata."""

        return {
            "request_id": self.request_id,
            "authenticated_subject": self.authenticated_subject,
            "idempotency_key": self.idempotency_key,
            "action_digest": self.action_digest,
            "tool": self.tool,
            "status": self.status,
            "deployment_scope_id": self.deployment_scope_id,
            "hunt_id": self.hunt_id,
            "execution_id": self.execution_id,
            "query_id": self.query_id,
            "approval_id": self.approval_id,
            "execution_config_snapshot_id": self.execution_config_snapshot_id,
            "deterministic_sid": self.deterministic_sid,
            "splunk_sid": self.splunk_sid,
            "attempt_count": self.attempt_count,
            "retry_count": self.retry_count,
            "result_count": self.result_count,
            "result_bytes": self.result_bytes,
            "result_truncated": self.result_truncated,
            "error_code": self.error_code,
        }


def deterministic_request_id(
    authenticated_subject: str,
    idempotency_key: str,
    action_digest_value: str,
) -> str:
    """Derive a stable opaque request ID from a subject-scoped action.

    UUIDv5 gives callers a familiar identifier while preserving deterministic
    replay behavior.  The action digest is already a SHA-256 value and is not
    expanded into the persisted request payload.
    """

    if not authenticated_subject or not idempotency_key or not action_digest_value:
        raise ValueError("subject, idempotency_key, and action digest are required")
    if not _HASH_RE.fullmatch(str(action_digest_value)):
        raise ValueError("action digest must be lowercase SHA-256 hex")
    name = f"mcp:{authenticated_subject}:{idempotency_key}:{action_digest_value}"
    return str(uuid5(NAMESPACE_URL, name))


def deterministic_job_id(request_id: str) -> str:
    """Return the stable opaque pending-job ID associated with a request."""

    return deterministic_sid(request_id)


def _is_cancelled(token: Any) -> bool:
    if token is None:
        return False
    checker = getattr(token, "is_cancelled", None)
    if callable(checker):
        return bool(checker())
    checker = getattr(token, "is_set", None)
    if callable(checker):
        return bool(checker())
    return bool(getattr(token, "cancelled", False))


def _utc(value: datetime | None) -> datetime:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("MCP timestamps must include a timezone")
    return timestamp.astimezone(timezone.utc)


def _bounded_json(value: Any, *, max_bytes: int) -> Any:
    """Normalize a transport result while enforcing its response byte cap."""

    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AdapterError(
            FailureCategory.UNKNOWN,
            "MCP returned a non-JSON response",
            operation="transport",
        ) from exc
    if len(encoded) > max_bytes:
        raise AdapterError(
            FailureCategory.VALIDATION_FAILURE,
            "MCP response exceeds the configured byte limit",
            operation="transport",
        )
    return value


def _decode_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _unwrap(value: Any) -> Any:
    """Unwrap common JSON-RPC/FastMCP response envelopes."""

    value = _decode_text(value)
    if isinstance(value, Mapping):
        if "error" in value:
            raise AdapterError(FailureCategory.UNKNOWN, "MCP tool call failed", operation="transport")
        if set(value) == {"result"}:
            return _unwrap(value["result"])
        content = value.get("content")
        if isinstance(content, list) and content:
            texts = [item.get("text") for item in content if isinstance(item, Mapping) and "text" in item]
            if len(texts) == 1:
                return _unwrap(texts[0])
            if texts:
                return [_unwrap(item) for item in texts]
        return value
    if isinstance(value, list):
        return [_unwrap(item) for item in value]
    return value


def _first_job_id(value: Any) -> str | None:
    value = _unwrap(value)
    if isinstance(value, Mapping):
        for key in _JOB_KEYS:
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        for key in ("data", "result", "job", "metadata"):
            if key in value:
                found = _first_job_id(value[key])
                if found:
                    return found
    return None


def _safe_status(value: Any) -> str | None:
    value = _unwrap(value)
    if not isinstance(value, Mapping):
        return None
    for key in ("status", "state", "job_status"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()[:32]
    return None


class _HTTPSJSONTransport:
    """Small stdlib MCP JSON-RPC transport used outside tests."""

    def __init__(self, config: MCPConnectionConfig) -> None:
        self.config = config

    def call_tool(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        *,
        request_id: str | None = None,
        timeout_seconds: float = 30.0,
        cancellation_token: Any = None,
    ) -> Any:
        if _is_cancelled(cancellation_token):
            raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation=tool)
        payload = {
            "jsonrpc": "2.0",
            "id": request_id or tool,
            "method": "tools/call",
            "params": {"name": tool, "arguments": dict(arguments)},
        }
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request = Request(
            self.config.url,
            data=body,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="POST",
        )
        context: ssl.SSLContext | None = None
        if urlsplit(self.config.url).scheme == "https":
            context = ssl.create_default_context(cafile=str(self.config.ca_bundle_path) if self.config.ca_bundle_path else None)
            if not self.config.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            if self.config.client_cert_path is None or self.config.client_key_path is None:
                raise AdapterError(
                    FailureCategory.INVALID_CONFIGURATION,
                    "MCP mTLS certificate and key are required",
                    operation=tool,
                )
            try:
                context.load_cert_chain(str(self.config.client_cert_path), str(self.config.client_key_path))
            except (OSError, ssl.SSLError) as exc:
                raise AdapterError(
                    FailureCategory.INVALID_CONFIGURATION,
                    "MCP mTLS certificate configuration is invalid",
                    operation=tool,
                ) from exc
        try:
            with urlopen(request, timeout=timeout_seconds, context=context) as response:
                raw = response.read(self.config.max_response_bytes + 1)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                category = FailureCategory.INVALID_CREDENTIALS if exc.code == 401 else FailureCategory.PERMISSION_DENIED
            elif exc.code == 429:
                category = FailureCategory.RATE_LIMITED
            elif exc.code >= 500:
                category = FailureCategory.PROVIDER_SERVER_ERROR
            else:
                category = FailureCategory.UNKNOWN
            raise AdapterError(category, "MCP service rejected the tool call", operation=tool) from exc
        except ssl.SSLError as exc:
            raise AdapterError(FailureCategory.TLS_CERTIFICATE_FAILURE, "MCP TLS verification failed", operation=tool) from exc
        except TimeoutError as exc:
            raise AdapterError(FailureCategory.HARD_TIMEOUT, "MCP operation exceeded its transport timeout", operation=tool) from exc
        except (URLError, ConnectionError, OSError) as exc:
            raise AdapterError(FailureCategory.TEMPORARY_NETWORK, "MCP connection failed", operation=tool) from exc
        if len(raw) > self.config.max_response_bytes:
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "MCP response exceeds the configured byte limit", operation=tool)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdapterError(FailureCategory.UNKNOWN, "MCP returned malformed JSON", operation=tool) from exc


class MCPConnector:
    """Application-owned MCP client with durable submit/replay semantics."""

    def __init__(
        self,
        config: MCPConnectionConfig,
        *,
        engine: Engine | Connection | None = None,
        database: Engine | Connection | None = None,
        transport: MCPTransport | Callable[..., Any] | None = None,
        tool_call: MCPTransport | Callable[..., Any] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if engine is not None and database is not None:
            raise ValueError("configure only one MCP database binding")
        if transport is not None and tool_call is not None:
            raise ValueError("configure only one MCP transport")
        self.config = config
        self.engine = engine or database
        self._transport = transport or tool_call or _HTTPSJSONTransport(config)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _table(conn: Connection) -> Table | None:
        try:
            return Table("mcp_tool_requests", MetaData(), autoload_with=conn)
        except SQLAlchemyError:
            return None

    @contextmanager
    def _connection(self, *, write: bool) -> Iterator[Connection | None]:
        if self.engine is None:
            yield None
            return
        if isinstance(self.engine, Connection):
            yield self.engine
            return
        context = self.engine.begin() if write else self.engine.connect()
        with context as conn:
            yield conn

    def _call_transport(
        self,
        operation: str,
        tool: str,
        arguments: Mapping[str, Any],
        *,
        request_id: str | None,
        cancellation_token: Any = None,
        allow_cancelled: bool = False,
    ) -> Any:
        if not allow_cancelled and _is_cancelled(cancellation_token):
            raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation=operation)
        callback = getattr(self._transport, "call_tool", None)
        if not callable(callback):
            callback = self._transport
        if not callable(callback):
            raise AdapterError(FailureCategory.INVALID_CONFIGURATION, "MCP transport is not callable", operation=operation)
        kwargs: dict[str, Any] = {}
        try:
            parameters = inspect.signature(callback).parameters
            accepts_kwargs = any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values())
        except (TypeError, ValueError):
            parameters = {}
            accepts_kwargs = True
        for name, value in (
            ("request_id", request_id),
            ("timeout_seconds", self.config.timeout_seconds),
            ("cancellation_token", cancellation_token),
        ):
            if accepts_kwargs or name in parameters:
                kwargs[name] = value
        try:
            result = callback(tool, MappingProxyType(dict(arguments)), **kwargs)
        except AdapterError:
            raise
        except ssl.SSLError as exc:
            raise AdapterError(FailureCategory.TLS_CERTIFICATE_FAILURE, "MCP TLS verification failed", operation=operation) from exc
        except TimeoutError as exc:
            raise AdapterError(FailureCategory.HARD_TIMEOUT, "MCP operation exceeded its transport timeout", operation=operation) from exc
        except (ConnectionError, OSError) as exc:
            raise AdapterError(FailureCategory.TEMPORARY_NETWORK, "MCP connection failed", operation=operation) from exc
        except Exception as exc:  # noqa: BLE001 - normalize injected provider errors
            raise AdapterError(FailureCategory.UNKNOWN, "MCP operation failed", operation=operation) from exc
        if not allow_cancelled and _is_cancelled(cancellation_token):
            raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation=operation)
        return _bounded_json(result, max_bytes=self.config.max_response_bytes)

    @staticmethod
    def _extract_envelope(
        tool: str | Mapping[str, Any] | None,
        arguments: Mapping[str, Any] | None,
        *,
        query: str | None,
    ) -> tuple[str, dict[str, Any], dict[str, Any]]:
        """Normalize generic and ``submit(query)``-style caller envelopes."""

        metadata: dict[str, Any] = {}
        if isinstance(tool, Mapping):
            envelope = dict(tool)
            selected_tool = envelope.pop("tool", None) or envelope.pop("operation", None)
            selected_args = envelope.pop("arguments", None) or envelope.pop("params", None)
            if arguments is not None:
                selected_args = arguments
            if selected_args is None:
                selected_args = {key: value for key, value in envelope.items() if key not in {
                    "request_id", "authenticated_subject", "worker_id", "idempotency_key", "action_digest",
                    "deployment_scope_id", "hunt_id", "execution_id", "query_id", "approval_id",
                    "execution_config_snapshot_id", "config_snapshot_id",
                }}
            metadata = envelope
            tool = selected_tool
            arguments = selected_args
        if not isinstance(tool, str) or not tool.strip():
            tool = "search_splunk"
        if arguments is None:
            arguments = {"query": query} if query is not None else {}
        if not isinstance(arguments, Mapping):
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "MCP arguments must be an object", operation="submit")
        return tool.strip(), dict(arguments), metadata

    def _prepare_submit(
        self,
        tool: str | Mapping[str, Any] | None,
        arguments: Mapping[str, Any] | None,
        *,
        query: str | None,
        request_id: str | None,
        authenticated_subject: str | None,
        idempotency_key: str | None,
        action_digest_value: str | None,
        metadata: Mapping[str, Any] | None,
    ) -> tuple[str, dict[str, Any], dict[str, Any]]:
        selected_tool, selected_args, envelope = self._extract_envelope(tool, arguments, query=query)
        all_metadata = {**envelope, **dict(metadata or {})}
        subject = str(authenticated_subject or all_metadata.get("authenticated_subject") or self.config.service_subject or "mcp-client")
        key = str(idempotency_key or all_metadata.get("idempotency_key") or "")
        action_fields = {
            "tool": selected_tool,
            "arguments": selected_args,
            "deployment_scope_id": all_metadata.get("deployment_scope_id"),
            "hunt_id": all_metadata.get("hunt_id"),
            "execution_id": all_metadata.get("execution_id"),
            "query_id": all_metadata.get("query_id"),
            "approval_id": all_metadata.get("approval_id"),
            "execution_config_snapshot_id": all_metadata.get("execution_config_snapshot_id") or all_metadata.get("config_snapshot_id"),
        }
        explicit_digest = action_digest_value or all_metadata.get("action_digest")
        if explicit_digest is not None:
            digest = str(explicit_digest)
            if not _HASH_RE.fullmatch(digest):
                raise AdapterError(FailureCategory.VALIDATION_FAILURE, "action digest must be lowercase SHA-256 hex", operation="submit")
        else:
            try:
                digest = action_digest(action_fields)
            except ValueError as exc:
                raise AdapterError(FailureCategory.VALIDATION_FAILURE, "MCP arguments must be JSON-serializable", operation="submit") from exc
        if not key:
            key = f"mcp-{digest}"
        resolved_request_id = request_id or all_metadata.get("request_id")
        if not resolved_request_id:
            resolved_request_id = deterministic_request_id(subject, key, digest)
        resolved_request_id = str(resolved_request_id)
        if len(resolved_request_id) > 128 or not resolved_request_id:
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "request_id must contain 1 to 128 characters", operation="submit")
        all_metadata.update({
            "authenticated_subject": subject,
            "idempotency_key": key,
            "action_digest": digest,
            "request_id": resolved_request_id,
            "tool": selected_tool,
            "deployment_scope_id": str(all_metadata.get("deployment_scope_id") or ""),
            "hunt_id": str(all_metadata.get("hunt_id") or ""),
            "approval_id": str(all_metadata.get("approval_id") or ""),
            "execution_config_snapshot_id": str(all_metadata.get("execution_config_snapshot_id") or all_metadata.get("config_snapshot_id") or ""),
        })
        return selected_tool, selected_args, all_metadata

    def _row(self, conn: Connection, *, request_id: str | None = None, job_id: str | None = None) -> dict[str, Any] | None:
        table = self._table(conn)
        if table is None:
            return None
        predicates = []
        if request_id is not None and "request_id" in table.c:
            predicates.append(table.c.request_id == request_id)
        if job_id is not None:
            for column_name in ("splunk_sid", "deterministic_sid", "request_id"):
                if column_name in table.c:
                    predicates.append(table.c[column_name] == job_id)
        if not predicates:
            return None
        try:
            row = conn.execute(select(table).where(predicates[0] if len(predicates) == 1 else or_(*predicates)).limit(1)).mappings().first()
        except SQLAlchemyError as exc:
            raise AdapterError(FailureCategory.DATABASE_FAILURE, "MCP request ledger read failed", operation="ledger") from exc
        return dict(row) if row is not None else None

    @staticmethod
    def _record(row: Mapping[str, Any]) -> MCPRequestRecord:
        def text(name: str, default: str = "") -> str:
            value = row.get(name, default)
            return default if value is None else str(value)

        def integer(name: str, default: int = 0) -> int:
            value = row.get(name, default)
            return default if value is None else int(value)

        return MCPRequestRecord(
            request_id=text("request_id"),
            authenticated_subject=text("authenticated_subject"),
            idempotency_key=text("idempotency_key"),
            action_digest=text("action_digest"),
            tool=text("tool"),
            status=text("status"),
            deployment_scope_id=text("deployment_scope_id"),
            hunt_id=text("hunt_id"),
            execution_id=row.get("execution_id"),
            query_id=row.get("query_id"),
            approval_id=text("approval_id"),
            execution_config_snapshot_id=text("execution_config_snapshot_id"),
            deterministic_sid=text("deterministic_sid"),
            splunk_sid=row.get("splunk_sid"),
            attempt_count=integer("attempt_count"),
            retry_count=integer("retry_count"),
            result_count=row.get("result_count"),
            result_bytes=row.get("result_bytes"),
            result_truncated=bool(row.get("result_truncated", False)),
            error_code=row.get("error_code"),
        )

    def _write(self, values: Mapping[str, Any], *, request_id: str, insert: bool = False) -> None:
        if self.engine is None:
            return
        with self._connection(write=True) as conn:
            if conn is None:
                return
            table = self._table(conn)
            if table is None:
                raise AdapterError(FailureCategory.DATABASE_FAILURE, "MCP request ledger is unavailable", operation="ledger")
            data = {key: value for key, value in values.items() if key in table.c}
            try:
                if insert:
                    conn.execute(table.insert().values(**data))
                else:
                    conn.execute(table.update().where(table.c.request_id == request_id).values(**data))
            except IntegrityError as exc:
                raise AdapterError(FailureCategory.DATABASE_FAILURE, "MCP request ledger write conflicted", operation="ledger") from exc
            except SQLAlchemyError as exc:
                raise AdapterError(FailureCategory.DATABASE_FAILURE, "MCP request ledger write failed", operation="ledger") from exc

    def _load_replay(self, subject: str, key: str, digest: str) -> dict[str, Any] | None:
        if self.engine is None:
            return None
        with self._connection(write=False) as conn:
            if conn is None:
                return None
            table = self._table(conn)
            if table is None:
                raise AdapterError(FailureCategory.DATABASE_FAILURE, "MCP request ledger is unavailable", operation="ledger")
            try:
                row = conn.execute(
                    select(table)
                    .where(and_(table.c.authenticated_subject == subject, table.c.idempotency_key == key))
                    .limit(1)
                ).mappings().first()
            except SQLAlchemyError as exc:
                raise AdapterError(FailureCategory.DATABASE_FAILURE, "MCP request ledger read failed", operation="ledger") from exc
            if row is None:
                return None
            result = dict(row)
        if str(result.get("action_digest")) != digest:
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "MCP idempotency key conflicts with prior action", operation="submit")
        return result

    def reconstruct_request(self, request_id: str) -> MCPRequestRecord:
        """Load safe request metadata so a new worker can resume polling."""

        if not isinstance(request_id, str) or not request_id.strip():
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "request_id must be non-empty", operation="reconstruct")
        if self.engine is None:
            raise AdapterError(FailureCategory.DATABASE_FAILURE, "MCP request ledger is unavailable", operation="reconstruct")
        with self._connection(write=False) as conn:
            assert conn is not None
            row = self._row(conn, request_id=request_id)
        if row is None:
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "MCP request was not found", operation="reconstruct")
        return self._record(row)

    load_request = reconstruct_request

    def _resolve_job(self, job_id: str) -> tuple[str, MCPRequestRecord | None]:
        if not isinstance(job_id, str) or not job_id.strip():
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "job_id must be non-empty", operation="job")
        if self.engine is None:
            return job_id.strip(), None
        with self._connection(write=False) as conn:
            assert conn is not None
            row = self._row(conn, job_id=job_id.strip())
        if row is None:
            return job_id.strip(), None
        record = self._record(row)
        return record.splunk_sid or record.deterministic_sid, record

    def _reconcile_reserved(self, row: Mapping[str, Any]) -> str:
        """Reconcile a reserved submit without issuing a duplicate submit."""

        request_id = str(row.get("request_id") or "")
        pending_id = str(row.get("splunk_sid") or row.get("deterministic_sid") or deterministic_job_id(request_id))
        result = self._call_transport(
            "reconcile",
            "status",
            {"job_id": pending_id, "request_id": request_id},
            request_id=request_id,
        )
        found_job = _first_job_id(result)
        if not found_job:
            raise AdapterError(FailureCategory.UNKNOWN, "MCP submit outcome is unresolved", operation="submit")
        now = _utc(self._clock())
        self._write({"status": "submitted", "splunk_sid": found_job, "submitted_at_utc": now, "updated_at_utc": now}, request_id=request_id)
        return found_job

    def submit(
        self,
        tool: str | Mapping[str, Any] | None = None,
        arguments: Mapping[str, Any] | None = None,
        *,
        query: str | None = None,
        request: Mapping[str, Any] | None = None,
        request_id: str | None = None,
        authenticated_subject: str | None = None,
        idempotency_key: str | None = None,
        action_digest_value: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        cancellation_token: Any = None,
    ) -> str:
        """Submit one MCP search and return its provider job ID.

        A ledger row is reserved before the external call.  An exact replay
        returns the persisted provider job ID; a conflicting idempotency key
        is rejected.  A reserved row is reconciled through status and is never
        blindly submitted a second time.
        """

        if request is not None:
            if tool is not None:
                raise AdapterError(FailureCategory.VALIDATION_FAILURE, "provide either request or tool, not both", operation="submit")
            tool = request
        selected_tool, selected_args, envelope = self._prepare_submit(
            self.config.submit_tool
            if isinstance(tool, str)
            and arguments is None
            and query is None
            and (tool.lstrip().startswith("|") or " " in tool.strip())
            else tool if tool is not None else self.config.submit_tool,
            arguments,
            query=tool if isinstance(tool, str)
            and arguments is None
            and query is None
            and (tool.lstrip().startswith("|") or " " in tool.strip())
            else query,
            request_id=request_id,
            authenticated_subject=authenticated_subject,
            idempotency_key=idempotency_key,
            action_digest_value=action_digest_value,
            metadata=metadata,
        )
        subject = str(envelope["authenticated_subject"])
        key = str(envelope["idempotency_key"])
        digest = str(envelope["action_digest"])
        request_id = str(envelope["request_id"])
        replay = self._load_replay(subject, key, digest)
        if replay is not None:
            persisted_job = replay.get("splunk_sid")
            if isinstance(persisted_job, str) and persisted_job:
                return persisted_job
            return self._reconcile_reserved(replay)
        now = _utc(self._clock())
        pending_job = deterministic_job_id(request_id)
        row_values = {
            **envelope,
            "status": "reserved",
            "deterministic_sid": pending_job,
            "attempt_count": 1,
            "retry_count": 0,
            "result_truncated": False,
            "created_at_utc": now,
            "updated_at_utc": now,
        }
        try:
            self._write(row_values, request_id=request_id, insert=True)
        except AdapterError:
            # A concurrent worker may have won the subject/idempotency race.
            # Re-read the ledger before treating the insert error as fatal.
            replay = self._load_replay(subject, key, digest)
            if replay is None:
                raise
            persisted_job = replay.get("splunk_sid")
            if isinstance(persisted_job, str) and persisted_job:
                return persisted_job
            return self._reconcile_reserved(replay)
        call_args = dict(selected_args)
        call_args.update({"request_id": request_id, "deterministic_sid": pending_job})
        try:
            result = self._call_transport("submit", selected_tool, call_args, request_id=request_id, cancellation_token=cancellation_token)
            provider_job = _first_job_id(result) or pending_job
        except AdapterError as exc:
            status = "unknown" if exc.category in {
                FailureCategory.TEMPORARY_NETWORK,
                FailureCategory.RATE_LIMITED,
                FailureCategory.PROVIDER_SERVER_ERROR,
                FailureCategory.HARD_TIMEOUT,
            } else "failed"
            self._write({"status": status, "error_code": exc.category.value, "updated_at_utc": _utc(self._clock())}, request_id=request_id)
            raise
        self._write({"status": "submitted", "splunk_sid": provider_job, "submitted_at_utc": _utc(self._clock()), "updated_at_utc": _utc(self._clock()), "error_code": None}, request_id=request_id)
        return provider_job

    def status(self, job_id: str, *, cancellation_token: Any = None) -> Mapping[str, Any]:
        """Fetch provider status and update the durable request state."""

        provider_job, record = self._resolve_job(job_id)
        result = _unwrap(self._call_transport("status", "status", {"job_id": provider_job}, request_id=record.request_id if record else None, cancellation_token=cancellation_token))
        if not isinstance(result, Mapping):
            result = {"status": str(result)}
        if record:
            state = _safe_status(result)
            values: dict[str, Any] = {"updated_at_utc": _utc(self._clock())}
            if state:
                values["status"] = state
                if state.lower() in _TERMINAL_STATES:
                    values["completed_at_utc"] = _utc(self._clock())
            self._write(values, request_id=record.request_id)
        return dict(result)

    job_metadata = status

    def fetch_results(
        self,
        job_id: str,
        page: int = 0,
        limit: int = 100,
        *,
        max_bytes: int | None = None,
        cancellation_token: Any = None,
    ) -> list[Mapping[str, Any]]:
        """Fetch one bounded result page and account for its size."""

        if page < 0 or limit <= 0 or limit > 10_000:
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "invalid result page or limit", operation="fetch_results")
        if max_bytes is not None and max_bytes <= 0:
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "invalid result byte limit", operation="fetch_results")
        provider_job, record = self._resolve_job(job_id)
        value = _unwrap(self._call_transport(
            "fetch_results",
            "fetch_results",
            {"job_id": provider_job, "page": page, "limit": limit},
            request_id=record.request_id if record else None,
            cancellation_token=cancellation_token,
        ))
        if isinstance(value, Mapping):
            for key in ("results", "items", "records", "data"):
                if key in value:
                    value = _unwrap(value[key])
                    break
        truncated = False
        if isinstance(value, Mapping):
            rows: list[Mapping[str, Any]] = [value]
        elif isinstance(value, list):
            truncated = len(value) > limit
            rows = [item if isinstance(item, Mapping) else {"value": item} for item in value[:limit]]
        else:
            rows = []
        encoded = json.dumps(rows, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
        if max_bytes is not None and len(encoded) > max_bytes:
            raise AdapterError(FailureCategory.BUDGET_EXHAUSTED, "MCP result exceeded the configured byte limit", operation="fetch_results")
        if record:
            self._write({"result_count": len(rows), "result_bytes": len(encoded), "result_truncated": truncated, "updated_at_utc": _utc(self._clock())}, request_id=record.request_id)
        return rows[:limit]

    def cancel(self, job_id: str, *, cancellation_token: Any = None) -> bool:
        """Cancel a provider job and record the terminal request state."""

        provider_job, record = self._resolve_job(job_id)
        result = _unwrap(self._call_transport(
            "cancel",
            "cancel",
            {"job_id": provider_job},
            request_id=record.request_id if record else None,
            cancellation_token=None,
            allow_cancelled=True,
        ))
        cancelled = True
        if isinstance(result, Mapping):
            for key in ("cancelled", "canceled", "success", "ok"):
                if key in result:
                    cancelled = bool(result[key])
                    break
        if record and cancelled:
            now = _utc(self._clock())
            self._write({"status": "cancelled", "completed_at_utc": now, "updated_at_utc": now}, request_id=record.request_id)
        return cancelled

    def request_metadata(self, request_id: str) -> Mapping[str, Any]:
        """Compatibility accessor for safe durable request reconstruction."""

        return self.reconstruct_request(request_id).as_dict()


# Names used by callers that refer to the MCP client rather than connector.
MCPClient = MCPConnector
MCPConfig = MCPConnectionConfig


__all__ = [
    "MCPClient",
    "MCPConfig",
    "MCPConnectionConfig",
    "MCPConnector",
    "MCPRequestRecord",
    "MCPTransport",
    "deterministic_job_id",
    "deterministic_request_id",
]
