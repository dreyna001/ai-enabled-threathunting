"""Focused MCP connector tests with an injected transport and SQLite ledger."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import Boolean, Column, DateTime, Integer, MetaData, String, Table, create_engine

from threat_hunting.db import deterministic_sid
from threat_hunting.domain.errors import FailureCategory
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.mcp import (
    MCPConnectionConfig,
    MCPConnector,
    deterministic_job_id,
    deterministic_request_id,
)


NOW = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


@pytest.fixture()
def database() -> object:
    """Build the MCP request ledger shape used by the production migration."""

    metadata = MetaData()
    Table(
        "mcp_tool_requests",
        metadata,
        Column("request_id", String(128), primary_key=True),
        Column("authenticated_subject", String(200), nullable=False),
        Column("idempotency_key", String(200), nullable=False),
        Column("action_digest", String(64), nullable=False),
        Column("tool", String(100), nullable=False),
        Column("status", String(32), nullable=False),
        Column("deployment_scope_id", String(200), nullable=False),
        Column("hunt_id", String(36), nullable=False),
        Column("execution_id", String(36)),
        Column("query_id", String(36)),
        Column("approval_id", String(36), nullable=False),
        Column("execution_config_snapshot_id", String(36), nullable=False),
        Column("deterministic_sid", String(64), nullable=False),
        Column("splunk_sid", String(200)),
        Column("attempt_count", Integer, nullable=False, default=0),
        Column("retry_count", Integer, nullable=False, default=0),
        Column("result_count", Integer),
        Column("result_bytes", Integer),
        Column("result_truncated", Boolean, nullable=False, default=False),
        Column("error_code", String(100)),
        Column("created_at_utc", DateTime(timezone=True), nullable=False),
        Column("updated_at_utc", DateTime(timezone=True), nullable=False),
        Column("submitted_at_utc", DateTime(timezone=True)),
        Column("completed_at_utc", DateTime(timezone=True)),
    )
    engine = create_engine("sqlite://")
    metadata.create_all(engine)
    return engine


class FakeMCPTransport:
    """Small callable MCP transport that records every tool invocation."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.submit_count = 0

    def call_tool(self, tool: str, arguments: dict[str, Any], *, request_id: str | None = None) -> Any:
        self.calls.append((tool, dict(arguments)))
        if tool == "search_splunk":
            self.submit_count += 1
            return {"job_id": "splunk-job-1"}
        if tool == "status":
            return {"status": "completed", "job_id": arguments["job_id"]}
        if tool == "fetch_results":
            return {"results": [{"host": "host-a"}, {"host": "host-b"}]}
        if tool == "cancel":
            return {"cancelled": True}
        raise AssertionError(f"unexpected tool: {tool}")


def make_connector(database: object, transport: FakeMCPTransport) -> MCPConnector:
    return MCPConnector(
        MCPConnectionConfig(
            endpoint="https://mcp.internal:8443",
            # These paths are intentionally absent: injection must avoid
            # opening TLS files in direct unit tests.
            ca_bundle_path="/tmp/missing-ca.pem",
            client_cert_path="/tmp/missing-client.pem",
            client_key_path="/tmp/missing-client-key.pem",
            service_subject="worker/customer-a",
        ),
        engine=database,
        transport=transport,
        clock=lambda: NOW,
    )


def submit_kwargs() -> dict[str, Any]:
    return {
        "authenticated_subject": "worker/customer-a",
        "idempotency_key": "idem-1",
        "request_id": "request-1",
        "metadata": {
            "deployment_scope_id": "customer-a",
            "hunt_id": "hunt-1",
            "execution_id": "execution-1",
            "query_id": "query-1",
            "approval_id": "approval-1",
            "execution_config_snapshot_id": "config-1",
        },
    }


def test_submit_status_fetch_and_cancel_use_injected_transport_and_ledger(database: object) -> None:
    transport = FakeMCPTransport()
    connector = make_connector(database, transport)

    job_id = connector.submit("search_splunk", {"query": "| makeresults"}, **submit_kwargs())
    assert job_id == "splunk-job-1"
    status = connector.status(job_id)
    rows = connector.fetch_results(job_id, page=0, limit=2)
    assert connector.cancel(job_id) is True

    assert status["status"] == "completed"
    assert rows == [{"host": "host-a"}, {"host": "host-b"}]
    assert [name for name, _ in transport.calls] == ["search_splunk", "status", "fetch_results", "cancel"]
    record = connector.reconstruct_request("request-1")
    assert record.splunk_sid == "splunk-job-1"
    assert record.status == "cancelled"
    assert record.result_count == 2
    assert record.deterministic_sid == deterministic_sid("request-1")


def test_exact_replay_reconstructs_durable_job_without_duplicate_submission(database: object) -> None:
    first_transport = FakeMCPTransport()
    first = make_connector(database, first_transport)
    assert first.submit("search_splunk", {"query": "| makeresults"}, **submit_kwargs()) == "splunk-job-1"

    second_transport = FakeMCPTransport()
    second = make_connector(database, second_transport)
    assert second.submit("search_splunk", {"query": "| makeresults"}, **submit_kwargs()) == "splunk-job-1"
    assert second_transport.calls == []
    assert second.load_request("request-1").job_id == "splunk-job-1"


def test_conflicting_replay_is_rejected_before_transport(database: object) -> None:
    transport = FakeMCPTransport()
    connector = make_connector(database, transport)
    connector.submit("search_splunk", {"query": "| makeresults"}, **submit_kwargs())

    with pytest.raises(Exception, match="conflicts with prior action"):
        connector.submit("search_splunk", {"query": "| search host=other"}, **submit_kwargs())
    assert transport.submit_count == 1


def test_deterministic_request_and_job_ids_are_stable_and_opaque() -> None:
    digest = "a" * 64
    request_a = deterministic_request_id("worker/customer-a", "idem-1", digest)
    request_b = deterministic_request_id("worker/customer-a", "idem-1", digest)
    assert request_a == request_b
    assert request_a != deterministic_request_id("worker/customer-a", "idem-2", digest)
    assert "idem-1" not in request_a
    assert deterministic_job_id(request_a) == deterministic_job_id(request_a)
    assert deterministic_job_id(request_a) == deterministic_sid(request_a)


def test_injected_transport_bypasses_missing_certificates() -> None:
    transport = FakeMCPTransport()
    connector = MCPConnector(
        MCPConnectionConfig(
            endpoint="https://mcp.internal:8443",
            ca_bundle_path="/tmp/missing-ca.pem",
            client_cert_path="/tmp/missing-client.pem",
            client_key_path="/tmp/missing-client-key.pem",
        ),
        transport=transport,
    )
    assert connector.submit("search_splunk", {"query": "| makeresults"})



class ReconcileMCPTransport(FakeMCPTransport):
    def call_tool(self, tool: str, arguments: dict[str, Any], *, request_id: str | None = None) -> Any:
        if tool == "status":
            self.calls.append((tool, dict(arguments)))
            return {"status": "submitted", "job_id": "splunk-job-recovered"}
        return super().call_tool(tool, arguments, request_id=request_id)


class TimeoutOnceMCPTransport(FakeMCPTransport):
    def __init__(self) -> None:
        super().__init__()
        self.timed_out = False

    def call_tool(self, tool: str, arguments: dict[str, Any], *, request_id: str | None = None) -> Any:
        if tool == "search_splunk" and not self.timed_out:
            self.timed_out = True
            self.calls.append((tool, dict(arguments)))
            raise TimeoutError("provider timed out")
        return super().call_tool(tool, arguments, request_id=request_id)


def test_reserved_submit_is_reconciled_after_persistence_crash(database: object) -> None:
    transport = FakeMCPTransport()
    connector = make_connector(database, transport)
    original_write = connector._write
    crash_once = True

    def crash_after_external_submit(values: Any, *, request_id: str, insert: bool = False) -> None:
        nonlocal crash_once
        if crash_once and not insert and "splunk_sid" in values:
            crash_once = False
            raise AdapterError(FailureCategory.DATABASE_FAILURE, "ledger write failed", operation="ledger")
        original_write(values, request_id=request_id, insert=insert)

    connector._write = crash_after_external_submit  # type: ignore[method-assign]
    with pytest.raises(AdapterError) as error:
        connector.submit("search_splunk", {"query": "| makeresults"}, **submit_kwargs())
    assert error.value.category is FailureCategory.DATABASE_FAILURE
    assert transport.submit_count == 1
    assert connector.reconstruct_request("request-1").status == "reserved"

    recovery_transport = ReconcileMCPTransport()
    recovered = make_connector(database, recovery_transport)
    assert recovered.submit("search_splunk", {"query": "| makeresults"}, **submit_kwargs()) == "splunk-job-recovered"
    assert [name for name, _ in recovery_transport.calls] == ["status"]
    assert recovered.load_request("request-1").status == "submitted"


def test_timeout_marks_submit_unknown_and_replay_reconciles_without_resubmitting(database: object) -> None:
    transport = TimeoutOnceMCPTransport()
    connector = make_connector(database, transport)

    with pytest.raises(AdapterError) as error:
        connector.submit("search_splunk", {"query": "| makeresults"}, **submit_kwargs())
    assert error.value.category is FailureCategory.HARD_TIMEOUT
    assert connector.load_request("request-1").status == "unknown"

    assert connector.submit("search_splunk", {"query": "| makeresults"}, **submit_kwargs()) == deterministic_job_id("request-1")
    assert [name for name, _ in transport.calls] == ["search_splunk", "status"]


def test_pre_cancelled_submit_records_failure_without_transport_call(database: object) -> None:
    class CancelledToken:
        cancelled = True

    transport = FakeMCPTransport()
    connector = make_connector(database, transport)
    with pytest.raises(AdapterError) as error:
        connector.submit("search_splunk", {"query": "| makeresults"}, cancellation_token=CancelledToken(), **submit_kwargs())

    assert error.value.category is FailureCategory.CANCELLED
    assert transport.calls == []
    record = connector.load_request("request-1")
    assert record.status == "failed"
    assert record.error_code == FailureCategory.CANCELLED.value
