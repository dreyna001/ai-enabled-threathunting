from threat_hunting.db import MIGRATION_HEAD, action_digest, deterministic_sid
from threat_hunting.services.schema import audit_records, execution_authorization_revocations, mcp_tool_requests


def test_runtime_migration_head_matches_latest_auth_uploads_jobs_revision() -> None:
    assert MIGRATION_HEAD == "0011_auth_uploads_jobs"


def test_mcp_request_ledger_binds_authorization_without_raw_payload_columns() -> None:
    columns = set(mcp_tool_requests.c.keys())
    assert {
        "request_id",
        "authenticated_subject",
        "idempotency_key",
        "action_digest",
        "tool",
        "status",
        "query_id",
        "hunt_id",
        "approval_id",
        "execution_config_snapshot_id",
        "deterministic_sid",
        "retry_count",
        "attempt_count",
        "result_count",
        "result_bytes",
        "result_truncated",
    } <= columns
    assert not {"spl", "entity", "results"} & columns
    assert mcp_tool_requests.c.request_id.primary_key
    assert any(
        {column.name for column in constraint.columns}
        == {"authenticated_subject", "idempotency_key"}
        for constraint in mcp_tool_requests.constraints
        if constraint.name == "uq_mcp_tool_request_subject_idempotency"
    )
    assert audit_records.c.metadata.nullable
    assert "revoked_at_utc" in execution_authorization_revocations.c


def test_mcp_correlation_identifiers_are_deterministic_and_opaque() -> None:
    action = {"tool": "search_authentication", "query_id": "q-1", "limit": 100}
    assert action_digest(action) == action_digest(dict(reversed(tuple(action.items()))))
    assert deterministic_sid("request-1") == deterministic_sid("request-1")
    assert deterministic_sid("request-1") != deterministic_sid("request-2")
    assert "request-1" not in deterministic_sid("request-1")
