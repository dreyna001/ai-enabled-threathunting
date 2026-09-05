"""SQLAlchemy Core tables for evidence-grounded hunt artifacts.

Migrations are intentionally owned by the block orchestrator.  Keeping the
table definitions here gives the services one stable vocabulary while the
migration can evolve independently.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, CheckConstraint, Column, DateTime, Integer, MetaData, String, Table, UniqueConstraint


metadata = MetaData()


evidence_records = Table(
    "evidence_records",
    metadata,
    Column("evidence_id", String(36), primary_key=True),
    Column("owner_id", String(36), nullable=False),
    Column("hunt_id", String(36), nullable=False),
    Column("query_id", String(36), nullable=False),
    Column("source_id", String(200), nullable=False),
    Column("splunk_job_id", String(200), nullable=False),
    Column("evidence_kind", String(32), nullable=False),
    Column("index", String(200), nullable=False),
    Column("sourcetype", String(200), nullable=False),
    Column("event_time_utc", DateTime(timezone=True), nullable=True),
    Column("collected_at_utc", DateTime(timezone=True), nullable=False),
    Column("source_event_ref", String(500), nullable=False),
    Column("selected_result", JSON, nullable=False),
    Column("truncation", JSON, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("dedupe_key", String(64), nullable=False),
    Column("created_at_utc", DateTime(timezone=True), nullable=False),
    UniqueConstraint("owner_id", "hunt_id", "dedupe_key", name="uq_evidence_owner_hunt_dedupe"),
)


entities = Table(
    "entities",
    metadata,
    Column("entity_id", String(36), primary_key=True),
    Column("owner_id", String(36), nullable=False),
    Column("hunt_id", String(36), nullable=False),
    Column("entity_type", String(32), nullable=False),
    Column("value", String(500), nullable=False),
    Column("result_row_refs", JSON, nullable=False),
    Column("created_at_utc", DateTime(timezone=True), nullable=False),
    UniqueConstraint("owner_id", "hunt_id", "entity_type", "value", name="uq_entity_owner_hunt_value"),
)


entity_evidence = Table(
    "entity_evidence",
    metadata,
    Column("entity_id", String(36), primary_key=True),
    Column("evidence_id", String(36), primary_key=True),
    Column("owner_id", String(36), nullable=False),
    Column("hunt_id", String(36), nullable=False),
)


pivots = Table(
    "pivots",
    metadata,
    Column("pivot_id", String(36), primary_key=True),
    Column("owner_id", String(36), nullable=False),
    Column("hunt_id", String(36), nullable=False),
    Column("entity_id", String(36), nullable=True),
    Column("pivot_type", String(64), nullable=False),
    Column("value", String(500), nullable=False),
    Column("rationale", String(2000), nullable=False),
    Column("evidence_ids", JSON, nullable=False),
    Column("query_ids", JSON, nullable=False),
    Column("created_at_utc", DateTime(timezone=True), nullable=False),
    UniqueConstraint("owner_id", "hunt_id", "pivot_type", "value", name="uq_pivot_owner_hunt_value"),
)


findings = Table(
    "findings",
    metadata,
    Column("finding_id", String(36), primary_key=True),
    Column("owner_id", String(36), nullable=False),
    Column("hunt_id", String(36), nullable=False),
    Column("title", String(500), nullable=False),
    Column("classification", String(64), nullable=False),
    Column("statement", String(4000), nullable=False),
    Column("confidence", String(32), nullable=False),
    Column("evidence_ids", JSON, nullable=False),
    Column("query_ids", JSON, nullable=False),
    Column("context_refs", JSON, nullable=False),
    Column("inference", String(4000), nullable=False),
    Column("limitations", JSON, nullable=False),
    Column("created_at_utc", DateTime(timezone=True), nullable=False),
    Column("idempotency_key", String(64), nullable=False),
    UniqueConstraint("owner_id", "hunt_id", "idempotency_key", name="uq_finding_owner_hunt_idempotency"),
)


# Reports are deliberately one-per-hunt.  ``version`` is incremented by an
# optimistic-concurrency update; the original agent draft is never replaced
# by an analyst save and the finalized fields are immutable after finalization.
reports = Table(
    "reports",
    metadata,
    Column("report_id", String(36), primary_key=True),
    Column("owner_id", String(36), nullable=False),
    Column("hunt_id", String(36), nullable=False, unique=True),
    Column("state", String(32), nullable=False, default="report_draft"),
    Column("version", Integer, nullable=False, default=1),
    Column("agent_draft", JSON, nullable=False),
    Column("draft_content", JSON, nullable=False),
    Column("final_content", JSON, nullable=True),
    Column("query_appendix", JSON, nullable=False),
    Column("finding_ids", JSON, nullable=False),
    Column("evidence_ids", JSON, nullable=False),
    Column("query_ids", JSON, nullable=False),
    Column("approved_plan_version", Integer, nullable=True),
    Column("approved_plan_sha256", String(64), nullable=True),
    Column("execution_config_snapshot_id", String(36), nullable=True),
    Column("execution_config_sha256", String(64), nullable=True),
    Column("pdf_path", String(1000), nullable=True),
    Column("pdf_sha256", String(64), nullable=True),
    Column("finalized_by_user_id", String(36), nullable=True),
    Column("finalized_at_utc", DateTime(timezone=True), nullable=True),
    Column("created_at_utc", DateTime(timezone=True), nullable=False),
    Column("updated_at_utc", DateTime(timezone=True), nullable=False),
    UniqueConstraint("owner_id", "hunt_id", name="uq_report_owner_hunt"),
)


# A durable cleanup task is separate from a transient worker lease.  A cursor
# lets a retry resume after a file or database deletion failed halfway through.
retention_cleanup_tasks = Table(
    "retention_cleanup_tasks",
    metadata,
    Column("task_id", String(36), primary_key=True),
    Column("owner_id", String(36), nullable=False),
    Column("hunt_id", String(36), nullable=False, unique=True),
    Column("state", String(32), nullable=False, default="pending"),
    Column("cursor", JSON, nullable=False),
    Column("attempts", Integer, nullable=False, default=0),
    Column("error", JSON, nullable=True),
    Column("claimed_at_utc", DateTime(timezone=True), nullable=True),
    Column("completed_at_utc", DateTime(timezone=True), nullable=True),
    Column("created_at_utc", DateTime(timezone=True), nullable=False),
    Column("updated_at_utc", DateTime(timezone=True), nullable=False),
)


# MCP requests persist only authorization and outcome metadata.  In
# particular, request payloads such as SPL, entity values, and result rows are
# deliberately absent; the canonical action digest is sufficient to correlate
# a replay without retaining sensitive input.
mcp_tool_requests = Table(
    "mcp_tool_requests",
    metadata,
    Column("request_id", String(128), primary_key=True, unique=True),
    Column("authenticated_subject", String(200), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("action_digest", String(64), nullable=False),
    Column("tool", String(100), nullable=False),
    Column("status", String(32), nullable=False),
    Column("deployment_scope_id", String(200), nullable=False),
    Column("hunt_id", String(36), nullable=False),
    Column("execution_id", String(36), nullable=True),
    Column("query_id", String(36), nullable=True),
    Column("approval_id", String(36), nullable=False),
    Column("execution_config_snapshot_id", String(36), nullable=False),
    Column("deterministic_sid", String(64), nullable=False),
    Column("splunk_sid", String(200), nullable=True),
    Column("attempt_count", Integer, nullable=False, default=0),
    Column("retry_count", Integer, nullable=False, default=0),
    Column("result_count", Integer, nullable=True),
    Column("result_bytes", Integer, nullable=True),
    Column("result_truncated", Boolean, nullable=False, default=False),
    Column("error_code", String(100), nullable=True),
    Column("created_at_utc", DateTime(timezone=True), nullable=False),
    Column("updated_at_utc", DateTime(timezone=True), nullable=False),
    Column("submitted_at_utc", DateTime(timezone=True), nullable=True),
    Column("completed_at_utc", DateTime(timezone=True), nullable=True),
    UniqueConstraint(
        "authenticated_subject",
        "idempotency_key",
        name="uq_mcp_tool_request_subject_idempotency",
    ),
    CheckConstraint("attempt_count >= 0", name="ck_mcp_tool_request_attempt_count_nonnegative"),
    CheckConstraint("retry_count >= 0", name="ck_mcp_tool_request_retry_count_nonnegative"),
    CheckConstraint("result_count IS NULL OR result_count >= 0", name="ck_mcp_tool_request_result_count_nonnegative"),
    CheckConstraint("result_bytes IS NULL OR result_bytes >= 0", name="ck_mcp_tool_request_result_bytes_nonnegative"),
)


# A revocation is a security event, not mutable request state.  The migration
# installs a database trigger on PostgreSQL so accidental updates/deletes fail
# closed in addition to the application treating this table as append-only.
execution_authorization_revocations = Table(
    "execution_authorization_revocations",
    metadata,
    Column("revocation_id", String(36), primary_key=True),
    Column("deployment_scope_id", String(200), nullable=False),
    Column("execution_id", String(36), nullable=True),
    Column("hunt_id", String(36), nullable=False),
    Column("approval_id", String(36), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("revoked_by_subject", String(200), nullable=False),
    Column("revoked_at_utc", DateTime(timezone=True), nullable=False),
)


# Phase 4 owns the broader audit contract.  Keep this definition here for a
# clean import in a foundation checkout, while appending only the new nullable
# metadata column when a later schema definition already exists.
audit_records = metadata.tables.get("audit_records")
if audit_records is None:
    audit_records = Table(
        "audit_records",
        metadata,
        Column("audit_id", String(36), primary_key=True),
        Column("hunt_id", String(36), nullable=True),
        Column("owner_id", String(36), nullable=True),
        Column("request_id", String(128), nullable=True),
        Column("actor_type", String(32), nullable=False),
        Column("actor_id", String(200), nullable=True),
        Column("action", String(100), nullable=False),
        Column("object_type", String(100), nullable=True),
        Column("object_id", String(200), nullable=True),
        Column("prior_state", String(32), nullable=True),
        Column("resulting_state", String(32), nullable=True),
        Column("outcome", String(32), nullable=False),
        Column("detail", String(2000), nullable=True),
        Column("metadata", JSON, nullable=True),
        Column("timestamp_utc", DateTime(timezone=True), nullable=False),
        CheckConstraint(
            "metadata IS NULL OR length(CAST(metadata AS TEXT)) <= 32768",
            name="ck_audit_records_metadata_bounded",
        ),
    )
elif "metadata" not in audit_records.c:
    audit_records.append_column(Column("metadata", JSON, nullable=True))

if audit_records is not None and not any(
    constraint.name == "ck_audit_records_metadata_bounded" for constraint in audit_records.constraints
):
    audit_records.append_constraint(
        CheckConstraint(
            "metadata IS NULL OR length(CAST(metadata AS TEXT)) <= 32768",
            name="ck_audit_records_metadata_bounded",
        )
    )


__all__ = [
    "metadata",
    "evidence_records",
    "entities",
    "entity_evidence",
    "pivots",
    "findings",
    "reports",
    "retention_cleanup_tasks",
    "mcp_tool_requests",
    "execution_authorization_revocations",
    "audit_records",
]
