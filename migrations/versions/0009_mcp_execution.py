"""Persist MCP authorization outcomes and security audit metadata.

Revision ID: 0009_mcp_execution
Revises: 0008_execution
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0009_mcp_execution"
down_revision = "0008_execution"
branch_labels = None
depends_on = None


_AUDIT_METADATA_CONSTRAINT = "ck_audit_records_metadata_bounded"


def _audit_columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns("audit_records")}


def _create_audit_records_if_missing() -> None:
    inspector = sa.inspect(op.get_bind())
    if "audit_records" in inspector.get_table_names():
        if "metadata" not in _audit_columns():
            op.add_column("audit_records", sa.Column("metadata", sa.JSON(), nullable=True))
        existing_checks = {
            constraint.get("name") for constraint in inspector.get_check_constraints("audit_records")
        }
        if op.get_bind().dialect.name == "postgresql" and _AUDIT_METADATA_CONSTRAINT not in existing_checks:
            op.create_check_constraint(
                _AUDIT_METADATA_CONSTRAINT,
                "audit_records",
                "metadata IS NULL OR length(CAST(metadata AS TEXT)) <= 32768",
            )
        return

    op.create_table(
        "audit_records",
        sa.Column("audit_id", sa.String(length=36), primary_key=True),
        sa.Column("hunt_id", sa.String(length=36), nullable=True),
        sa.Column("owner_id", sa.String(length=36), nullable=True),
        sa.Column("request_id", sa.String(length=128), nullable=True),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.String(length=200), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("object_type", sa.String(length=100), nullable=True),
        sa.Column("object_id", sa.String(length=200), nullable=True),
        sa.Column("prior_state", sa.String(length=32), nullable=True),
        sa.Column("resulting_state", sa.String(length=32), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("detail", sa.String(length=2000), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("timestamp_utc", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "metadata IS NULL OR length(CAST(metadata AS TEXT)) <= 32768",
            name=_AUDIT_METADATA_CONSTRAINT,
        ),
    )


def upgrade() -> None:
    _create_audit_records_if_missing()

    op.create_table(
        "mcp_tool_requests",
        sa.Column("request_id", sa.String(length=128), primary_key=True, unique=True),
        sa.Column("authenticated_subject", sa.String(length=200), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("action_digest", sa.String(length=64), nullable=False),
        sa.Column("tool", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("deployment_scope_id", sa.String(length=200), nullable=False),
        sa.Column("hunt_id", sa.String(length=36), nullable=False),
        sa.Column("execution_id", sa.String(length=36), nullable=True),
        sa.Column("query_id", sa.String(length=36), nullable=True),
        sa.Column("approval_id", sa.String(length=36), nullable=False),
        sa.Column("execution_config_snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("deterministic_sid", sa.String(length=64), nullable=False),
        sa.Column("splunk_sid", sa.String(length=200), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("result_count", sa.Integer(), nullable=True),
        sa.Column("result_bytes", sa.Integer(), nullable=True),
        sa.Column("result_truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("submitted_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "authenticated_subject",
            "idempotency_key",
            name="uq_mcp_tool_request_subject_idempotency",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_mcp_tool_request_attempt_count_nonnegative"),
        sa.CheckConstraint("retry_count >= 0", name="ck_mcp_tool_request_retry_count_nonnegative"),
        sa.CheckConstraint("result_count IS NULL OR result_count >= 0", name="ck_mcp_tool_request_result_count_nonnegative"),
        sa.CheckConstraint("result_bytes IS NULL OR result_bytes >= 0", name="ck_mcp_tool_request_result_bytes_nonnegative"),
    )

    op.create_table(
        "execution_authorization_revocations",
        sa.Column("revocation_id", sa.String(length=36), primary_key=True),
        sa.Column("deployment_scope_id", sa.String(length=200), nullable=False),
        sa.Column("execution_id", sa.String(length=36), nullable=True),
        sa.Column("hunt_id", sa.String(length=36), nullable=False),
        sa.Column("approval_id", sa.String(length=36), nullable=False),
        sa.Column("reason_code", sa.String(length=100), nullable=False),
        sa.Column("revoked_by_subject", sa.String(length=200), nullable=False),
        sa.Column("revoked_at_utc", sa.DateTime(timezone=True), nullable=False),
    )

    # PostgreSQL enforces append-only revocations at the database boundary.
    # Other dialects still receive the append-only shape and can exercise the
    # migration contract without requiring PL/pgSQL.
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            """
            CREATE FUNCTION reject_execution_authorization_revocation_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'execution authorization revocations are append-only';
            END;
            $$
            """
        )
        op.execute(
            """
            CREATE TRIGGER execution_authorization_revocations_append_only
            BEFORE UPDATE OR DELETE ON execution_authorization_revocations
            FOR EACH ROW
            EXECUTE FUNCTION reject_execution_authorization_revocation_mutation()
            """
        )
    elif op.get_bind().dialect.name == "sqlite":
        op.execute(
            """
            CREATE TRIGGER execution_authorization_revocations_append_only_update
            BEFORE UPDATE ON execution_authorization_revocations
            BEGIN
                SELECT RAISE(ABORT, 'execution authorization revocations are append-only');
            END
            """
        )
        op.execute(
            """
            CREATE TRIGGER execution_authorization_revocations_append_only_delete
            BEFORE DELETE ON execution_authorization_revocations
            BEGIN
                SELECT RAISE(ABORT, 'execution authorization revocations are append-only');
            END
            """
        )
def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS execution_authorization_revocations_append_only "
            "ON execution_authorization_revocations"
        )
        op.execute("DROP FUNCTION IF EXISTS reject_execution_authorization_revocation_mutation()")
    elif op.get_bind().dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS execution_authorization_revocations_append_only_update")
        op.execute("DROP TRIGGER IF EXISTS execution_authorization_revocations_append_only_delete")

    op.drop_table("execution_authorization_revocations")
    op.drop_table("mcp_tool_requests")

    inspector = sa.inspect(op.get_bind())
    if "audit_records" in inspector.get_table_names() and _AUDIT_METADATA_CONSTRAINT in {
        constraint.get("name") for constraint in inspector.get_check_constraints("audit_records")
    }:
        if op.get_bind().dialect.name == "postgresql":
            op.drop_constraint(_AUDIT_METADATA_CONSTRAINT, "audit_records", type_="check")
        if "metadata" in _audit_columns():
            op.drop_column("audit_records", "metadata")
