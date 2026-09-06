"""Production local auth, bounded uploads, durable jobs, and retention tasks.

Revision ID: 0011_auth_uploads_jobs
Revises: 0010_vertical_slice
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0011_auth_uploads_jobs"
down_revision = "0010_vertical_slice"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("workflow_sessions", sa.Column("csrf_hash", sa.String(length=64), nullable=False, server_default=""))
    op.create_table(
        "uploads",
        sa.Column("upload_id", sa.String(length=36), primary_key=True),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("hunt_id", sa.String(length=36), nullable=False),
        sa.Column("original_filename", sa.String(length=500), nullable=False),
        sa.Column("detected_type", sa.String(length=100), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("uploader_id", sa.String(length=36), nullable=False),
        sa.Column("uploaded_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("parser_version", sa.String(length=50), nullable=False),
        sa.Column("extraction_status", sa.String(length=32), nullable=False),
        sa.Column("extraction_error", sa.String(length=2000), nullable=True),
        sa.Column("storage_path", sa.String(length=1000), nullable=False),
        sa.Column("extracted_text", sa.Text(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=True),
    )
    op.create_index("ix_uploads_owner_id", "uploads", ["owner_id"])
    op.create_index("ix_uploads_hunt_id", "uploads", ["hunt_id"])
    op.create_table(
        "execution_jobs",
        sa.Column("job_id", sa.String(length=36), primary_key=True),
        sa.Column("hunt_id", sa.String(length=36), nullable=False),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("deployment_scope_id", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("worker_id", sa.String(length=200), nullable=True),
        sa.Column("lease_expires_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False, unique=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at_utc", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_execution_jobs_hunt_id", "execution_jobs", ["hunt_id"])
    op.create_index("ix_execution_jobs_owner_id", "execution_jobs", ["owner_id"])
    op.create_table(
        "retention_cleanup_tasks",
        sa.Column("task_id", sa.String(length=36), primary_key=True),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("hunt_id", sa.String(length=36), nullable=False, unique=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("cursor", sa.JSON(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error", sa.JSON(), nullable=True),
        sa.Column("claimed_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at_utc", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("retention_cleanup_tasks")
    op.drop_index("ix_execution_jobs_owner_id", table_name="execution_jobs")
    op.drop_index("ix_execution_jobs_hunt_id", table_name="execution_jobs")
    op.drop_table("execution_jobs")
    op.drop_index("ix_uploads_hunt_id", table_name="uploads")
    op.drop_index("ix_uploads_owner_id", table_name="uploads")
    op.drop_table("uploads")
    op.drop_column("workflow_sessions", "csrf_hash")
