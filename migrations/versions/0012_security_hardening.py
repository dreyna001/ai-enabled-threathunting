"""Persist login throttles and atomic upload quotas.

Revision ID: 0012_security_hardening
Revises: 0011_auth_uploads_jobs
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0012_security_hardening"
down_revision = "0011_auth_uploads_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "login_rate_limits",
        sa.Column("bucket_hash", sa.String(length=64), primary_key=True),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("window_started_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("blocked_until_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at_utc", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "upload_quotas",
        sa.Column("owner_id", sa.String(length=36), primary_key=True),
        sa.Column("hunt_id", sa.String(length=36), primary_key=True),
        sa.Column("file_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("total_bytes", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.execute(
        """
        INSERT INTO upload_quotas (owner_id, hunt_id, file_count, total_bytes)
        SELECT owner_id, hunt_id, COUNT(*), COALESCE(SUM(byte_size), 0)
        FROM uploads
        GROUP BY owner_id, hunt_id
        """
    )


def downgrade() -> None:
    op.drop_table("upload_quotas")
    op.drop_table("login_rate_limits")
