"""Add owner-scoped persisted vertical-slice workflow.

Revision ID: 0010_vertical_slice
Revises: 0009_mcp_execution
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0010_vertical_slice"
down_revision = "0009_mcp_execution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workflow_users",
        sa.Column("user_id", sa.String(length=36), primary_key=True),
        sa.Column("username", sa.String(length=100), nullable=False, unique=True),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
    )
    op.create_table(
        "workflow_sessions",
        sa.Column("token_hash", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("workflow_users.user_id"), nullable=False),
        sa.Column("expires_at_utc", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "workflow_hunts",
        sa.Column("hunt_id", sa.String(length=36), primary_key=True),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("hypothesis", sa.Text(), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("threat_intelligence", sa.Text(), nullable=False),
        sa.Column("synthetic_data", sa.Text(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=True),
        sa.Column("plan", sa.JSON(), nullable=True),
        sa.Column("discovery_snapshot", sa.JSON(), nullable=True),
        sa.Column("approval", sa.JSON(), nullable=True),
        sa.Column("results", sa.JSON(), nullable=True),
        sa.Column("report_id", sa.String(length=36), nullable=True),
        sa.Column("report_version", sa.Integer(), nullable=True),
        sa.Column("report_state", sa.String(length=32), nullable=True),
        sa.Column("report_content", sa.JSON(), nullable=True),
        sa.Column("report_pdf", sa.LargeBinary(), nullable=True),
        sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at_utc", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_workflow_hunts_owner_id", "workflow_hunts", ["owner_id"])


def downgrade() -> None:
    op.drop_index("ix_workflow_hunts_owner_id", table_name="workflow_hunts")
    op.drop_table("workflow_hunts")
    op.drop_table("workflow_sessions")
    op.drop_table("workflow_users")
