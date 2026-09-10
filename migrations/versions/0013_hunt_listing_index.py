"""Index owner-scoped hunt summary pages.

Revision ID: 0013_hunt_listing_index
Revises: 0012_security_hardening
"""

from alembic import op

revision = "0013_hunt_listing_index"
down_revision = "0012_security_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_workflow_hunts_owner_created_id", "workflow_hunts",
        ["owner_id", "created_at_utc", "hunt_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_workflow_hunts_owner_created_id", table_name="workflow_hunts")
