"""Track privacy erasure backup-retention deadlines.

Revision ID: 0012_privacy_erasure_retention
Revises: 0011_privacy_export_artifacts
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_privacy_erasure_retention"
down_revision: str | None = "0011_privacy_export_artifacts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "gdpr_requests",
        sa.Column("backup_purge_due_at", sa.DateTime(timezone=True)),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_column("gdpr_requests", "backup_purge_due_at", schema="auth")
