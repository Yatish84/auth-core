"""Add MFA replay and usage tracking.

Revision ID: 0007_mfa_replay_protection
Revises: 0006_login_identity_providers
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_mfa_replay_protection"
down_revision: str | None = "0006_login_identity_providers"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mfa_devices", sa.Column("last_totp_step", sa.BigInteger()), schema="auth"
    )
    op.add_column(
        "mfa_devices",
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_column("mfa_devices", "last_used_at", schema="auth")
    op.drop_column("mfa_devices", "last_totp_step", schema="auth")
