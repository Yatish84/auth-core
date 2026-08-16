"""Prepare the auth namespace and PostgreSQL extensions.

Revision ID: 0001_prepare_auth_schema
Revises:
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0001_prepare_auth_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")
    op.execute("CREATE SCHEMA IF NOT EXISTS auth")


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS auth CASCADE")
