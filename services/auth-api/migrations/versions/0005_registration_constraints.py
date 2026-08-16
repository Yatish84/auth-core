"""Add registration contact constraints.

Revision ID: 0005_registration_constraints
Revises: 0004_enforce_catalog_and_version
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005_registration_constraints"
down_revision: str | None = "0004_enforce_catalog_and_version"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "uq_users_phone_active",
        "users",
        ["phone_e164"],
        unique=True,
        schema="auth",
        postgresql_where="phone_e164 IS NOT NULL AND anonymized_at IS NULL",
    )


def downgrade() -> None:
    op.drop_index("uq_users_phone_active", table_name="users", schema="auth")
