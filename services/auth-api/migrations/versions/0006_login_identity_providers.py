"""Add the approved Microsoft identity-provider boundary.

Revision ID: 0006_login_identity_providers
Revises: 0005_registration_constraints
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0006_login_identity_providers"
down_revision: str | None = "0005_registration_constraints"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_identities_provider_valid"), "identities", schema="auth")
    op.create_check_constraint(
        op.f("ck_identities_provider_valid"),
        "identities",
        "provider IN ('password', 'google', 'apple', 'microsoft', 'phone')",
        schema="auth",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_identities_provider_valid"), "identities", schema="auth")
    op.create_check_constraint(
        op.f("ck_identities_provider_valid"),
        "identities",
        "provider IN ('password', 'google', 'apple', 'phone')",
        schema="auth",
    )
