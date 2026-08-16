"""Add encrypted, owner-isolated privacy export artifacts.

Revision ID: 0011_privacy_export_artifacts
Revises: 0010_audit_query_access
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_privacy_export_artifacts"
down_revision: str | None = "0010_audit_query_access"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "gdpr_requests",
        sa.Column("idempotency_key_hash", sa.String(length=128)),
        schema="auth",
    )
    op.create_unique_constraint(
        "uq_gdpr_requests_user_id",
        "gdpr_requests",
        ["user_id", "request_type", "idempotency_key_hash"],
        schema="auth",
    )
    op.create_table(
        "privacy_export_artifacts",
        sa.Column(
            "artifact_id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("gdpr_request_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("encrypted_content", sa.LargeBinary(), nullable=False),
        sa.Column("content_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["gdpr_request_id"],
            ["auth.gdpr_requests.gdpr_request_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["auth.users.user_id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("artifact_id"),
        sa.UniqueConstraint("gdpr_request_id"),
        schema="auth",
    )
    op.create_index(
        "ix_auth_privacy_export_artifacts_user_id",
        "privacy_export_artifacts",
        ["user_id"],
        schema="auth",
    )
    op.create_index(
        "ix_privacy_export_artifacts_expiry",
        "privacy_export_artifacts",
        ["expires_at"],
        schema="auth",
    )
    current_user = "NULLIF(current_setting('app.current_user_id', true), '')::uuid"
    for table in ("gdpr_requests", "privacy_export_artifacts"):
        op.execute(f"ALTER TABLE auth.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE auth.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_user_isolation ON auth.{table}
            FOR ALL TO auth_app
            USING (user_id = {current_user})
            WITH CHECK (user_id = {current_user})
            """
        )


def downgrade() -> None:
    for table in ("privacy_export_artifacts", "gdpr_requests"):
        op.execute(f"DROP POLICY IF EXISTS {table}_user_isolation ON auth.{table}")
        op.execute(f"ALTER TABLE auth.{table} DISABLE ROW LEVEL SECURITY")
    op.drop_index(
        "ix_privacy_export_artifacts_expiry",
        table_name="privacy_export_artifacts",
        schema="auth",
    )
    op.drop_index(
        "ix_auth_privacy_export_artifacts_user_id",
        table_name="privacy_export_artifacts",
        schema="auth",
    )
    op.drop_table("privacy_export_artifacts", schema="auth")
    op.drop_constraint(
        "uq_gdpr_requests_user_id",
        "gdpr_requests",
        schema="auth",
        type_="unique",
    )
    op.drop_column("gdpr_requests", "idempotency_key_hash", schema="auth")
