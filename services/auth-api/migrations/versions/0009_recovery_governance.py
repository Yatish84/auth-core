"""Add account recovery and governed administration state.

Revision ID: 0009_recovery_governance
Revises: 0008_workspaces_and_referrals
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_recovery_governance"
down_revision: str | None = "0008_workspaces_and_referrals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("ck_ephemeral_tokens_purpose_valid", "ephemeral_tokens", schema="auth")
    op.create_check_constraint(
        "purpose_valid",
        "ephemeral_tokens",
        "purpose IN ('email_verify', 'phone_verify', 'password_reset', 'support_recovery', 'invite')",
        schema="auth",
    )
    op.add_column(
        "governed_requests", sa.Column("approved_at", sa.DateTime(timezone=True)), schema="auth"
    )
    op.add_column(
        "governed_requests", sa.Column("executed_at", sa.DateTime(timezone=True)), schema="auth"
    )
    op.add_column(
        "governed_requests",
        sa.Column("target_user_version", sa.Integer(), server_default="1", nullable=False),
        schema="auth",
    )
    op.create_table(
        "staff_role_bindings",
        sa.Column("binding_id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("role", sa.String(length=48), nullable=False),
        sa.Column("granted_by_user_id", sa.UUID()),
        sa.Column("granted_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "role IN ('SUPPORT_AGENT_L2', 'SECURITY_SUPERVISOR_L3', 'ACCOUNT_ADMIN')",
            name=op.f("ck_staff_role_bindings_role_valid"),
        ),
        sa.ForeignKeyConstraint(["user_id"], ["auth.users.user_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["granted_by_user_id"], ["auth.users.user_id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("binding_id"),
        schema="auth",
    )
    op.create_index(
        "ix_auth_staff_role_bindings_user_id",
        "staff_role_bindings",
        ["user_id"],
        schema="auth",
    )
    op.create_index(
        "uq_staff_role_bindings_active",
        "staff_role_bindings",
        ["user_id", "role"],
        unique=True,
        schema="auth",
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.execute(
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON auth.staff_role_bindings FROM auth_app"
    )
    op.create_table(
        "contact_change_requests",
        sa.Column("request_id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("contact_type", sa.String(length=16), nullable=False),
        sa.Column("old_value", sa.String(length=320), nullable=False),
        sa.Column("new_value", sa.String(length=320), nullable=False),
        sa.Column("old_code_hash", sa.String(length=128), nullable=False),
        sa.Column("new_code_hash", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=24), server_default="pending", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("old_verified_at", sa.DateTime(timezone=True)),
        sa.Column("new_verified_at", sa.DateTime(timezone=True)),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("contact_type IN ('email', 'phone')", name=op.f("ck_contact_change_requests_contact_type_valid")),
        sa.CheckConstraint("state IN ('pending', 'applied', 'expired', 'cancelled')", name=op.f("ck_contact_change_requests_state_valid")),
        sa.CheckConstraint("expires_at > created_at", name=op.f("ck_contact_change_requests_expiry_after_creation")),
        sa.ForeignKeyConstraint(["user_id"], ["auth.users.user_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("request_id"),
        schema="auth",
    )
    op.create_index(
        "ix_auth_contact_change_requests_user_id",
        "contact_change_requests",
        ["user_id"],
        schema="auth",
    )
    op.create_index(
        "ix_contact_changes_user_pending",
        "contact_change_requests",
        ["user_id", "state", "expires_at"],
        schema="auth",
    )
    op.execute("ALTER TABLE auth.contact_change_requests ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE auth.contact_change_requests FORCE ROW LEVEL SECURITY")
    current_user = "NULLIF(current_setting('app.current_user_id', true), '')::uuid"
    op.execute(
        f"""
        CREATE POLICY contact_change_requests_user_isolation
        ON auth.contact_change_requests
        FOR ALL TO auth_app
        USING (user_id = {current_user})
        WITH CHECK (user_id = {current_user})
        """
    )
    op.execute(
        """
        INSERT INTO auth.password_history (history_id, identity_id, password_hash)
        SELECT gen_random_uuid(), identity_id, password_hash
        FROM auth.identities identity
        WHERE provider = 'password'
          AND password_hash IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM auth.password_history history
              WHERE history.identity_id = identity.identity_id
          )
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION auth.current_user_is_staff()
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = auth, pg_temp
        AS $$
            SELECT EXISTS (
                SELECT 1 FROM auth.staff_role_bindings
                WHERE user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
                  AND revoked_at IS NULL
            )
        $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION auth.current_user_is_staff() FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION auth.current_user_is_staff() TO auth_app")
    op.execute("DROP POLICY governed_requests_tenant_isolation ON auth.governed_requests")
    op.execute(
        f"""
        CREATE POLICY governed_requests_tenant_isolation ON auth.governed_requests
        FOR ALL TO auth_app
        USING (target_user_id = {current_user} OR auth.current_user_is_staff())
        WITH CHECK (target_user_id = {current_user} OR auth.current_user_is_staff())
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY governed_requests_tenant_isolation ON auth.governed_requests")
    current_user = "NULLIF(current_setting('app.current_user_id', true), '')::uuid"
    op.execute(
        f"""
        CREATE POLICY governed_requests_tenant_isolation ON auth.governed_requests
        FOR ALL TO auth_app
        USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid OR (org_id IS NULL AND target_user_id = {current_user}))
        WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid OR (org_id IS NULL AND target_user_id = {current_user}))
        """
    )
    op.execute("DROP FUNCTION IF EXISTS auth.current_user_is_staff()")
    op.execute(
        "DROP POLICY IF EXISTS contact_change_requests_user_isolation "
        "ON auth.contact_change_requests"
    )
    op.execute("ALTER TABLE auth.contact_change_requests DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_contact_changes_user_pending", table_name="contact_change_requests", schema="auth")
    op.drop_index("ix_auth_contact_change_requests_user_id", table_name="contact_change_requests", schema="auth")
    op.drop_table("contact_change_requests", schema="auth")
    op.drop_index("uq_staff_role_bindings_active", table_name="staff_role_bindings", schema="auth")
    op.drop_index("ix_auth_staff_role_bindings_user_id", table_name="staff_role_bindings", schema="auth")
    op.drop_table("staff_role_bindings", schema="auth")
    op.drop_column("governed_requests", "target_user_version", schema="auth")
    op.drop_column("governed_requests", "executed_at", schema="auth")
    op.drop_column("governed_requests", "approved_at", schema="auth")
    op.drop_constraint("ck_ephemeral_tokens_purpose_valid", "ephemeral_tokens", schema="auth")
    op.create_check_constraint(
        "purpose_valid",
        "ephemeral_tokens",
        "purpose IN ('email_verify', 'phone_verify', 'password_reset', 'invite')",
        schema="auth",
    )
