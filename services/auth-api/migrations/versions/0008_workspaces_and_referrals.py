"""Add personal workspaces and referral attribution.

Revision ID: 0008_workspaces_and_referrals
Revises: 0007_mfa_replay_protection
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_workspaces_and_referrals"
down_revision: str | None = "0007_mfa_replay_protection"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "workspace_type",
            sa.String(length=24),
            server_default="organization",
            nullable=False,
        ),
        schema="auth",
    )
    op.add_column(
        "organizations",
        sa.Column("personal_owner_user_id", sa.UUID(), nullable=True),
        schema="auth",
    )
    op.create_foreign_key(
        "fk_organizations_personal_owner_user_id_users",
        "organizations",
        "users",
        ["personal_owner_user_id"],
        ["user_id"],
        source_schema="auth",
        referent_schema="auth",
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_auth_organizations_personal_owner_user_id",
        "organizations",
        ["personal_owner_user_id"],
        schema="auth",
    )
    op.create_index(
        "uq_organizations_personal_owner",
        "organizations",
        ["personal_owner_user_id"],
        unique=True,
        schema="auth",
        postgresql_where=sa.text("workspace_type = 'personal'"),
    )
    op.execute(
        """
        INSERT INTO auth.organizations (
            org_id, name, slug, workspace_type, personal_owner_user_id, state
        )
        SELECT
            gen_random_uuid(),
            CASE
                WHEN NULLIF(trim(concat_ws(' ', given_name, family_name)), '') IS NULL
                    THEN 'My Personal Portfolio'
                ELSE trim(concat_ws(' ', given_name, family_name)) || '''s Portfolio'
            END,
            'personal-' || replace(user_id::text, '-', ''),
            'personal',
            user_id,
            'active'
        FROM auth.users
        WHERE anonymized_at IS NULL
        ON CONFLICT DO NOTHING
        """
    )
    op.create_check_constraint(
        "owner_matches_workspace_type",
        "organizations",
        "(workspace_type = 'personal' AND personal_owner_user_id IS NOT NULL) OR "
        "(workspace_type = 'organization' AND personal_owner_user_id IS NULL)",
        schema="auth",
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION auth.user_has_org_membership(
            target_org_id uuid,
            target_user_id uuid
        )
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = auth, pg_temp
        AS $$
            SELECT EXISTS (
                SELECT 1
                FROM auth.user_role_bindings
                WHERE org_id = target_org_id
                  AND user_id = target_user_id
                  AND revoked_at IS NULL
            )
        $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION auth.user_has_org_membership(uuid, uuid) FROM PUBLIC")
    op.execute(
        "GRANT EXECUTE ON FUNCTION auth.user_has_org_membership(uuid, uuid) TO auth_app"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION auth.organization_invitation_org(candidate_hash text)
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = auth, pg_temp
        AS $$
            SELECT org_id
            FROM auth.invitations
            WHERE token_hash = candidate_hash
              AND state = 'pending'
              AND expires_at > now()
            LIMIT 1
        $$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION auth.organization_invitation_org(text) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION auth.organization_invitation_org(text) TO auth_app"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION auth.reject_personal_workspace_collaboration()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM auth.organizations
                WHERE org_id = NEW.org_id AND workspace_type = 'personal'
            ) THEN
                RAISE EXCEPTION 'personal workspaces cannot have invitations or role bindings'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    for table in ("invitations", "user_role_bindings"):
        op.execute(
            f"""
            CREATE TRIGGER {table}_organization_only
            BEFORE INSERT OR UPDATE OF org_id ON auth.{table}
            FOR EACH ROW EXECUTE FUNCTION auth.reject_personal_workspace_collaboration()
            """
        )
    op.execute("DROP POLICY organizations_tenant_isolation ON auth.organizations")
    current_org = "NULLIF(current_setting('app.current_org_id', true), '')::uuid"
    current_user = "NULLIF(current_setting('app.current_user_id', true), '')::uuid"
    op.execute(
        f"""
        CREATE POLICY organizations_tenant_isolation ON auth.organizations
        FOR ALL TO auth_app
        USING (
            (workspace_type = 'personal' AND personal_owner_user_id = {current_user})
            OR org_id = {current_org}
            OR auth.user_has_org_membership(org_id, {current_user})
        )
        WITH CHECK (
            (workspace_type = 'personal' AND personal_owner_user_id = {current_user})
            OR org_id = {current_org}
            OR auth.user_has_org_membership(org_id, {current_user})
        )
        """
    )
    op.execute(
        """
        INSERT INTO auth.role_permission_catalog (
            catalog_id, module, role, permission, version, active
        )
        SELECT gen_random_uuid(), seed.module, seed.role, seed.permission, 1, true
        FROM (VALUES
            ('workspace', 'OWNER', 'workspace.manage'),
            ('workspace', 'OWNER', 'members.manage'),
            ('portfolio', 'OWNER', 'portfolio.read'),
            ('portfolio', 'OWNER', 'portfolio.write'),
            ('portfolio', 'MEMBER', 'portfolio.read'),
            ('portfolio', 'MEMBER', 'portfolio.write'),
            ('portfolio', 'VIEWER', 'portfolio.read')
        ) AS seed(module, role, permission)
        WHERE NOT EXISTS (
            SELECT 1
            FROM auth.role_permission_catalog existing
            WHERE existing.module = seed.module
              AND existing.role = seed.role
              AND existing.permission = seed.permission
              AND existing.version = 1
        )
        """
    )

    op.create_table(
        "referrals",
        sa.Column("referral_id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("referrer_user_id", sa.UUID(), nullable=False),
        sa.Column("invitee_email", postgresql.CITEXT(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("referred_user_id", sa.UUID(), nullable=True),
        sa.Column("state", sa.String(length=24), server_default="invited", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('invited', 'registered', 'verified', 'expired', 'revoked')",
            name=op.f("ck_referrals_state_valid"),
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name=op.f("ck_referrals_expiry_after_creation"),
        ),
        sa.ForeignKeyConstraint(
            ["referrer_user_id"],
            ["auth.users.user_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["referred_user_id"],
            ["auth.users.user_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("referral_id"),
        sa.UniqueConstraint("token_hash"),
        schema="auth",
    )
    op.create_index(
        "ix_auth_referrals_referrer_user_id",
        "referrals",
        ["referrer_user_id"],
        schema="auth",
    )
    op.create_index(
        "ix_auth_referrals_referred_user_id",
        "referrals",
        ["referred_user_id"],
        schema="auth",
    )
    op.create_index(
        "ix_referrals_referrer_created",
        "referrals",
        ["referrer_user_id", "created_at"],
        schema="auth",
    )
    op.create_index(
        "uq_referrals_referred_user",
        "referrals",
        ["referred_user_id"],
        unique=True,
        schema="auth",
        postgresql_where=sa.text("referred_user_id IS NOT NULL"),
    )
    op.execute("ALTER TABLE auth.referrals ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE auth.referrals FORCE ROW LEVEL SECURITY")
    current_user = "NULLIF(current_setting('app.current_user_id', true), '')::uuid"
    op.execute(
        f"""
        CREATE POLICY referrals_user_isolation ON auth.referrals
        FOR ALL TO auth_app
        USING (referrer_user_id = {current_user} OR referred_user_id = {current_user})
        WITH CHECK (referrer_user_id = {current_user} OR referred_user_id = {current_user})
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS referrals_user_isolation ON auth.referrals")
    op.drop_table("referrals", schema="auth")
    op.execute("DROP POLICY organizations_tenant_isolation ON auth.organizations")
    for table in ("user_role_bindings", "invitations"):
        op.execute(f"DROP TRIGGER IF EXISTS {table}_organization_only ON auth.{table}")
    op.execute("DROP FUNCTION IF EXISTS auth.reject_personal_workspace_collaboration()")
    op.execute("DROP FUNCTION IF EXISTS auth.organization_invitation_org(text)")
    current_org = "NULLIF(current_setting('app.current_org_id', true), '')::uuid"
    op.execute(
        f"""
        CREATE POLICY organizations_tenant_isolation ON auth.organizations
        FOR ALL TO auth_app
        USING (org_id = {current_org})
        WITH CHECK (org_id = {current_org})
        """
    )
    op.execute("DROP FUNCTION IF EXISTS auth.user_has_org_membership(uuid, uuid)")
    op.drop_constraint(
        op.f("ck_organizations_owner_matches_workspace_type"),
        "organizations",
        schema="auth",
        type_="check",
    )
    op.drop_index("uq_organizations_personal_owner", table_name="organizations", schema="auth")
    op.drop_index(
        "ix_auth_organizations_personal_owner_user_id",
        table_name="organizations",
        schema="auth",
    )
    op.drop_constraint(
        op.f("fk_organizations_personal_owner_user_id_users"),
        "organizations",
        schema="auth",
        type_="foreignkey",
    )
    op.drop_column("organizations", "personal_owner_user_id", schema="auth")
    op.drop_column("organizations", "workspace_type", schema="auth")
