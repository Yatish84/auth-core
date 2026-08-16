"""Add database roles, tenant isolation, and immutable auditing.

Revision ID: 0003_secure_roles_rls_audit
Revises: 349e932027c8
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003_secure_roles_rls_audit"
down_revision: str | None = "349e932027c8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_TABLES = (
    "organizations",
    "invitations",
    "user_role_bindings",
    "sessions",
    "governed_requests",
    "audit_logs",
)


def upgrade() -> None:
    for role in ("auth_migration", "auth_app", "auth_audit_reader", "auth_break_glass"):
        op.execute(
            f"""
            DO $$
            BEGIN
                CREATE ROLE {role} NOLOGIN;
            EXCEPTION WHEN duplicate_object THEN
                NULL;
            END
            $$
            """
        )

    op.execute("GRANT USAGE ON SCHEMA auth TO auth_app, auth_audit_reader")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth TO auth_app")
    op.execute("GRANT SELECT ON auth.audit_logs TO auth_audit_reader")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON auth.audit_logs FROM auth_app")
    op.execute(
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE "
        "ON auth.role_permission_catalog FROM auth_app"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA auth "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_app"
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION auth.reject_audit_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'audit records are immutable' USING ERRCODE = '55000';
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_logs_immutable
        BEFORE UPDATE OR DELETE ON auth.audit_logs
        FOR EACH ROW EXECUTE FUNCTION auth.reject_audit_mutation()
        """
    )

    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE auth.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE auth.{table} FORCE ROW LEVEL SECURITY")

    current_org = "NULLIF(current_setting('app.current_org_id', true), '')::uuid"
    current_user = "NULLIF(current_setting('app.current_user_id', true), '')::uuid"

    op.execute(
        f"""
        CREATE POLICY organizations_tenant_isolation ON auth.organizations
        FOR ALL TO auth_app
        USING (org_id = {current_org})
        WITH CHECK (org_id = {current_org})
        """
    )
    for table in ("invitations", "user_role_bindings"):
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON auth.{table}
            FOR ALL TO auth_app
            USING (org_id = {current_org})
            WITH CHECK (org_id = {current_org})
            """
        )
    op.execute(
        f"""
        CREATE POLICY sessions_tenant_isolation ON auth.sessions
        FOR ALL TO auth_app
        USING (
            org_id = {current_org}
            OR (org_id IS NULL AND user_id = {current_user})
        )
        WITH CHECK (
            org_id = {current_org}
            OR (org_id IS NULL AND user_id = {current_user})
        )
        """
    )
    op.execute(
        f"""
        CREATE POLICY governed_requests_tenant_isolation ON auth.governed_requests
        FOR ALL TO auth_app
        USING (
            org_id = {current_org}
            OR (org_id IS NULL AND target_user_id = {current_user})
        )
        WITH CHECK (
            org_id = {current_org}
            OR (org_id IS NULL AND target_user_id = {current_user})
        )
        """
    )
    op.execute(
        f"""
        CREATE POLICY audit_logs_tenant_isolation ON auth.audit_logs
        FOR ALL TO auth_app
        USING (
            org_id = {current_org}
            OR (
                org_id IS NULL
                AND (subject_user_id = {current_user} OR actor_user_id = {current_user})
            )
        )
        WITH CHECK (
            org_id = {current_org}
            OR (
                org_id IS NULL
                AND (subject_user_id = {current_user} OR actor_user_id = {current_user})
            )
        )
        """
    )


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON auth.{table}")
        op.execute(f"ALTER TABLE auth.{table} DISABLE ROW LEVEL SECURITY")

    op.execute("DROP TRIGGER IF EXISTS audit_logs_immutable ON auth.audit_logs")
    op.execute("DROP FUNCTION IF EXISTS auth.reject_audit_mutation()")
    op.execute("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA auth FROM auth_app")
    op.execute("REVOKE ALL PRIVILEGES ON SCHEMA auth FROM auth_app, auth_audit_reader")
    for role in ("auth_break_glass", "auth_audit_reader", "auth_app", "auth_migration"):
        op.execute(f"DROP ROLE IF EXISTS {role}")
