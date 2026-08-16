"""Authorize controlled security audit queries.

Revision ID: 0010_audit_query_access
Revises: 0009_recovery_governance
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010_audit_query_access"
down_revision: str | None = "0009_recovery_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION auth.current_user_has_staff_role(required_role text)
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = auth, pg_temp
        AS $$
            SELECT EXISTS (
                SELECT 1 FROM auth.staff_role_bindings
                WHERE user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
                  AND role = required_role
                  AND revoked_at IS NULL
            )
        $$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION auth.current_user_has_staff_role(text) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION auth.current_user_has_staff_role(text) TO auth_app"
    )
    op.execute("DROP POLICY audit_logs_tenant_isolation ON auth.audit_logs")
    current_org = "NULLIF(current_setting('app.current_org_id', true), '')::uuid"
    current_user = "NULLIF(current_setting('app.current_user_id', true), '')::uuid"
    op.execute(
        f"""
        CREATE POLICY audit_logs_tenant_isolation ON auth.audit_logs
        FOR ALL TO auth_app
        USING (
            auth.current_user_has_staff_role('SECURITY_SUPERVISOR_L3')
            OR org_id = {current_org}
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
    op.execute("DROP POLICY audit_logs_tenant_isolation ON auth.audit_logs")
    current_org = "NULLIF(current_setting('app.current_org_id', true), '')::uuid"
    current_user = "NULLIF(current_setting('app.current_user_id', true), '')::uuid"
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
    op.execute("DROP FUNCTION IF EXISTS auth.current_user_has_staff_role(text)")
