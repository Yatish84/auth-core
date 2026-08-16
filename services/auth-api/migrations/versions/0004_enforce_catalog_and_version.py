"""Enforce active role catalog entries and positive user versions.

Revision ID: 0004_enforce_catalog_and_version
Revises: 0003_secure_roles_rls_audit
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004_enforce_catalog_and_version"
down_revision: str | None = "0003_secure_roles_rls_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_check_constraint("version_positive", "users", "version >= 1", schema="auth")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION auth.require_active_role_catalog()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM auth.role_permission_catalog
                WHERE catalog_id = NEW.catalog_id AND active = true
            ) THEN
                RAISE EXCEPTION 'role binding requires an active catalog entry'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER user_role_bindings_active_catalog
        BEFORE INSERT OR UPDATE OF catalog_id ON auth.user_role_bindings
        FOR EACH ROW EXECUTE FUNCTION auth.require_active_role_catalog()
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS user_role_bindings_active_catalog ON auth.user_role_bindings"
    )
    op.execute("DROP FUNCTION IF EXISTS auth.require_active_role_catalog()")
    op.execute(
        "ALTER TABLE auth.users DROP CONSTRAINT IF EXISTS ck_users_ck_users_version_positive"
    )
    op.execute("ALTER TABLE auth.users DROP CONSTRAINT IF EXISTS ck_users_version_positive")
