from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_core.entity.user import UserState
from auth_core.infrastructure.persistence.user_repository import SqlAlchemyUserRepository


@pytest.mark.integration
@pytest.mark.asyncio
async def test_empty_database_upgrades_to_complete_schema(migrated_database_url: str) -> None:
    engine = create_async_engine(migrated_database_url)
    try:
        async with engine.connect() as connection:
            table_count = await connection.scalar(
                text(
                    "SELECT count(*) FROM information_schema.tables "
                    "WHERE table_schema = 'auth' AND table_type = 'BASE TABLE'"
                )
            )
            revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
        assert table_count == 20
        assert revision == "0008_workspaces_and_referrals"
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_user_repository_normalizes_email_and_prevents_stale_updates(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    repository = SqlAlchemyUserRepository(async_sessionmaker(engine, expire_on_commit=False))
    try:
        created = await repository.create("  Repository.User@Example.com ")
        loaded = await repository.get_by_email("repository.user@example.com")
        activated = await repository.change_state(
            created.user_id, created.version, UserState.ACTIVE
        )
        stale_update = await repository.change_state(
            created.user_id, created.version, UserState.LOCKED
        )

        assert loaded is not None
        assert loaded.email == "repository.user@example.com"
        assert activated is not None
        assert activated.state is UserState.ACTIVE
        assert activated.version == 2
        assert stale_update is None
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_email_and_governance_constraints_are_enforced(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    first_user = uuid4()
    second_user = uuid4()
    organization_id = uuid4()
    catalog_id = uuid4()
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO auth.users (user_id, email, state) "
                    "VALUES (:first_user, 'Person@Example.com', 'active'), "
                    "(:second_user, 'second@example.com', 'active')"
                ),
                {"first_user": first_user, "second_user": second_user},
            )
            await connection.execute(
                text(
                    "INSERT INTO auth.organizations (org_id, name, slug) "
                    "VALUES (:org_id, 'Constraint Organization', :slug)"
                ),
                {"org_id": organization_id, "slug": f"constraint-{organization_id.hex[:8]}"},
            )
            await connection.execute(
                text(
                    "INSERT INTO auth.role_permission_catalog "
                    "(catalog_id, module, role, permission, active) "
                    "VALUES (:catalog_id, 'auth', 'inactive-role', 'read', false)"
                ),
                {"catalog_id": catalog_id},
            )

        with pytest.raises(IntegrityError):
            async with engine.begin() as connection:
                await connection.execute(
                    text("INSERT INTO auth.users (email) VALUES ('person@example.com')")
                )

        with pytest.raises(DBAPIError, match="requires an active catalog entry"):
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO auth.user_role_bindings "
                        "(user_id, org_id, catalog_id, granted_by_user_id) "
                        "VALUES (:user_id, :org_id, :catalog_id, :grantor)"
                    ),
                    {
                        "user_id": first_user,
                        "org_id": organization_id,
                        "catalog_id": catalog_id,
                        "grantor": second_user,
                    },
                )

        with pytest.raises(IntegrityError):
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO auth.governed_requests "
                        "(request_type, target_user_id, initiator_user_id, approver_user_id, "
                        "execute_after) VALUES "
                        "('mfa_reset', :target, :actor, :actor, :execute_after)"
                    ),
                    {
                        "target": first_user,
                        "actor": second_user,
                        "execute_after": datetime.now(UTC) + timedelta(hours=24),
                    },
                )
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_audit_records_cannot_be_changed(migrated_database_url: str) -> None:
    engine = create_async_engine(migrated_database_url)
    audit_id = uuid4()
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO auth.audit_logs "
                    "(audit_id, event_type, outcome, correlation_id) "
                    "VALUES (:audit_id, 'test.event', 'success', :correlation_id)"
                ),
                {"audit_id": audit_id, "correlation_id": uuid4()},
            )

        with pytest.raises(DBAPIError, match="audit records are immutable"):
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE auth.audit_logs SET outcome = 'failure' "
                        "WHERE audit_id = :audit_id"
                    ),
                    {"audit_id": audit_id},
                )

        with pytest.raises(DBAPIError, match="audit records are immutable"):
            async with engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM auth.audit_logs WHERE audit_id = :audit_id"),
                    {"audit_id": audit_id},
                )
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_database_role_cannot_cross_organization_boundary(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    first_org = uuid4()
    second_org = uuid4()
    rejected_org = uuid4()
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO auth.organizations (org_id, name, slug) VALUES "
                    "(:first_org, 'First Organization', :first_slug), "
                    "(:second_org, 'Second Organization', :second_slug)"
                ),
                {
                    "first_org": first_org,
                    "second_org": second_org,
                    "first_slug": f"first-{first_org.hex[:8]}",
                    "second_slug": f"second-{second_org.hex[:8]}",
                },
            )

        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE auth_app"))
            await connection.execute(
                text("SELECT set_config('app.current_org_id', :org_id, true)"),
                {"org_id": str(first_org)},
            )
            visible_orgs = (
                await connection.execute(text("SELECT org_id FROM auth.organizations"))
            ).scalars().all()
            assert visible_orgs == [first_org]

        with pytest.raises(DBAPIError, match="row-level security policy"):
            async with engine.begin() as connection:
                await connection.execute(text("SET LOCAL ROLE auth_app"))
                await connection.execute(
                    text("SELECT set_config('app.current_org_id', :org_id, true)"),
                    {"org_id": str(first_org)},
                )
                await connection.execute(
                    text(
                        "INSERT INTO auth.organizations (org_id, name, slug) "
                        "VALUES (:org_id, 'Rejected Organization', :slug)"
                    ),
                    {"org_id": rejected_org, "slug": f"rejected-{rejected_org.hex[:8]}"},
                )
    finally:
        await engine.dispose()
