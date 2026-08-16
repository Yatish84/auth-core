import hmac
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_core.control.session import SessionControl
from auth_core.entity.session import ClientType, SessionError
from auth_core.entity.workspace import LastOwnerError, OrganizationRole
from auth_core.infrastructure.persistence.models import (
    Organization,
    Referral,
    RolePermissionCatalog,
    Session,
    User,
    UserRoleBinding,
)
from auth_core.infrastructure.persistence.registration_repository import (
    SqlAlchemyRegistrationRepository,
)
from auth_core.infrastructure.persistence.session_repository import (
    SqlAlchemySessionRepository,
)
from auth_core.infrastructure.persistence.workspace_repository import (
    SqlAlchemyWorkspaceRepository,
)
from auth_core.infrastructure.redis_security import RedisSecurityStore, SecurityKeyFactory
from auth_core.infrastructure.security.tokens import LocalRS256TokenProvider


@pytest.mark.integration
@pytest.mark.asyncio
async def test_personal_workspace_organization_and_referral_lifecycle(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    workspaces = SqlAlchemyWorkspaceRepository(sessions)
    registrations = SqlAlchemyRegistrationRepository(sessions)
    referrer_id = uuid4()
    correlation_id = uuid4()
    now = datetime.now(UTC)
    raw_referral = "integration-referral-token-with-enough-entropy"
    referral_hash = hmac.new(
        b"integration-referral-key", raw_referral.encode(), sha256
    ).hexdigest()
    verification_hash = sha256(b"integration-email-verification").hexdigest()
    try:
        async with sessions.begin() as session:
            session.add(
                User(
                    user_id=referrer_id,
                    email="referrer@example.com",
                    given_name="Referring",
                    family_name="Person",
                    state="active",
                )
            )

        personal = await workspaces.ensure_personal_workspace(referrer_id)
        organization = await workspaces.create_organization(
            referrer_id, "Example Investments", "example-investments", correlation_id
        )
        available = await workspaces.list_workspaces(referrer_id)
        referral = await workspaces.create_referral(
            referrer_id,
            "friend@example.com",
            referral_hash,
            now + timedelta(days=30),
            correlation_id,
        )
        referred_user_id = await registrations.create_email_registration(
            "friend@example.com",
            "Friendly",
            "Person",
            "argon2id-test-hash",
            verification_hash,
            now + timedelta(minutes=15),
            correlation_id,
            referral_hash,
        )

        async with sessions() as session:
            claimed = await session.get(Referral, referral.referral_id)
            personal_count = await session.scalar(
                select(func.count())
                .select_from(Organization)
                .where(
                    Organization.workspace_type == "personal",
                    Organization.personal_owner_user_id == referred_user_id,
                )
            )

        assert personal.workspace_type.value == "personal"
        assert organization.workspace_type.value == "organization"
        assert {item.workspace_id for item in available} == {
            personal.workspace_id,
            organization.workspace_id,
        }
        assert claimed is not None
        assert claimed.state == "registered"
        assert claimed.referred_user_id == referred_user_id
        assert personal_count == 1

        assert await registrations.verify_email(verification_hash, now, correlation_id)
        async with sessions() as session:
            verified = await session.get(Referral, referral.referral_id)
            assert verified is not None
            assert verified.state == "verified"
            assert verified.verified_at is not None
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_organization_invitation_scope_roles_and_offboarding(
    migrated_database_url: str,
    integration_redis: Redis,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    workspaces = SqlAlchemyWorkspaceRepository(sessions)
    session_repository = SqlAlchemySessionRepository(sessions)
    redis_store = RedisSecurityStore(
        integration_redis, SecurityKeyFactory(b"integration-workspace-security")
    )
    token_provider = LocalRS256TokenProvider("https://issuer.test", "grox-test")
    session_control = SessionControl(
        session_repository,
        token_provider,
        redis_store,
        b"integration-workspace-refresh",
        b"integration-workspace-fingerprint",
    )
    owner_id = uuid4()
    member_id = uuid4()
    correlation_id = uuid4()
    now = datetime.now(UTC)
    invitation_token = "organization-invitation-token-with-enough-entropy"
    invitation_hash = hmac.new(
        b"integration-organization-invitation",
        invitation_token.encode(),
        sha256,
    ).hexdigest()
    try:
        async with sessions.begin() as session:
            session.add_all(
                [
                    User(user_id=owner_id, email="org-owner@example.com", state="active"),
                    User(user_id=member_id, email="org-member@example.com", state="active"),
                ]
            )
        organization = await workspaces.create_organization(
            owner_id, "Organization Flow", "organization-flow", correlation_id
        )
        invitation = await workspaces.create_organization_invitation(
            owner_id,
            organization.workspace_id,
            "org-member@example.com",
            OrganizationRole.MEMBER,
            invitation_hash,
            now + timedelta(days=7),
            correlation_id,
        )
        assert invitation is not None
        accepted = await workspaces.accept_organization_invitation(
            member_id, invitation_hash, now, correlation_id
        )
        assert accepted is not None
        assert accepted.roles == ("MEMBER",)
        assert (
            await workspaces.accept_organization_invitation(
                member_id, invitation_hash, now, correlation_id
            )
            is None
        )

        members = await workspaces.list_members(owner_id, organization.workspace_id)
        assert members is not None
        assert {item.user_id for item in members} == {owner_id, member_id}
        assert await workspaces.list_members(member_id, organization.workspace_id) is None

        with pytest.raises(LastOwnerError):
            await workspaces.offboard_member(
                owner_id,
                organization.workspace_id,
                owner_id,
                now,
                correlation_id,
            )
        changed = await workspaces.replace_member_role(
            owner_id,
            organization.workspace_id,
            member_id,
            OrganizationRole.VIEWER,
            now,
            correlation_id,
        )
        assert changed is not None and changed.roles == (OrganizationRole.VIEWER,)

        created = await session_repository.create_session(
            member_id,
            ClientType.MOBILE,
            "hashed-device-fingerprint",
            "127.0.0.1",
            "hashed-refresh-token",
            uuid4(),
            now + timedelta(days=30),
            now + timedelta(days=1),
            now + timedelta(days=30),
        )
        initial_token, _ = token_provider.issue(
            member_id,
            created.record.session_id,
            created.record.family_id,
            created.record.access_jti,
            ClientType.MOBILE,
            ("password",),
            now,
        )
        initial_claims = await session_control.authenticate(initial_token)
        access = await workspaces.get_workspace_access(member_id, organization.workspace_id)
        assert access is not None
        scoped_token, _ = await session_control.issue_workspace_scope(
            initial_claims, access, correlation_id
        )
        with pytest.raises(SessionError):
            await session_control.authenticate(initial_token)
        scoped_claims = await session_control.authenticate(scoped_token)
        assert scoped_claims.workspace_id == organization.workspace_id
        assert scoped_claims.workspace_type == "organization"
        assert scoped_claims.roles == ("VIEWER",)

        offboarded = await workspaces.offboard_member(
            owner_id,
            organization.workspace_id,
            member_id,
            now + timedelta(seconds=1),
            correlation_id,
        )
        assert offboarded is not None
        await session_control.revoke_organization_access(
            member_id, organization.workspace_id, offboarded.revoked_access_jtis
        )
        with pytest.raises(SessionError):
            await session_control.authenticate(scoped_token)
        async with sessions() as session:
            active_session = await session.get(Session, created.record.session_id)
            assert active_session is not None
            assert active_session.revoked_at is None
            assert active_session.org_id is None
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_personal_workspace_rejects_collaboration_rows(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SqlAlchemyWorkspaceRepository(sessions)
    owner_id = uuid4()
    try:
        async with sessions.begin() as session:
            session.add(User(user_id=owner_id, email="personal-only@example.com", state="active"))
        personal = await repository.ensure_personal_workspace(owner_id)
        async with sessions() as session:
            catalog_id = await session.scalar(
                select(RolePermissionCatalog.catalog_id).where(
                    RolePermissionCatalog.role == "OWNER"
                )
            )
        assert catalog_id is not None
        with pytest.raises(DBAPIError, match="personal workspaces cannot have"):
            async with sessions.begin() as session:
                session.add(
                    UserRoleBinding(
                        user_id=owner_id,
                        org_id=personal.workspace_id,
                        catalog_id=catalog_id,
                        granted_by_user_id=owner_id,
                    )
                )
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_database_role_separates_private_personal_workspaces(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SqlAlchemyWorkspaceRepository(sessions)
    first_user = uuid4()
    second_user = uuid4()
    try:
        async with sessions.begin() as session:
            session.add_all(
                [
                    User(user_id=first_user, email="private-one@example.com", state="active"),
                    User(user_id=second_user, email="private-two@example.com", state="active"),
                ]
            )
        first_personal = await repository.ensure_personal_workspace(first_user)
        second_personal = await repository.ensure_personal_workspace(second_user)
        organization = await repository.create_organization(
            first_user, "First User Organization", "first-user-org", uuid4()
        )

        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE auth_app"))
            await connection.execute(
                text("SELECT set_config('app.current_user_id', :user_id, true)"),
                {"user_id": str(first_user)},
            )
            visible = set(
                (
                    await connection.execute(
                        text("SELECT org_id FROM auth.organizations")
                    )
                ).scalars()
            )

        assert visible == {first_personal.workspace_id, organization.workspace_id}
        assert second_personal.workspace_id not in visible
    finally:
        await engine.dispose()
