import hmac
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_core.infrastructure.persistence.models import Organization, Referral, User
from auth_core.infrastructure.persistence.registration_repository import (
    SqlAlchemyRegistrationRepository,
)
from auth_core.infrastructure.persistence.workspace_repository import (
    SqlAlchemyWorkspaceRepository,
)


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
