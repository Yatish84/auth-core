from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_core.entity.recovery import (
    ContactProof,
    ContactType,
    PasswordResetOutcome,
    RecoveryError,
    RecoveryErrorCode,
    StaffRole,
)
from auth_core.infrastructure.persistence.models import (
    Identity,
    MFADevice,
    PasswordHistory,
    StaffRoleBinding,
    User,
)
from auth_core.infrastructure.persistence.recovery_repository import (
    SqlAlchemyRecoveryRepository,
)
from auth_core.infrastructure.security.passwords import Argon2idPasswordHasher

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_password_reset_is_single_use_and_enforces_history(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    hasher = Argon2idPasswordHasher()
    repository = SqlAlchemyRecoveryRepository(sessions, hasher)
    user_id = uuid4()
    identity_id = uuid4()
    current_hash = hasher.hash("Initial secure password 2026!")
    now = datetime.now(UTC)
    first_token_hash = sha256(b"first-recovery-token").hexdigest()
    second_token_hash = sha256(b"second-recovery-token").hexdigest()
    try:
        async with sessions.begin() as database:
            database.add(
                User(
                    user_id=user_id,
                    email="reset-integration@example.com",
                    state="active",
                )
            )
            await database.flush()
            database.add(
                Identity(
                    identity_id=identity_id,
                    user_id=user_id,
                    provider="password",
                    provider_subject="reset-integration@example.com",
                    password_hash=current_hash,
                    verified=True,
                )
            )
            database.add(
                PasswordHistory(identity_id=identity_id, password_hash=current_hash)
            )
        await repository.issue_password_reset(
            user_id,
            first_token_hash,
            "password_reset",
            now + timedelta(minutes=15),
            uuid4(),
        )
        outcome, user = await repository.consume_password_reset(
            first_token_hash,
            "New unique secure password 2026!",
            hasher.hash("New unique secure password 2026!"),
            now,
            uuid4(),
        )
        replay, _ = await repository.consume_password_reset(
            first_token_hash,
            "Another unique secure password 2026!",
            hasher.hash("Another unique secure password 2026!"),
            now,
            uuid4(),
        )
        await repository.issue_password_reset(
            user_id,
            second_token_hash,
            "password_reset",
            now + timedelta(minutes=15),
            uuid4(),
        )
        reused, _ = await repository.consume_password_reset(
            second_token_hash,
            "Initial secure password 2026!",
            hasher.hash("Initial secure password 2026!"),
            now,
            uuid4(),
        )

        assert outcome is PasswordResetOutcome.UPDATED
        assert user is not None and user.user_id == user_id
        assert replay is PasswordResetOutcome.INVALID
        assert reused is PasswordResetOutcome.REUSED
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_contact_change_applies_only_after_old_and_new_proof(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SqlAlchemyRecoveryRepository(sessions, Argon2idPasswordHasher())
    user_id = uuid4()
    now = datetime.now(UTC)
    old_hash = sha256(b"old-code").hexdigest()
    new_hash = sha256(b"new-code").hexdigest()
    try:
        async with sessions.begin() as database:
            database.add(User(user_id=user_id, email="old-contact@example.com", state="active"))
            await database.flush()
            database.add(
                Identity(
                    user_id=user_id,
                    provider="password",
                    provider_subject="old-contact@example.com",
                    password_hash=Argon2idPasswordHasher().hash("Contact password 2026!"),
                    verified=True,
                )
            )
        request = await repository.create_contact_change(
            user_id,
            ContactType.EMAIL,
            "new-contact@example.com",
            old_hash,
            new_hash,
            now + timedelta(minutes=10),
            uuid4(),
        )
        assert request is not None
        old_proof = await repository.verify_contact_change(
            user_id, request.request_id, ContactProof.OLD, old_hash, now, uuid4()
        )
        assert old_proof is not None and old_proof.applied_at is None
        new_proof = await repository.verify_contact_change(
            user_id, request.request_id, ContactProof.NEW, new_hash, now, uuid4()
        )
        assert new_proof is not None and new_proof.applied_at is not None

        async with sessions() as database:
            user = await database.get(User, user_id)
            identity = await database.scalar(
                select(Identity).where(
                    Identity.user_id == user_id, Identity.provider == "password"
                )
            )
        assert user is not None and user.email == "new-contact@example.com"
        assert identity is not None and identity.provider_subject == "new-contact@example.com"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_mfa_reset_requires_distinct_approval_and_twelve_hour_delay(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SqlAlchemyRecoveryRepository(sessions, Argon2idPasswordHasher())
    l2_id = uuid4()
    l3_id = uuid4()
    target_id = uuid4()
    now = datetime.now(UTC)
    try:
        async with sessions.begin() as database:
            database.add_all(
                [
                    User(user_id=l2_id, email="l2@example.com", state="active"),
                    User(user_id=l3_id, email="l3@example.com", state="active"),
                    User(user_id=target_id, email="governed-target@example.com", state="active"),
                ]
            )
            await database.flush()
            database.add_all(
                [
                    StaffRoleBinding(user_id=l2_id, role=StaffRole.SUPPORT_AGENT_L2.value),
                    StaffRoleBinding(
                        user_id=l3_id, role=StaffRole.SECURITY_SUPERVISOR_L3.value
                    ),
                    MFADevice(user_id=target_id, factor_type="email", status="active"),
                ]
            )
        assert await repository.staff_has_role(l2_id, StaffRole.SUPPORT_AGENT_L2)
        initiated = await repository.initiate_mfa_reset(
            l2_id,
            target_id,
            "SECURITY-123",
            now + timedelta(hours=12),
            uuid4(),
        )
        assert initiated is not None
        request, _ = initiated
        with pytest.raises(RecoveryError) as self_approval:
            await repository.approve_mfa_reset(l2_id, request.request_id, now, uuid4())
        assert self_approval.value.code is RecoveryErrorCode.FOUR_EYES_REQUIRED

        approved = await repository.approve_mfa_reset(
            l3_id, request.request_id, now, uuid4()
        )
        assert approved is not None and approved.state == "approved"
        with pytest.raises(RecoveryError) as too_early:
            await repository.execute_mfa_reset(l3_id, request.request_id, now, uuid4())
        assert too_early.value.code is RecoveryErrorCode.GOVERNED_TOO_EARLY

        executed = await repository.execute_mfa_reset(
            l3_id, request.request_id, now + timedelta(hours=12), uuid4()
        )
        assert executed is not None and executed[0].state == "executed"
        async with sessions() as database:
            factor = await database.scalar(
                select(MFADevice).where(MFADevice.user_id == target_id)
            )
        assert factor is not None and factor.status == "revoked"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_database_role_cannot_grant_staff_or_read_another_contact_change(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SqlAlchemyRecoveryRepository(sessions, Argon2idPasswordHasher())
    owner_id = uuid4()
    other_id = uuid4()
    now = datetime.now(UTC)
    try:
        async with sessions.begin() as database:
            database.add_all(
                [
                    User(user_id=owner_id, email="rls-owner@example.com", state="active"),
                    User(user_id=other_id, email="rls-other@example.com", state="active"),
                ]
            )
        request = await repository.create_contact_change(
            owner_id,
            ContactType.EMAIL,
            "rls-owner-new@example.com",
            sha256(b"old-proof").hexdigest(),
            sha256(b"new-proof").hexdigest(),
            now + timedelta(minutes=10),
            uuid4(),
        )
        assert request is not None

        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE auth_app"))
            await connection.execute(
                text("SELECT set_config('app.current_user_id', :user_id, true)"),
                {"user_id": str(other_id)},
            )
            visible = await connection.scalar(
                text(
                    "SELECT count(*) FROM auth.contact_change_requests "
                    "WHERE request_id = :request_id"
                ),
                {"request_id": request.request_id},
            )
        assert visible == 0

        with pytest.raises(DBAPIError, match="permission denied"):
            async with engine.begin() as connection:
                await connection.execute(text("SET LOCAL ROLE auth_app"))
                await connection.execute(
                    text(
                        "INSERT INTO auth.staff_role_bindings (user_id, role) "
                        "VALUES (:user_id, 'ACCOUNT_ADMIN')"
                    ),
                    {"user_id": other_id},
                )
    finally:
        await engine.dispose()
