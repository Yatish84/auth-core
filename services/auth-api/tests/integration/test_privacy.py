from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_core.control.privacy import GDPRControl
from auth_core.entity.session import AccessClaims, ClientType
from auth_core.infrastructure.persistence.models import (
    AuditLog,
    Identity,
    MFADevice,
    Organization,
    PrivacyExportArtifact,
    RolePermissionCatalog,
    TrustedDevice,
    User,
    UserRoleBinding,
)
from auth_core.infrastructure.persistence.privacy_repository import (
    SqlAlchemyPrivacyRepository,
)
from auth_core.infrastructure.security.secrets import LocalAESGCMSecretCipher

pytestmark = pytest.mark.integration

LOCAL_EXPORT_KEY = "bG9jYWwtbWZhLWtleS1jaGFuZ2UtYmVmb3JlLXByb2Q="


class SessionRevokerFake:
    async def revoke_user_access(self, user_id: object, reason: str) -> int:
        del user_id
        assert reason == "privacy_erasure"
        return 0


@pytest.mark.asyncio
async def test_only_active_security_supervisor_can_cross_user_audit_boundary(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    supervisor_id = uuid4()
    ordinary_user_id = uuid4()
    subject_user_id = uuid4()
    audit_id = uuid4()
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO auth.users (user_id, email, state) VALUES "
                    "(:supervisor_id, 'audit-supervisor@example.com', 'active'), "
                    "(:ordinary_user_id, 'audit-ordinary@example.com', 'active'), "
                    "(:subject_user_id, 'audit-subject@example.com', 'active')"
                ),
                {
                    "supervisor_id": supervisor_id,
                    "ordinary_user_id": ordinary_user_id,
                    "subject_user_id": subject_user_id,
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO auth.staff_role_bindings (user_id, role) "
                    "VALUES (:supervisor_id, 'SECURITY_SUPERVISOR_L3')"
                ),
                {"supervisor_id": supervisor_id},
            )
            await connection.execute(
                text(
                    "INSERT INTO auth.audit_logs "
                    "(audit_id, subject_user_id, event_type, outcome, correlation_id) "
                    "VALUES (:audit_id, :subject_user_id, 'LOGIN_FAILED', "
                    "'failure', :correlation_id)"
                ),
                {
                    "audit_id": audit_id,
                    "subject_user_id": subject_user_id,
                    "correlation_id": uuid4(),
                },
            )

        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE auth_app"))
            await connection.execute(
                text("SELECT set_config('app.current_user_id', :user_id, true)"),
                {"user_id": str(ordinary_user_id)},
            )
            ordinary_count = await connection.scalar(
                text("SELECT count(*) FROM auth.audit_logs WHERE audit_id = :audit_id"),
                {"audit_id": audit_id},
            )

        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE auth_app"))
            await connection.execute(
                text("SELECT set_config('app.current_user_id', :user_id, true)"),
                {"user_id": str(supervisor_id)},
            )
            supervisor_count = await connection.scalar(
                text("SELECT count(*) FROM auth.audit_logs WHERE audit_id = :audit_id"),
                {"audit_id": audit_id},
            )

        assert ordinary_count == 0
        assert supervisor_count == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_export_is_encrypted_idempotent_and_owner_isolated(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SqlAlchemyPrivacyRepository(sessions)
    control = GDPRControl(
        repository,
        LocalAESGCMSecretCipher(LOCAL_EXPORT_KEY),
        b"integration-privacy-idempotency",
        SessionRevokerFake(),
    )
    user_id = uuid4()
    other_user_id = uuid4()
    now = datetime.now(UTC)
    claims = AccessClaims(
        user_id,
        uuid4(),
        uuid4(),
        uuid4(),
        now,
        now + timedelta(minutes=15),
        ClientType.WEB,
        ("totp",),
    )
    try:
        async with sessions.begin() as database:
            database.add_all(
                [
                    User(
                        user_id=user_id,
                        email="privacy-export-owner@example.com",
                        given_name="Export",
                        family_name="Owner",
                        state="active",
                    ),
                    User(
                        user_id=other_user_id,
                        email="privacy-export-other@example.com",
                        state="active",
                    ),
                ]
            )

        first = await control.request_export(claims, "same-export-attempt", uuid4())
        duplicate = await control.request_export(claims, "same-export-attempt", uuid4())
        download = await control.download_export(claims, first.request_id)

        async with sessions() as database:
            artifact = await database.scalar(
                select(PrivacyExportArtifact).where(
                    PrivacyExportArtifact.gdpr_request_id == first.request_id
                )
            )
        assert artifact is not None
        assert b"privacy-export-owner@example.com" not in artifact.encrypted_content
        assert duplicate.request_id == first.request_id
        assert b"privacy-export-owner@example.com" in download.content

        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE auth_app"))
            await connection.execute(
                text("SELECT set_config('app.current_user_id', :user_id, true)"),
                {"user_id": str(other_user_id)},
            )
            visible = await connection.scalar(
                text(
                    "SELECT count(*) FROM auth.privacy_export_artifacts "
                    "WHERE gdpr_request_id = :request_id"
                ),
                {"request_id": first.request_id},
            )
        assert visible == 0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_erasure_removes_pii_credentials_and_retains_evidence(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SqlAlchemyPrivacyRepository(sessions)
    control = GDPRControl(
        repository,
        LocalAESGCMSecretCipher(LOCAL_EXPORT_KEY),
        b"integration-erasure-idempotency",
        SessionRevokerFake(),
    )
    user_id = uuid4()
    now = datetime.now(UTC)
    claims = AccessClaims(
        user_id,
        uuid4(),
        uuid4(),
        uuid4(),
        now,
        now + timedelta(minutes=15),
        ClientType.WEB,
        ("totp",),
    )
    try:
        async with sessions.begin() as database:
            database.add(
                User(
                    user_id=user_id,
                    email="erase-owner@example.com",
                    given_name="Erase",
                    family_name="Owner",
                    phone_e164="+16045550123",
                    state="active",
                )
            )
            await database.flush()
            database.add_all(
                [
                    Identity(
                        user_id=user_id,
                        provider="password",
                        provider_subject="erase-owner@example.com",
                        password_hash="stored-password-hash",
                        verified=True,
                    ),
                    MFADevice(
                        user_id=user_id,
                        factor_type="email",
                        status="active",
                        label="Primary email",
                    ),
                    TrustedDevice(
                        user_id=user_id,
                        fingerprint_hash="stored-device-fingerprint",
                        trust_state="trusted",
                    ),
                ]
            )

        erased = await control.request_erasure(
            claims, "integration-erasure-request", uuid4()
        )

        async with sessions() as database:
            user = await database.get(User, user_id)
            identity_count = len(
                (await database.scalars(select(Identity).where(Identity.user_id == user_id))).all()
            )
            factor_count = len(
                (
                    await database.scalars(
                        select(MFADevice).where(MFADevice.user_id == user_id)
                    )
                ).all()
            )
            device_count = len(
                (
                    await database.scalars(
                        select(TrustedDevice).where(TrustedDevice.user_id == user_id)
                    )
                ).all()
            )
            evidence = await database.scalar(
                select(AuditLog).where(
                    AuditLog.subject_user_id == user_id,
                    AuditLog.event_type == "PRIVACY_ACCOUNT_ERASED",
                )
            )

        assert user is not None
        assert user.state == "anonymized"
        assert user.email is None and user.phone_e164 is None
        assert user.given_name is None and user.family_name is None
        assert identity_count == factor_count == device_count == 0
        assert erased.state == "completed"
        assert erased.backup_purge_due_at is not None
        assert evidence is not None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_erasure_blocks_last_organization_owner(
    migrated_database_url: str,
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SqlAlchemyPrivacyRepository(sessions)
    user_id = uuid4()
    org_id = uuid4()
    try:
        async with sessions.begin() as database:
            owner_catalog = await database.scalar(
                select(RolePermissionCatalog).where(
                    RolePermissionCatalog.role == "OWNER",
                    RolePermissionCatalog.active.is_(True),
                )
            )
            assert owner_catalog is not None
            database.add_all(
                [
                    User(
                        user_id=user_id,
                        email="sole-owner@example.com",
                        state="active",
                    ),
                    Organization(
                        org_id=org_id,
                        name="Sole Owner Organization",
                        slug=f"sole-owner-{org_id.hex[:8]}",
                        workspace_type="organization",
                    ),
                ]
            )
            await database.flush()
            database.add(
                UserRoleBinding(
                    user_id=user_id,
                    org_id=org_id,
                    catalog_id=owner_catalog.catalog_id,
                    granted_by_user_id=user_id,
                )
            )

        request, created = await repository.get_or_create_erasure(
            user_id, "sole-owner-idempotency-hash", uuid4()
        )

        assert request is None
        assert created is False
    finally:
        await engine.dispose()
