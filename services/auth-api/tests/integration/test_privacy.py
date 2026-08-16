from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_core.control.privacy import GDPRControl
from auth_core.entity.session import AccessClaims, ClientType
from auth_core.infrastructure.persistence.models import PrivacyExportArtifact, User
from auth_core.infrastructure.persistence.privacy_repository import (
    SqlAlchemyPrivacyRepository,
)
from auth_core.infrastructure.security.secrets import LocalAESGCMSecretCipher

pytestmark = pytest.mark.integration

LOCAL_EXPORT_KEY = "bG9jYWwtbWZhLWtleS1jaGFuZ2UtYmVmb3JlLXByb2Q="


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
