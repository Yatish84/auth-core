from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.integration


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
