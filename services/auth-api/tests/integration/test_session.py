from datetime import UTC, datetime, timedelta

import pytest
from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_core.control.session import SessionControl
from auth_core.entity.session import ClientType, SessionError, SessionErrorCode
from auth_core.infrastructure.persistence.models import RefreshToken, Session, User
from auth_core.infrastructure.persistence.session_repository import (
    SqlAlchemySessionRepository,
)
from auth_core.infrastructure.redis_security import RedisSecurityStore, SecurityKeyFactory
from auth_core.infrastructure.security.tokens import LocalRS256TokenProvider

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_real_session_rotation_reuse_detection_and_logout(
    migrated_database_url: str, integration_redis: Redis
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    store = RedisSecurityStore(
        integration_redis, SecurityKeyFactory(b"integration-session-key-material")
    )
    control = SessionControl(
        SqlAlchemySessionRepository(sessions),
        LocalRS256TokenProvider("https://issuer.test", "grox-test"),
        store,
        b"integration-refresh-token-pepper",
        b"integration-device-fingerprint-pepper",
    )
    try:
        async with sessions.begin() as database:
            user = User(email="session@example.com", state="active")
            database.add(user)
            await database.flush()
            user_id = user.user_id

        await store.store_login_workflow(
            "integration-session-workflow",
            {
                "user_id": str(user_id),
                "decision": "session_ready",
                "primary_method": "password",
            },
        )
        created = await control.create_session(
            "integration-session-workflow",
            ClientType.MOBILE,
            "integration-device-fingerprint",
            "127.0.0.1",
            user_id,
        )
        claims = await control.authenticate(created.access_token)
        rotated = await control.refresh(
            created.refresh_token,
            ClientType.MOBILE,
            "integration-device-fingerprint",
            user_id,
        )
        assert rotated.refresh_token != created.refresh_token
        assert (await control.authenticate(rotated.access_token)).session_id == claims.session_id
        with pytest.raises(SessionError):
            await control.authenticate(created.access_token)

        with pytest.raises(SessionError) as reuse:
            await control.refresh(
                created.refresh_token,
                ClientType.MOBILE,
                "integration-device-fingerprint",
                user_id,
            )
        assert reuse.value.code == SessionErrorCode.TOKEN_REUSED
        with pytest.raises(SessionError):
            await control.authenticate(rotated.access_token)

        async with sessions() as database:
            stored = (await database.scalars(select(RefreshToken))).all()
        assert all(item.token_hash != created.refresh_token for item in stored)
        assert claims.user_id == user_id
        assert datetime.now(UTC) < created.refresh_expires_at
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_real_session_cap_revokes_oldest_of_eleven(
    migrated_database_url: str, integration_redis: Redis
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    store = RedisSecurityStore(
        integration_redis, SecurityKeyFactory(b"integration-session-cap-key")
    )
    control = SessionControl(
        SqlAlchemySessionRepository(sessions),
        LocalRS256TokenProvider("https://issuer.test", "grox-test"),
        store,
        b"integration-session-cap-refresh",
        b"integration-session-cap-fingerprint",
    )
    try:
        async with sessions.begin() as database:
            user = User(email="session-cap@example.com", state="active")
            database.add(user)
            await database.flush()
            user_id = user.user_id

        issued = []
        for index in range(11):
            workflow = f"integration-session-cap-workflow-{index}"
            await store.store_login_workflow(
                workflow,
                {
                    "user_id": str(user_id),
                    "decision": "session_ready",
                    "primary_method": "password",
                },
            )
            issued.append(
                await control.create_session(
                    workflow,
                    ClientType.MOBILE,
                    f"integration-cap-device-{index}",
                    "127.0.0.1",
                    user_id,
                )
            )

        with pytest.raises(SessionError):
            await control.authenticate(issued[0].access_token)
        newest = await control.authenticate(issued[-1].access_token)
        assert len(await control.sessions(newest)) == 10
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_real_selected_logout_global_logout_and_idle_timeout(
    migrated_database_url: str, integration_redis: Redis
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    store = RedisSecurityStore(
        integration_redis, SecurityKeyFactory(b"integration-session-logout-key")
    )
    control = SessionControl(
        SqlAlchemySessionRepository(sessions),
        LocalRS256TokenProvider("https://issuer.test", "grox-test"),
        store,
        b"integration-session-logout-refresh",
        b"integration-session-logout-fingerprint",
    )
    try:
        async with sessions.begin() as database:
            user = User(email="session-logout@example.com", state="active")
            database.add(user)
            await database.flush()
            user_id = user.user_id

        issued = []
        for index in range(4):
            workflow = f"integration-session-logout-workflow-{index}"
            await store.store_login_workflow(
                workflow,
                {
                    "user_id": str(user_id),
                    "decision": "session_ready",
                    "primary_method": "password",
                },
            )
            issued.append(
                await control.create_session(
                    workflow,
                    ClientType.MOBILE,
                    f"integration-logout-device-{index}",
                    "127.0.0.1",
                    user_id,
                )
            )

        current = await control.authenticate(issued[0].access_token)
        selected = await control.authenticate(issued[1].access_token)
        await control.revoke_selected(current, selected.session_id, user_id)
        with pytest.raises(SessionError):
            await control.authenticate(issued[1].access_token)

        logout_claims = await control.authenticate(issued[2].access_token)
        await control.logout(logout_claims, user_id)
        with pytest.raises(SessionError):
            await control.authenticate(issued[2].access_token)

        async with sessions.begin() as database:
            await database.execute(
                update(Session)
                .where(Session.session_id == issued[3].session_id)
                .values(last_activity_at=datetime.now(UTC) - timedelta(minutes=16))
            )
        with pytest.raises(SessionError) as expired:
            await control.refresh(
                issued[3].refresh_token,
                ClientType.MOBILE,
                "integration-logout-device-3",
                user_id,
            )
        assert expired.value.code == SessionErrorCode.SESSION_EXPIRED

        remaining = await control.authenticate(issued[0].access_token)
        assert await control.logout_all(remaining, user_id) == 1
        with pytest.raises(SessionError):
            await control.authenticate(issued[0].access_token)
    finally:
        await engine.dispose()
