import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest_asyncio
from alembic import command
from alembic.config import Config
from redis.asyncio import Redis
from sqlalchemy.engine import make_url

PROJECT_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = PROJECT_ROOT / "services" / "auth-api" / "alembic.ini"


def asyncpg_url(sqlalchemy_url: str) -> str:
    return sqlalchemy_url.replace("postgresql+asyncpg://", "postgresql://", 1)


@pytest_asyncio.fixture(scope="session")
async def migrated_database_url() -> AsyncIterator[str]:
    admin_url = os.environ.get(
        "TEST_ADMIN_DATABASE_URL",
        "postgresql+asyncpg://auth_core:local-development-only@localhost:5432/postgres",
    )
    database_name = f"auth_core_test_{uuid4().hex[:12]}"
    admin_connection = await asyncpg.connect(asyncpg_url(admin_url))
    await admin_connection.execute(f'CREATE DATABASE "{database_name}"')
    await admin_connection.close()

    database_url = make_url(admin_url).set(database=database_name).render_as_string(False)
    previous_database_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = database_url
    alembic_config = Config(str(ALEMBIC_CONFIG))

    try:
        await asyncio.to_thread(command.upgrade, alembic_config, "head")
        yield database_url
    finally:
        if previous_database_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_database_url
        admin_connection = await asyncpg.connect(asyncpg_url(admin_url))
        await admin_connection.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = $1 AND pid <> pg_backend_pid()",
            database_name,
        )
        await admin_connection.execute(f'DROP DATABASE IF EXISTS "{database_name}"')
        await admin_connection.close()


@pytest_asyncio.fixture
async def integration_redis() -> AsyncIterator[Redis]:
    redis_url = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/15")
    client: Redis = Redis.from_url(redis_url, decode_responses=True)
    await client.flushdb()
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()
