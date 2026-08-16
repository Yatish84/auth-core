from uuid import uuid4

import pytest
from redis.asyncio import Redis

from auth_core.infrastructure.redis_security import (
    OTP_TTL_SECONDS,
    RedisSecurityStore,
    SecurityKeyFactory,
)


def test_security_keys_hide_identifiers_and_define_expiry() -> None:
    user_id = uuid4()
    factory = SecurityKeyFactory(b"test-key-material-for-redis")

    key = factory.otp(user_id, "password-reset")

    assert str(user_id) not in key.name
    assert "password-reset" not in key.name
    assert key.ttl_seconds == OTP_TTL_SECONDS


@pytest.mark.integration
@pytest.mark.asyncio
async def test_otp_hash_is_expiring(integration_redis: Redis) -> None:
    factory = SecurityKeyFactory(b"test-key-material-for-redis")
    store = RedisSecurityStore(integration_redis, factory)
    user_id = uuid4()
    key = factory.otp(user_id, "login")

    await store.store_otp_hash(user_id, "login", "synthetic-otp-hash")

    ttl = await integration_redis.ttl(key.name)
    stored_hash = await integration_redis.hget(key.name, "hash")
    assert 0 < ttl <= OTP_TTL_SECONDS
    assert stored_hash == "synthetic-otp-hash"
