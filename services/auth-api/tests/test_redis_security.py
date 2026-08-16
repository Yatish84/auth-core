from datetime import UTC, datetime
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from auth_core.infrastructure.redis_security import (
    LOGIN_LOCK_TTL_SECONDS,
    LOGIN_WORKFLOW_TTL_SECONDS,
    MFA_CHALLENGE_TTL_SECONDS,
    OTP_TTL_SECONDS,
    WEBAUTHN_CHALLENGE_TTL_SECONDS,
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
async def test_session_revocations_are_expiring_and_queryable(
    integration_redis: Redis,
) -> None:
    store = RedisSecurityStore(
        integration_redis, SecurityKeyFactory(b"test-key-material-for-redis")
    )
    user_id, family_id, jti = uuid4(), uuid4(), uuid4()
    revoked_at = datetime.now(UTC)

    await store.revoke_access_token(jti, 900)
    await store.revoke_family(family_id, 3600)
    await store.revoke_user(user_id, revoked_at)

    assert await store.access_token_is_revoked(jti)
    assert await store.family_is_revoked(family_id)
    assert await store.user_revoked_at(user_id) == revoked_at.replace(microsecond=0)


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


@pytest.mark.integration
@pytest.mark.asyncio
async def test_otp_verification_is_atomic_and_single_use(integration_redis: Redis) -> None:
    store = RedisSecurityStore(
        integration_redis, SecurityKeyFactory(b"test-key-material-for-redis")
    )
    user_id = uuid4()
    await store.store_otp_hash(user_id, "phone_verify", "candidate-hash")

    first = await store.verify_and_consume_otp(
        user_id, "phone_verify", "candidate-hash", 3
    )
    replay = await store.verify_and_consume_otp(
        user_id, "phone_verify", "candidate-hash", 3
    )

    assert first == 1
    assert replay == -1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_login_lock_and_workflow_are_expiring(integration_redis: Redis) -> None:
    factory = SecurityKeyFactory(b"test-key-material-for-redis")
    store = RedisSecurityStore(integration_redis, factory)
    await store.lock_login("person@example.com")
    await store.store_login_workflow("opaque-workflow-token", {"decision": "mfa_required"})

    lock_ttl = await integration_redis.ttl(factory.login_lock("person@example.com").name)
    workflow_ttl = await integration_redis.ttl(
        factory.login_workflow("opaque-workflow-token").name
    )

    assert 0 < lock_ttl <= LOGIN_LOCK_TTL_SECONDS
    assert 0 < workflow_ttl <= LOGIN_WORKFLOW_TTL_SECONDS


@pytest.mark.integration
@pytest.mark.asyncio
async def test_oidc_state_is_consumed_once(integration_redis: Redis) -> None:
    store = RedisSecurityStore(
        integration_redis, SecurityKeyFactory(b"test-key-material-for-redis")
    )
    await store.store_oidc_workflow("opaque-state", {"provider": "google"})

    first = await store.consume_oidc_workflow("opaque-state")
    replay = await store.consume_oidc_workflow("opaque-state")

    assert first == {"provider": "google"}
    assert replay is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_mfa_and_webauthn_challenges_expire_and_are_single_use(
    integration_redis: Redis,
) -> None:
    factory = SecurityKeyFactory(b"test-key-material-for-redis")
    store = RedisSecurityStore(integration_redis, factory)
    await store.store_mfa_challenge("mfa-token", {"method": "totp"})
    await store.store_webauthn_challenge("passkey-token", {"purpose": "authenticate"})

    mfa_ttl = await integration_redis.ttl(factory.mfa_challenge("mfa-token").name)
    passkey_ttl = await integration_redis.ttl(
        factory.webauthn_challenge("passkey-token").name
    )
    first_mfa = await store.consume_mfa_challenge("mfa-token")
    replay_mfa = await store.consume_mfa_challenge("mfa-token")
    first_passkey = await store.consume_webauthn_challenge("passkey-token")
    replay_passkey = await store.consume_webauthn_challenge("passkey-token")

    assert 0 < mfa_ttl <= MFA_CHALLENGE_TTL_SECONDS
    assert 0 < passkey_ttl <= WEBAUTHN_CHALLENGE_TTL_SECONDS
    assert first_mfa == {"method": "totp"}
    assert replay_mfa is None
    assert first_passkey == {"purpose": "authenticate"}
    assert replay_passkey is None
