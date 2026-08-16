import hmac
import json
from collections.abc import Awaitable
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, cast
from uuid import UUID

from redis.asyncio import Redis

OTP_TTL_SECONDS = 180
MFA_CHALLENGE_TTL_SECONDS = 300
WEBAUTHN_CHALLENGE_TTL_SECONDS = 300
FACTOR_LOCK_TTL_SECONDS = 900
USER_REVOCATION_TTL_SECONDS = 2_592_000
RISK_TTL_SECONDS = 2_592_000
LOGIN_LOCK_TTL_SECONDS = 900
LOGIN_WORKFLOW_TTL_SECONDS = 300
OIDC_WORKFLOW_TTL_SECONDS = 300

RATE_LIMIT_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""

VERIFY_OTP_SCRIPT = """
local stored = redis.call('HGET', KEYS[1], 'hash')
if not stored then
  return -1
end
if stored == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if attempts >= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
end
return 0
"""


@dataclass(frozen=True, slots=True)
class RedisKey:
    name: str
    ttl_seconds: int


class SecurityKeyFactory:
    def __init__(self, hmac_secret: bytes) -> None:
        if len(hmac_secret) < 16:
            raise ValueError("Redis key HMAC secret must contain at least 16 bytes")
        self._hmac_secret = hmac_secret

    def _opaque(self, value: str | UUID) -> str:
        return hmac.new(self._hmac_secret, str(value).encode(), sha256).hexdigest()[:32]

    def otp(self, user_id: UUID, purpose: str) -> RedisKey:
        return RedisKey(
            f"auth:otp:{self._opaque(user_id)}:{self._opaque(purpose)}", OTP_TTL_SECONDS
        )

    def mfa_challenge(self, challenge_id: str) -> RedisKey:
        return RedisKey(
            f"auth:mfa-challenge:{self._opaque(challenge_id)}", MFA_CHALLENGE_TTL_SECONDS
        )

    def webauthn_challenge(self, challenge_id: str) -> RedisKey:
        return RedisKey(
            f"auth:webauthn:{self._opaque(challenge_id)}", WEBAUTHN_CHALLENGE_TTL_SECONDS
        )

    def rate_limit(self, route: str, subject: str, window_seconds: int) -> RedisKey:
        return RedisKey(
            f"auth:rate:{self._opaque(route)}:{self._opaque(subject)}", window_seconds
        )

    def factor_lock(self, factor_id: UUID) -> RedisKey:
        return RedisKey(f"auth:lock:mfa:{self._opaque(factor_id)}", FACTOR_LOCK_TTL_SECONDS)

    def access_revocation(self, jti: UUID, remaining_lifetime: int) -> RedisKey:
        return RedisKey(f"auth:revocation:jti:{self._opaque(jti)}", remaining_lifetime)

    def user_revocation(self, user_id: UUID) -> RedisKey:
        return RedisKey(
            f"auth:revocation:user:{self._opaque(user_id)}", USER_REVOCATION_TTL_SECONDS
        )

    def organization_revocation(self, user_id: UUID, org_id: UUID) -> RedisKey:
        return RedisKey(
            f"auth:revocation:org:{self._opaque(user_id)}:{self._opaque(org_id)}",
            USER_REVOCATION_TTL_SECONDS,
        )

    def risk(self, user_id: UUID, fingerprint: str) -> RedisKey:
        return RedisKey(
            f"auth:risk:{self._opaque(user_id)}:{self._opaque(fingerprint)}", RISK_TTL_SECONDS
        )

    def login_lock(self, subject: str) -> RedisKey:
        return RedisKey(f"auth:lock:login:{self._opaque(subject)}", LOGIN_LOCK_TTL_SECONDS)

    def login_workflow(self, token: str) -> RedisKey:
        return RedisKey(f"auth:login-workflow:{self._opaque(token)}", LOGIN_WORKFLOW_TTL_SECONDS)

    def oidc_workflow(self, state: str) -> RedisKey:
        return RedisKey(f"auth:oidc:{self._opaque(state)}", OIDC_WORKFLOW_TTL_SECONDS)


class RedisSecurityStore:
    def __init__(self, client: Redis, keys: SecurityKeyFactory) -> None:
        self._client = client
        self._keys = keys

    async def store_otp_hash(self, user_id: UUID, purpose: str, otp_hash: str) -> None:
        key = self._keys.otp(user_id, purpose)
        await cast(
            Awaitable[Any],
            self._client.hset(key.name, mapping={"hash": otp_hash, "attempts": "0"}),
        )
        await self._client.expire(key.name, key.ttl_seconds)

    async def record_otp_failure(self, user_id: UUID, purpose: str) -> int:
        key = self._keys.otp(user_id, purpose)
        result = await cast(Awaitable[Any], self._client.hincrby(key.name, "attempts", 1))
        return int(result)

    async def get_otp_hash(self, user_id: UUID, purpose: str) -> str | None:
        key = self._keys.otp(user_id, purpose)
        result = await cast(Awaitable[Any], self._client.hget(key.name, "hash"))
        return str(result) if result is not None else None

    async def consume_otp(self, user_id: UUID, purpose: str) -> None:
        key = self._keys.otp(user_id, purpose)
        await self._client.delete(key.name)

    async def verify_and_consume_otp(
        self, user_id: UUID, purpose: str, candidate_hash: str, max_attempts: int
    ) -> int:
        key = self._keys.otp(user_id, purpose)
        result = await cast(
            Awaitable[Any],
            self._client.eval(
                VERIFY_OTP_SCRIPT, 1, key.name, candidate_hash, str(max_attempts)
            ),
        )
        return int(result)

    async def increment_rate_limit(self, route: str, subject: str, window_seconds: int) -> int:
        key = self._keys.rate_limit(route, subject, window_seconds)
        result = await cast(
            Awaitable[Any],
            self._client.eval(RATE_LIMIT_SCRIPT, 1, key.name, str(key.ttl_seconds)),
        )
        return int(result)

    async def reset_rate_limit(self, route: str, subject: str, window_seconds: int) -> None:
        key = self._keys.rate_limit(route, subject, window_seconds)
        await self._client.delete(key.name)

    async def lock_login(self, subject: str) -> None:
        key = self._keys.login_lock(subject)
        await cast(Awaitable[Any], self._client.set(key.name, "1", ex=key.ttl_seconds))

    async def login_is_locked(self, subject: str) -> bool:
        key = self._keys.login_lock(subject)
        return bool(await self._client.exists(key.name))

    async def store_login_workflow(self, token: str, payload: dict[str, Any]) -> None:
        key = self._keys.login_workflow(token)
        await cast(
            Awaitable[Any], self._client.set(key.name, json.dumps(payload), ex=key.ttl_seconds)
        )

    async def get_login_workflow(self, token: str) -> dict[str, Any] | None:
        key = self._keys.login_workflow(token)
        value = await self._client.get(key.name)
        return cast(dict[str, Any], json.loads(value)) if value is not None else None

    async def consume_login_workflow(self, token: str) -> dict[str, Any] | None:
        key = self._keys.login_workflow(token)
        value = await self._client.getdel(key.name)
        return cast(dict[str, Any], json.loads(value)) if value is not None else None

    async def store_mfa_challenge(self, token: str, payload: dict[str, Any]) -> None:
        key = self._keys.mfa_challenge(token)
        await cast(
            Awaitable[Any], self._client.set(key.name, json.dumps(payload), ex=key.ttl_seconds)
        )

    async def get_mfa_challenge(self, token: str) -> dict[str, Any] | None:
        key = self._keys.mfa_challenge(token)
        value = await self._client.get(key.name)
        return cast(dict[str, Any], json.loads(value)) if value is not None else None

    async def consume_mfa_challenge(self, token: str) -> dict[str, Any] | None:
        key = self._keys.mfa_challenge(token)
        value = await self._client.getdel(key.name)
        return cast(dict[str, Any], json.loads(value)) if value is not None else None

    async def store_webauthn_challenge(
        self, token: str, payload: dict[str, Any]
    ) -> None:
        key = self._keys.webauthn_challenge(token)
        await cast(
            Awaitable[Any], self._client.set(key.name, json.dumps(payload), ex=key.ttl_seconds)
        )

    async def consume_webauthn_challenge(self, token: str) -> dict[str, Any] | None:
        key = self._keys.webauthn_challenge(token)
        value = await self._client.getdel(key.name)
        return cast(dict[str, Any], json.loads(value)) if value is not None else None

    async def lock_factor(self, factor_id: UUID) -> None:
        key = self._keys.factor_lock(factor_id)
        await cast(Awaitable[Any], self._client.set(key.name, "1", ex=key.ttl_seconds))

    async def factor_is_locked(self, factor_id: UUID) -> bool:
        key = self._keys.factor_lock(factor_id)
        return bool(await self._client.exists(key.name))

    async def store_oidc_workflow(self, state: str, payload: dict[str, Any]) -> None:
        key = self._keys.oidc_workflow(state)
        await cast(
            Awaitable[Any], self._client.set(key.name, json.dumps(payload), ex=key.ttl_seconds)
        )

    async def consume_oidc_workflow(self, state: str) -> dict[str, Any] | None:
        key = self._keys.oidc_workflow(state)
        value = await self._client.getdel(key.name)
        return cast(dict[str, Any], json.loads(value)) if value is not None else None

    async def revoke_access_token(self, jti: UUID, remaining_lifetime: int) -> None:
        key = self._keys.access_revocation(jti, remaining_lifetime)
        await cast(Awaitable[Any], self._client.set(key.name, "1", ex=key.ttl_seconds))
