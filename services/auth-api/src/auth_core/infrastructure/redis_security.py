import hmac
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

RATE_LIMIT_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
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

    async def increment_rate_limit(self, route: str, subject: str, window_seconds: int) -> int:
        key = self._keys.rate_limit(route, subject, window_seconds)
        result = await cast(
            Awaitable[Any],
            self._client.eval(RATE_LIMIT_SCRIPT, 1, key.name, str(key.ttl_seconds)),
        )
        return int(result)

    async def revoke_access_token(self, jti: UUID, remaining_lifetime: int) -> None:
        key = self._keys.access_revocation(jti, remaining_lifetime)
        await cast(Awaitable[Any], self._client.set(key.name, "1", ex=key.ttl_seconds))
