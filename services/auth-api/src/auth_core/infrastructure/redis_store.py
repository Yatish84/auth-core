from redis.asyncio import Redis

from auth_core.config import get_settings
from auth_core.infrastructure.redis_security import RedisSecurityStore, SecurityKeyFactory

settings = get_settings()
redis_client: Redis = Redis.from_url(settings.redis_url, decode_responses=True)
security_store = RedisSecurityStore(
    redis_client, SecurityKeyFactory(settings.redis_key_hmac_secret.encode())
)


async def check_redis() -> None:
    await redis_client.ping()


async def close_redis() -> None:
    await redis_client.aclose()
