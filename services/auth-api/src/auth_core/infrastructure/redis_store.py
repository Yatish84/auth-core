from redis.asyncio import Redis

from auth_core.config import get_settings

redis_client: Redis = Redis.from_url(get_settings().redis_url, decode_responses=True)


async def check_redis() -> None:
    await redis_client.ping()


async def close_redis() -> None:
    await redis_client.aclose()
