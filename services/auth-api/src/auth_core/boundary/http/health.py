import asyncio
from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from auth_core.config import get_settings
from auth_core.infrastructure.database import check_database
from auth_core.infrastructure.redis_store import check_redis

router = APIRouter(prefix="/health", tags=["health"])


class ComponentHealth(BaseModel):
    status: Literal["up", "down"]


class HealthResponse(BaseModel):
    service: str
    status: Literal["up", "ready", "not_ready"]
    components: dict[str, ComponentHealth] | None = None


async def component_status(check: Callable[[], Awaitable[None]]) -> ComponentHealth:
    try:
        await check()
    except Exception:
        return ComponentHealth(status="down")
    return ComponentHealth(status="up")


@router.get("/live", response_model=HealthResponse)
async def liveness() -> HealthResponse:
    return HealthResponse(service=get_settings().app_name, status="up")


@router.get("/ready", response_model=HealthResponse)
async def readiness() -> JSONResponse:
    database, redis = await asyncio.gather(
        component_status(check_database),
        component_status(check_redis),
    )
    components = {"postgresql": database, "redis": redis}
    ready = all(component.status == "up" for component in components.values())
    payload = HealthResponse(
        service=get_settings().app_name,
        status="ready" if ready else "not_ready",
        components=components,
    )
    return JSONResponse(status_code=200 if ready else 503, content=payload.model_dump())
