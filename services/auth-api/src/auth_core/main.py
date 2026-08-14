from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth_core.boundary.http.health import router as health_router
from auth_core.config import get_settings
from auth_core.infrastructure.database import close_database
from auth_core.infrastructure.redis_store import close_redis


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    await close_database()
    await close_redis()


settings = get_settings()
app = FastAPI(
    title="Vittavaan Auth-Core API",
    version="0.1.0",
    docs_url="/docs" if settings.app_env != "production" else None,
    redoc_url=None,
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["Content-Type", "X-Request-ID"],
)
app.include_router(health_router)
