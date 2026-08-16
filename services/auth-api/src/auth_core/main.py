from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from auth_core.boundary.http.health import router as health_router
from auth_core.boundary.http.registration import router as registration_router
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
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Request-ID"],
)
app.include_router(health_router)
app.include_router(registration_router)


@app.exception_handler(RequestValidationError)
async def validation_problem(request: Request, error: RequestValidationError) -> JSONResponse:
    supplied_request_id = request.headers.get("X-Request-ID")
    try:
        correlation_id = UUID(supplied_request_id) if supplied_request_id else uuid4()
    except ValueError:
        correlation_id = uuid4()
    safe_errors = [
        {"field": ".".join(str(part) for part in item["loc"][1:]), "message": item["msg"]}
        for item in error.errors()
    ]
    return JSONResponse(
        status_code=422,
        media_type="application/problem+json",
        content={
            "type": "https://auth.vittavaan.com/problems/request-validation",
            "title": "Request validation failed",
            "status": 422,
            "detail": "One or more request fields are invalid.",
            "instance": request.url.path,
            "code": "REQUEST_VALIDATION_FAILED",
            "request_id": str(correlation_id),
            "errors": safe_errors,
        },
    )
