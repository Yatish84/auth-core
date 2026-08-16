from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Cookie, Header, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from auth_core.boundary.http.registration import request_id
from auth_core.config import get_settings
from auth_core.control.session import REFRESH_FAMILY_SECONDS, SessionControl
from auth_core.entity.session import (
    AccessClaims,
    ClientType,
    SessionError,
    SessionErrorCode,
    SessionSummary,
    TokenPair,
)
from auth_core.infrastructure.database import session_factory
from auth_core.infrastructure.persistence.session_repository import (
    SqlAlchemySessionRepository,
)
from auth_core.infrastructure.redis_store import security_store
from auth_core.infrastructure.token_store import token_provider

router = APIRouter(prefix="/api/v1/auth", tags=["sessions"])
jwks_router = APIRouter(tags=["sessions"])
settings = get_settings()
session_control = SessionControl(
    repository=SqlAlchemySessionRepository(session_factory),
    tokens=token_provider,
    redis_store=security_store,
    token_pepper=settings.refresh_token_hmac_secret.encode(),
    fingerprint_pepper=settings.login_signal_hmac_secret.encode(),
)

REFRESH_COOKIE = "__Host-auth_refresh"
CSRF_COOKIE = "__Host-auth_csrf"


class CreateSessionRequest(BaseModel):
    workflow_token: str = Field(min_length=20, max_length=512)


class RefreshRequest(BaseModel):
    refresh_token: str | None = Field(default=None, min_length=32, max_length=512)


class TokenResponse(BaseModel):
    token_type: str = "Bearer"
    access_token: str
    access_expires_at: datetime
    refresh_token: str | None
    refresh_expires_at: datetime
    session_id: UUID
    csrf_token: str | None


class LogoutAllResponse(BaseModel):
    revoked_sessions: int


class SessionResponse(BaseModel):
    session_id: UUID
    client_type: ClientType
    device_hint: str
    ip_address: str | None
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime
    current: bool


class SessionsResponse(BaseModel):
    sessions: list[SessionResponse]


def problem(request: Request, error: SessionError, correlation_id: UUID) -> JSONResponse:
    response = JSONResponse(
        status_code=error.status_code,
        media_type="application/problem+json",
        content={
            "type": f"https://auth.vittavaan.com/problems/{error.code.value.lower()}",
            "title": "The session operation could not be completed",
            "status": error.status_code,
            "detail": error.message,
            "instance": request.url.path,
            "code": error.code.value,
            "request_id": str(correlation_id),
        },
    )
    if error.status_code == 401:
        response.headers["WWW-Authenticate"] = "Bearer"
    return response


def token_response(pair: TokenPair, client_type: ClientType) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access_token,
        access_expires_at=pair.access_expires_at,
        refresh_token=pair.refresh_token if client_type == ClientType.MOBILE else None,
        refresh_expires_at=pair.refresh_expires_at,
        session_id=pair.session_id,
        csrf_token=pair.csrf_token if client_type == ClientType.WEB else None,
    )


def set_web_cookies(response: Response, pair: TokenPair) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        pair.refresh_token,
        max_age=REFRESH_FAMILY_SECONDS,
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
    )
    if pair.csrf_token:
        response.set_cookie(
            CSRF_COOKIE,
            pair.csrf_token,
            max_age=REFRESH_FAMILY_SECONDS,
            secure=True,
            httponly=False,
            samesite="lax",
            path="/",
        )


def clear_web_cookies(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, secure=True, httponly=True, samesite="lax", path="/")
    response.delete_cookie(CSRF_COOKIE, secure=True, httponly=False, samesite="lax", path="/")


def require_csrf(
    client_type: ClientType,
    header_value: str | None,
    cookie_value: str | None,
) -> None:
    if client_type == ClientType.WEB and (
        not header_value or not cookie_value or header_value != cookie_value
    ):
        raise SessionError(
            SessionErrorCode.CSRF_INVALID,
            "The browser security token is missing or invalid.",
            403,
        )


async def access_claims(authorization: str | None) -> AccessClaims:
    if not authorization or not authorization.startswith("Bearer "):
        raise SessionError(
            SessionErrorCode.TOKEN_INVALID,
            "The access token is invalid or expired.",
            401,
        )
    return await session_control.authenticate(authorization[7:])


@router.post("/session", response_model=TokenResponse)
async def create_session(
    payload: CreateSessionRequest,
    request: Request,
    response: Response,
    x_client_type: Annotated[ClientType, Header()],
    x_device_fingerprint: Annotated[str, Header(min_length=16, max_length=512)],
    x_request_id: Annotated[str | None, Header()] = None,
) -> TokenResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        pair = await session_control.create_session(
            payload.workflow_token,
            x_client_type,
            x_device_fingerprint,
            request.client.host if request.client else None,
            correlation_id,
        )
    except SessionError as error:
        return problem(request, error, correlation_id)
    if x_client_type == ClientType.WEB:
        set_web_cookies(response, pair)
    return token_response(pair, x_client_type)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    request: Request,
    response: Response,
    x_client_type: Annotated[ClientType, Header()],
    x_device_fingerprint: Annotated[str, Header(min_length=16, max_length=512)],
    refresh_cookie: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
    csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE)] = None,
    x_csrf_token: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> TokenResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        require_csrf(x_client_type, x_csrf_token, csrf_cookie)
        supplied = refresh_cookie if x_client_type == ClientType.WEB else payload.refresh_token
        if supplied is None:
            raise SessionError(
                SessionErrorCode.TOKEN_INVALID,
                "The refresh token is invalid or expired.",
                401,
            )
        pair = await session_control.refresh(
            supplied, x_client_type, x_device_fingerprint, correlation_id
        )
    except SessionError as error:
        error_response = problem(request, error, correlation_id)
        clear_web_cookies(error_response)
        return error_response
    if x_client_type == ClientType.WEB:
        set_web_cookies(response, pair)
    return token_response(pair, x_client_type)


@router.post("/logout", status_code=204, response_class=Response, response_model=None)
async def logout(
    request: Request,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> Response | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        await session_control.logout(claims, correlation_id)
    except SessionError as error:
        return problem(request, error, correlation_id)
    clear_web_cookies(response)
    response.status_code = 204
    return response


@router.post("/logout-all", response_model=LogoutAllResponse)
async def logout_all(
    request: Request,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> LogoutAllResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        count = await session_control.logout_all(claims, correlation_id)
    except SessionError as error:
        return problem(request, error, correlation_id)
    clear_web_cookies(response)
    return LogoutAllResponse(revoked_sessions=count)


@router.get("/sessions", response_model=SessionsResponse)
async def sessions(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> SessionsResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        claims = await access_claims(authorization)
        values = await session_control.sessions(claims)
    except SessionError as error:
        return problem(request, error, correlation_id)
    return SessionsResponse(sessions=[session_model(item) for item in values])


@router.delete(
    "/sessions/{session_id}", status_code=204, response_class=Response, response_model=None
)
async def revoke_session(
    session_id: UUID,
    request: Request,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> Response | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        await session_control.revoke_selected(claims, session_id, correlation_id)
    except SessionError as error:
        return problem(request, error, correlation_id)
    if session_id == claims.session_id:
        clear_web_cookies(response)
    response.status_code = 204
    return response


@jwks_router.get("/.well-known/jwks.json")
async def jwks() -> dict[str, Any]:
    return dict(token_provider.jwks())


def session_model(value: SessionSummary) -> SessionResponse:
    return SessionResponse(
        session_id=value.session_id,
        client_type=value.client_type,
        device_hint=value.device_hint,
        ip_address=value.ip_address,
        created_at=value.created_at,
        last_activity_at=value.last_activity_at,
        expires_at=value.expires_at,
        current=value.current,
    )
