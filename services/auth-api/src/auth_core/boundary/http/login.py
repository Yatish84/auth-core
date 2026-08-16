from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field

from auth_core.boundary.http.registration import remote_ip, request_id
from auth_core.config import get_settings
from auth_core.control.login import LoginControl
from auth_core.entity.login import LoginDecision, LoginError
from auth_core.infrastructure.database import session_factory
from auth_core.infrastructure.persistence.login_repository import SqlAlchemyLoginRepository
from auth_core.infrastructure.providers.captcha import LocalCaptchaProvider
from auth_core.infrastructure.providers.notifications import (
    MailpitEmailProvider,
    MailpitSMSProvider,
)
from auth_core.infrastructure.providers.oidc import LocalOIDCProvider
from auth_core.infrastructure.redis_store import security_store
from auth_core.infrastructure.security.passwords import Argon2idPasswordHasher

router = APIRouter(prefix="/api/v1/auth", tags=["login"])
settings = get_settings()
email_provider = MailpitEmailProvider(settings.smtp_host, settings.smtp_port, settings.email_sender)
login_control = LoginControl(
    repository=SqlAlchemyLoginRepository(session_factory),
    password_hasher=Argon2idPasswordHasher(),
    captcha_provider=LocalCaptchaProvider(settings.local_captcha_token),
    sms_provider=MailpitSMSProvider(email_provider, settings.local_sms_inbox),
    oidc_provider=LocalOIDCProvider(
        settings.local_oidc_signing_secret.encode(), settings.local_oidc_frontend_url
    ),
    redis_store=security_store,
    signal_hmac_secret=settings.login_signal_hmac_secret.encode(),
    otp_pepper=settings.otp_hmac_secret.encode(),
)


class PasswordLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    device_fingerprint: str = Field(min_length=16, max_length=512)


class PhoneLoginRequest(BaseModel):
    phone: str = Field(min_length=8, max_length=32)
    captcha_token: str = Field(min_length=1, max_length=2048)


class PhoneLoginConfirmRequest(PhoneLoginRequest):
    code: str = Field(pattern=r"^\d{6}$")
    device_fingerprint: str = Field(min_length=16, max_length=512)


class OIDCCallbackRequest(BaseModel):
    state: str = Field(min_length=20, max_length=512)
    code: str = Field(min_length=20, max_length=8192)
    device_fingerprint: str = Field(min_length=16, max_length=512)


class LoginDecisionResponse(BaseModel):
    decision: Literal["session_ready", "mfa_required", "collision_proof_required"]
    risk: Literal["low", "medium", "high"]
    workflow_token: str
    allowed_methods: list[str]


class AcceptedResponse(BaseModel):
    status: Literal["accepted"] = "accepted"
    message: str


class OIDCAuthorizationResponse(BaseModel):
    authorization_url: str
    state: str


class FallbackOptionsResponse(BaseModel):
    allowed_methods: list[str]


def response(decision: LoginDecision) -> LoginDecisionResponse:
    return LoginDecisionResponse(
        decision=decision.decision.value,
        risk=decision.risk.value,
        workflow_token=decision.workflow_token,
        allowed_methods=list(decision.allowed_methods),
    )


def problem(request: Request, error: LoginError, correlation_id: UUID) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        media_type="application/problem+json",
        content={
            "type": f"https://auth.vittavaan.com/problems/{error.code.value.lower()}",
            "title": "Login request could not be completed",
            "status": error.status_code,
            "detail": error.message,
            "instance": request.url.path,
            "code": error.code.value,
            "request_id": str(correlation_id),
        },
    )


@router.post("/login", response_model=LoginDecisionResponse)
async def login_password(
    payload: PasswordLoginRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> LoginDecisionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        decision = await login_control.login_password(
            str(payload.email),
            payload.password,
            payload.device_fingerprint,
            remote_ip(request),
            correlation_id,
        )
    except LoginError as error:
        return problem(request, error, correlation_id)
    return response(decision)


@router.post("/login/phone/request", response_model=AcceptedResponse, status_code=202)
async def request_phone_login(
    payload: PhoneLoginRequest, request: Request
) -> AcceptedResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        await login_control.request_phone_otp(
            payload.phone, payload.captcha_token, remote_ip(request)
        )
    except LoginError as error:
        return problem(request, error, correlation_id)
    return AcceptedResponse(message="If the account is eligible, a login code has been sent.")


@router.post("/login/phone/confirm", response_model=LoginDecisionResponse)
async def confirm_phone_login(
    payload: PhoneLoginConfirmRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> LoginDecisionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        decision = await login_control.login_phone(
            payload.phone,
            payload.code,
            payload.captcha_token,
            payload.device_fingerprint,
            remote_ip(request),
            correlation_id,
        )
    except LoginError as error:
        return problem(request, error, correlation_id)
    return response(decision)


@router.post("/sso/{provider}/authorize", response_model=OIDCAuthorizationResponse)
async def authorize_oidc(
    provider: str, request: Request
) -> OIDCAuthorizationResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        authorization_url, state = await login_control.start_oidc(provider)
    except LoginError as error:
        return problem(request, error, correlation_id)
    return OIDCAuthorizationResponse(authorization_url=authorization_url, state=state)


@router.post("/sso/{provider}/callback", response_model=LoginDecisionResponse)
async def callback_oidc(
    provider: str,
    payload: OIDCCallbackRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> LoginDecisionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        decision = await login_control.login_oidc(
            provider,
            payload.state,
            payload.code,
            payload.device_fingerprint,
            remote_ip(request),
            correlation_id,
        )
    except LoginError as error:
        return problem(request, error, correlation_id)
    return response(decision)


@router.get("/fallback-options", response_model=FallbackOptionsResponse)
async def fallback_options(
    request: Request, workflow_token: Annotated[str, Query(min_length=20, max_length=512)]
) -> FallbackOptionsResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        methods = await login_control.fallback_options(workflow_token)
    except LoginError as error:
        return problem(request, error, correlation_id)
    return FallbackOptionsResponse(allowed_methods=list(methods))
