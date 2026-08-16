from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field

from auth_core.config import get_settings
from auth_core.control.registration import RegistrationControl
from auth_core.entity.registration import RegistrationError
from auth_core.infrastructure.database import session_factory
from auth_core.infrastructure.persistence.registration_repository import (
    SqlAlchemyRegistrationRepository,
)
from auth_core.infrastructure.providers.breach import HibpBreachPasswordProvider
from auth_core.infrastructure.providers.captcha import LocalCaptchaProvider
from auth_core.infrastructure.providers.notifications import (
    MailpitEmailProvider,
    MailpitSMSProvider,
)
from auth_core.infrastructure.redis_store import security_store
from auth_core.infrastructure.security.passwords import Argon2idPasswordHasher

router = APIRouter(prefix="/api/v1/auth", tags=["registration"])
settings = get_settings()
email_provider = MailpitEmailProvider(settings.smtp_host, settings.smtp_port, settings.email_sender)
registration_control = RegistrationControl(
    repository=SqlAlchemyRegistrationRepository(session_factory),
    password_hasher=Argon2idPasswordHasher(),
    breach_provider=HibpBreachPasswordProvider(settings.hibp_user_agent),
    captcha_provider=LocalCaptchaProvider(settings.local_captcha_token),
    email_provider=email_provider,
    sms_provider=MailpitSMSProvider(email_provider, settings.local_sms_inbox),
    redis_store=security_store,
    verification_base_url=settings.verification_base_url,
    otp_pepper=settings.otp_hmac_secret.encode(),
    referral_token_pepper=settings.workspace_token_hmac_secret.encode(),
)


class EmailSignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    given_name: str = Field(min_length=1, max_length=120)
    family_name: str = Field(min_length=1, max_length=120)
    captcha_token: str = Field(min_length=1, max_length=2048)
    referral_token: str | None = Field(default=None, min_length=20, max_length=512)


class EmailVerificationRequest(BaseModel):
    token: str = Field(min_length=20, max_length=512)


class EmailVerificationResendRequest(BaseModel):
    email: EmailStr
    captcha_token: str = Field(min_length=1, max_length=2048)


class PhoneSignupRequest(BaseModel):
    phone: str = Field(min_length=8, max_length=32)
    given_name: str | None = Field(default=None, min_length=1, max_length=120)
    family_name: str | None = Field(default=None, min_length=1, max_length=120)
    captcha_token: str = Field(min_length=1, max_length=2048)


class PhoneVerificationRequest(BaseModel):
    phone: str = Field(min_length=8, max_length=32)
    captcha_token: str = Field(min_length=1, max_length=2048)


class PhoneVerificationConfirmRequest(BaseModel):
    phone: str = Field(min_length=8, max_length=32)
    code: str = Field(pattern=r"^\d{6}$")
    captcha_token: str = Field(min_length=1, max_length=2048)


class AcceptedResponse(BaseModel):
    status: Literal["accepted"] = "accepted"
    message: str


class VerifiedResponse(BaseModel):
    status: Literal["verified"] = "verified"


class ProblemResponse(BaseModel):
    type: str
    title: str
    status: int
    detail: str
    instance: str
    code: str
    request_id: str


def request_id(value: str | None) -> UUID:
    try:
        return UUID(value) if value else uuid4()
    except ValueError:
        return uuid4()


def remote_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def problem(request: Request, error: RegistrationError, correlation_id: UUID) -> JSONResponse:
    payload = ProblemResponse(
        type=f"https://auth.vittavaan.com/problems/{error.code.value.lower()}",
        title="Registration request could not be completed",
        status=error.status_code,
        detail=error.message,
        instance=request.url.path,
        code=error.code.value,
        request_id=str(correlation_id),
    )
    return JSONResponse(
        status_code=error.status_code,
        content=payload.model_dump(),
        media_type="application/problem+json",
    )


@router.post("/signup", response_model=AcceptedResponse, status_code=201)
async def signup_email(
    payload: EmailSignupRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> AcceptedResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        await registration_control.register_email(
            str(payload.email),
            payload.password,
            payload.given_name,
            payload.family_name,
            payload.captcha_token,
            remote_ip(request),
            correlation_id,
            payload.referral_token,
        )
    except RegistrationError as error:
        return problem(request, error, correlation_id)
    return AcceptedResponse(
        message="If registration can proceed, verification instructions have been sent."
    )


@router.post("/verify/email", response_model=VerifiedResponse)
async def verify_email(
    payload: EmailVerificationRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> VerifiedResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        await registration_control.verify_email(payload.token, correlation_id)
    except RegistrationError as error:
        return problem(request, error, correlation_id)
    return VerifiedResponse()


@router.post("/verify/email/request", response_model=AcceptedResponse, status_code=202)
async def request_email_verification(
    payload: EmailVerificationResendRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> AcceptedResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        await registration_control.request_email_verification(
            str(payload.email), payload.captcha_token, remote_ip(request), correlation_id
        )
    except RegistrationError as error:
        return problem(request, error, correlation_id)
    return AcceptedResponse(
        message="If the account is eligible, verification instructions have been sent."
    )


@router.post("/signup/phone", response_model=AcceptedResponse, status_code=201)
async def signup_phone(
    payload: PhoneSignupRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> AcceptedResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        await registration_control.register_phone(
            payload.phone,
            payload.captcha_token,
            remote_ip(request),
            payload.given_name,
            payload.family_name,
            correlation_id,
        )
    except RegistrationError as error:
        return problem(request, error, correlation_id)
    return AcceptedResponse(
        message="If registration can proceed, a verification code has been sent."
    )


@router.post("/verify/phone/request", response_model=AcceptedResponse, status_code=202)
async def request_phone_verification(
    payload: PhoneVerificationRequest,
    request: Request,
) -> AcceptedResponse | JSONResponse:
    correlation_id = uuid4()
    try:
        await registration_control.request_phone_verification(
            payload.phone, payload.captcha_token, remote_ip(request)
        )
    except RegistrationError as error:
        return problem(request, error, correlation_id)
    return AcceptedResponse(
        message="If the account is eligible, a verification code has been sent."
    )


@router.post("/verify/phone/confirm", response_model=VerifiedResponse)
async def confirm_phone_verification(
    payload: PhoneVerificationConfirmRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> VerifiedResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        await registration_control.verify_phone(
            payload.phone,
            payload.code,
            payload.captcha_token,
            remote_ip(request),
            correlation_id,
        )
    except RegistrationError as error:
        return problem(request, error, correlation_id)
    return VerifiedResponse()
