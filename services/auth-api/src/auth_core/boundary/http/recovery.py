from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field

from auth_core.boundary.http.registration import request_id
from auth_core.boundary.http.session import access_claims, session_control
from auth_core.config import get_settings
from auth_core.control.recovery import RecoveryControl, SupportAdminControl
from auth_core.entity.recovery import (
    ContactChangeRecord,
    ContactProof,
    ContactType,
    GovernedResetRecord,
    RecoveryError,
)
from auth_core.entity.session import SessionError
from auth_core.infrastructure.database import session_factory
from auth_core.infrastructure.persistence.recovery_repository import (
    SqlAlchemyRecoveryRepository,
)
from auth_core.infrastructure.providers.breach import HibpBreachPasswordProvider
from auth_core.infrastructure.providers.notifications import (
    MailpitEmailProvider,
    MailpitRecoveryNotificationProvider,
    MailpitSMSProvider,
)
from auth_core.infrastructure.redis_store import security_store
from auth_core.infrastructure.security.passwords import Argon2idPasswordHasher

router = APIRouter(prefix="/api/v1", tags=["recovery and administration"])
settings = get_settings()
password_hasher = Argon2idPasswordHasher()
email_provider = MailpitEmailProvider(
    settings.smtp_host, settings.smtp_port, settings.email_sender
)
notifications = MailpitRecoveryNotificationProvider(
    email_provider,
    MailpitSMSProvider(email_provider, settings.local_sms_inbox),
)
recovery_repository = SqlAlchemyRecoveryRepository(session_factory, password_hasher)
recovery_control = RecoveryControl(
    repository=recovery_repository,
    password_hasher=password_hasher,
    breach_provider=HibpBreachPasswordProvider(settings.hibp_user_agent),
    notifications=notifications,
    rate_store=security_store,
    session_revoker=session_control,
    reset_base_url=settings.password_reset_base_url,
    token_pepper=settings.recovery_token_hmac_secret.encode(),
    otp_pepper=settings.otp_hmac_secret.encode(),
)
admin_control = SupportAdminControl(
    repository=recovery_repository,
    notifications=notifications,
    session_revoker=session_control,
    reset_base_url=settings.password_reset_base_url,
    token_pepper=settings.recovery_token_hmac_secret.encode(),
)


class PasswordForgotRequest(BaseModel):
    email: EmailStr


class PasswordResetRequest(BaseModel):
    token: str = Field(min_length=20, max_length=512)
    new_password: str = Field(min_length=12, max_length=128)


class GenericAcceptedResponse(BaseModel):
    status: Literal["accepted"] = "accepted"
    message: str


class PasswordUpdatedResponse(BaseModel):
    status: Literal["updated"] = "updated"


class ContactChangeRequest(BaseModel):
    contact_type: ContactType
    new_value: str = Field(min_length=3, max_length=320)


class ContactVerificationRequest(BaseModel):
    request_id: UUID
    code: str = Field(pattern=r"^\d{6}$")


class ContactChangeResponse(BaseModel):
    request_id: UUID
    contact_type: ContactType
    state: Literal["pending", "applied"]
    expires_at: datetime
    old_verified: bool
    new_verified: bool


class TicketRequest(BaseModel):
    ticket_reference: str = Field(min_length=3, max_length=120)


class SuspensionRequest(TicketRequest):
    reason: str = Field(min_length=3, max_length=240)


class SupportRecoveryRequest(TicketRequest):
    evidence_reference: str = Field(min_length=3, max_length=120)


class MFAResetRequest(TicketRequest):
    target_user_id: UUID


class AdminActionResponse(BaseModel):
    status: Literal["completed"] = "completed"


class GovernedResetResponse(BaseModel):
    request_id: UUID
    target_user_id: UUID
    state: str
    initiated_at: datetime
    execute_after: datetime
    approved_at: datetime | None
    executed_at: datetime | None
    ticket_reference: str | None


def problem(
    request: Request,
    error: RecoveryError | SessionError,
    correlation_id: UUID,
) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        media_type="application/problem+json",
        content={
            "type": f"https://auth.vittavaan.com/problems/{error.code.value.lower()}",
            "title": "The recovery or administrative action could not be completed",
            "status": error.status_code,
            "detail": error.message,
            "instance": request.url.path,
            "code": error.code.value,
            "request_id": str(correlation_id),
        },
    )


@router.post(
    "/auth/password/forgot",
    response_model=GenericAcceptedResponse,
    status_code=202,
)
async def forgot_password(
    payload: PasswordForgotRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> GenericAcceptedResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        await recovery_control.request_password_reset(str(payload.email), correlation_id)
    except RecoveryError as error:
        return problem(request, error, correlation_id)
    return GenericAcceptedResponse(
        message="If the account is eligible, password-reset instructions have been sent."
    )


@router.post("/auth/password/reset", response_model=PasswordUpdatedResponse)
async def reset_password(
    payload: PasswordResetRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> PasswordUpdatedResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        await recovery_control.reset_password(
            payload.token, payload.new_password, correlation_id
        )
    except RecoveryError as error:
        return problem(request, error, correlation_id)
    return PasswordUpdatedResponse()


@router.post("/auth/contact-change", response_model=ContactChangeResponse, status_code=202)
async def start_contact_change(
    payload: ContactChangeRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> ContactChangeResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        record = await recovery_control.start_contact_change(
            claims, payload.contact_type, payload.new_value, correlation_id
        )
    except (RecoveryError, SessionError) as error:
        return problem(request, error, correlation_id)
    return contact_model(record)


@router.post("/auth/contact-change/verify-old", response_model=ContactChangeResponse)
async def verify_old_contact(
    payload: ContactVerificationRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> ContactChangeResponse | JSONResponse:
    return await verify_contact(
        payload, ContactProof.OLD, request, authorization, x_request_id
    )


@router.post("/auth/contact-change/verify-new", response_model=ContactChangeResponse)
async def verify_new_contact(
    payload: ContactVerificationRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> ContactChangeResponse | JSONResponse:
    return await verify_contact(
        payload, ContactProof.NEW, request, authorization, x_request_id
    )


async def verify_contact(
    payload: ContactVerificationRequest,
    proof: ContactProof,
    request: Request,
    authorization: str | None,
    supplied_request_id: str | None,
) -> ContactChangeResponse | JSONResponse:
    correlation_id = request_id(supplied_request_id)
    try:
        claims = await access_claims(authorization)
        record = await recovery_control.verify_contact_change(
            claims, payload.request_id, proof, payload.code, correlation_id
        )
    except (RecoveryError, SessionError) as error:
        return problem(request, error, correlation_id)
    return contact_model(record)


@router.post("/admin/users/{user_id}/unlock", response_model=AdminActionResponse)
async def unlock_user(
    user_id: UUID,
    payload: TicketRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> AdminActionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        await admin_control.unlock(
            claims, user_id, payload.ticket_reference, correlation_id
        )
    except (RecoveryError, SessionError) as error:
        return problem(request, error, correlation_id)
    return AdminActionResponse()


@router.post("/admin/users/{user_id}/suspend", response_model=AdminActionResponse)
async def suspend_user(
    user_id: UUID,
    payload: SuspensionRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> AdminActionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        await admin_control.suspend(
            claims,
            user_id,
            payload.ticket_reference,
            payload.reason,
            correlation_id,
        )
    except (RecoveryError, SessionError) as error:
        return problem(request, error, correlation_id)
    return AdminActionResponse()


@router.post(
    "/admin/users/{user_id}/recovery",
    response_model=GenericAcceptedResponse,
    status_code=202,
)
async def support_recovery(
    user_id: UUID,
    payload: SupportRecoveryRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> GenericAcceptedResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        await admin_control.support_recovery(
            claims,
            user_id,
            payload.ticket_reference,
            payload.evidence_reference,
            correlation_id,
        )
    except (RecoveryError, SessionError) as error:
        return problem(request, error, correlation_id)
    return GenericAcceptedResponse(message="The governed recovery instructions were issued.")


@router.post("/admin/mfa-resets", response_model=GovernedResetResponse, status_code=202)
async def initiate_mfa_reset(
    payload: MFAResetRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> GovernedResetResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        record = await admin_control.initiate_mfa_reset(
            claims, payload.target_user_id, payload.ticket_reference, correlation_id
        )
    except (RecoveryError, SessionError) as error:
        return problem(request, error, correlation_id)
    return governed_model(record)


@router.post("/admin/mfa-resets/{reset_id}/approve", response_model=GovernedResetResponse)
async def approve_mfa_reset(
    reset_id: UUID,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> GovernedResetResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        record = await admin_control.approve_mfa_reset(claims, reset_id, correlation_id)
    except (RecoveryError, SessionError) as error:
        return problem(request, error, correlation_id)
    return governed_model(record)


@router.post("/admin/mfa-resets/{reset_id}/execute", response_model=GovernedResetResponse)
async def execute_mfa_reset(
    reset_id: UUID,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> GovernedResetResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        record = await admin_control.execute_mfa_reset(claims, reset_id, correlation_id)
    except (RecoveryError, SessionError) as error:
        return problem(request, error, correlation_id)
    return governed_model(record)


@router.get("/admin/mfa-resets/{reset_id}", response_model=GovernedResetResponse)
async def get_mfa_reset(
    reset_id: UUID,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> GovernedResetResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        claims = await access_claims(authorization)
        record = await admin_control.get_mfa_reset(claims, reset_id)
    except (RecoveryError, SessionError) as error:
        return problem(request, error, correlation_id)
    return governed_model(record)


def contact_model(record: ContactChangeRecord) -> ContactChangeResponse:
    return ContactChangeResponse(
        request_id=record.request_id,
        contact_type=record.contact_type,
        state="applied" if record.applied_at else "pending",
        expires_at=record.expires_at,
        old_verified=record.old_verified_at is not None,
        new_verified=record.new_verified_at is not None,
    )


def governed_model(record: GovernedResetRecord) -> GovernedResetResponse:
    return GovernedResetResponse(
        request_id=record.request_id,
        target_user_id=record.target_user_id,
        state=record.state,
        initiated_at=record.initiated_at,
        execute_after=record.execute_after,
        approved_at=record.approved_at,
        executed_at=record.executed_at,
        ticket_reference=record.ticket_reference,
    )
