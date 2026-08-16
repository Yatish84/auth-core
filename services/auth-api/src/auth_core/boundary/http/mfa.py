from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from auth_core.boundary.http.registration import request_id
from auth_core.config import get_settings
from auth_core.control.mfa import MFAControl
from auth_core.entity.mfa import MFACompletion, MFAError, MFAMethod
from auth_core.infrastructure.database import session_factory
from auth_core.infrastructure.persistence.mfa_repository import SqlAlchemyMFARepository
from auth_core.infrastructure.providers.notifications import (
    MailpitEmailProvider,
    MailpitMFANotificationProvider,
    MailpitSMSProvider,
)
from auth_core.infrastructure.providers.totp import PyOTPProvider
from auth_core.infrastructure.providers.webauthn import PyWebAuthnProvider
from auth_core.infrastructure.redis_store import security_store
from auth_core.infrastructure.security.passwords import Argon2idPasswordHasher
from auth_core.infrastructure.security.secrets import LocalAESGCMSecretCipher

router = APIRouter(prefix="/api/v1/auth", tags=["mfa"])
settings = get_settings()
email_provider = MailpitEmailProvider(settings.smtp_host, settings.smtp_port, settings.email_sender)
sms_provider = MailpitSMSProvider(email_provider, settings.local_sms_inbox)
mfa_control = MFAControl(
    repository=SqlAlchemyMFARepository(session_factory),
    password_hasher=Argon2idPasswordHasher(),
    secret_cipher=LocalAESGCMSecretCipher(settings.local_data_encryption_key),
    totp_provider=PyOTPProvider(settings.totp_issuer),
    notification_provider=MailpitMFANotificationProvider(email_provider, sms_provider),
    webauthn_provider=PyWebAuthnProvider(
        settings.webauthn_rp_id,
        settings.webauthn_rp_name,
        settings.allowed_webauthn_origins,
    ),
    redis_store=security_store,
    otp_pepper=settings.otp_hmac_secret.encode(),
    backup_code_pepper=settings.backup_code_hmac_secret.encode(),
)


class ChallengeRequest(BaseModel):
    workflow_token: str = Field(min_length=20, max_length=512)
    method: MFAMethod


class ChallengeTokenRequest(BaseModel):
    challenge_token: str = Field(min_length=20, max_length=512)


class VerifyCodeRequest(ChallengeTokenRequest):
    code: str = Field(min_length=6, max_length=32)


class TOTPSetupRequest(BaseModel):
    workflow_token: str = Field(min_length=20, max_length=512)
    label: str = Field(default="Authenticator app", min_length=1, max_length=120)


class TOTPConfirmRequest(BaseModel):
    enrollment_token: str = Field(min_length=20, max_length=512)
    code: str = Field(pattern=r"^\d{6}$")


class PasskeyRegistrationOptionsRequest(BaseModel):
    workflow_token: str = Field(min_length=20, max_length=512)
    label: str = Field(default="Passkey", min_length=1, max_length=120)


class PasskeyAuthenticationOptionsRequest(BaseModel):
    workflow_token: str | None = Field(default=None, min_length=20, max_length=512)


class PasskeyConfirmRequest(ChallengeTokenRequest):
    credential: dict[str, Any]


class CollisionPasswordProofRequest(BaseModel):
    workflow_token: str = Field(min_length=20, max_length=512)
    password: str = Field(min_length=1, max_length=128)


class FactorRevokeRequest(BaseModel):
    workflow_token: str = Field(min_length=20, max_length=512)


class MethodsResponse(BaseModel):
    methods: list[MFAMethod]


class ChallengeResponse(BaseModel):
    challenge_token: str
    method: MFAMethod
    destination_hint: str | None


class CompletionResponse(BaseModel):
    result: Literal["session_ready", "identity_linked"]
    workflow_token: str | None
    backup_codes: list[str]


class TOTPSetupResponse(BaseModel):
    enrollment_token: str
    provisioning_uri: str
    manual_secret: str


class PasskeyOptionsResponse(BaseModel):
    challenge_token: str
    public_key: dict[str, Any]


class FactorResponse(BaseModel):
    mfa_id: UUID
    factor_type: str
    label: str | None


class FactorsResponse(BaseModel):
    factors: list[FactorResponse]


def completion_response(value: MFACompletion) -> CompletionResponse:
    return CompletionResponse(
        result=value.result.value,
        workflow_token=value.workflow_token,
        backup_codes=list(value.backup_codes),
    )


def problem(request: Request, error: MFAError, correlation_id: UUID) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        media_type="application/problem+json",
        content={
            "type": f"https://auth.vittavaan.com/problems/{error.code.value.lower()}",
            "title": "Security verification could not be completed",
            "status": error.status_code,
            "detail": error.message,
            "instance": request.url.path,
            "code": error.code.value,
            "request_id": str(correlation_id),
        },
    )


@router.get("/mfa/methods", response_model=MethodsResponse)
async def methods(
    request: Request,
    workflow_token: Annotated[str, Query(min_length=20, max_length=512)],
) -> MethodsResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        values = await mfa_control.available_methods(workflow_token)
    except MFAError as error:
        return problem(request, error, correlation_id)
    return MethodsResponse(methods=list(values))


@router.post("/mfa/challenge", response_model=ChallengeResponse)
async def issue_challenge(
    payload: ChallengeRequest, request: Request
) -> ChallengeResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        challenge = await mfa_control.issue_challenge(payload.workflow_token, payload.method)
    except MFAError as error:
        return problem(request, error, correlation_id)
    return ChallengeResponse(
        challenge_token=challenge.challenge_token,
        method=challenge.method,
        destination_hint=challenge.destination_hint,
    )


@router.post("/mfa/challenge/resend", response_model=ChallengeResponse)
async def resend_challenge(
    payload: ChallengeTokenRequest, request: Request
) -> ChallengeResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        challenge = await mfa_control.resend_challenge(payload.challenge_token)
    except MFAError as error:
        return problem(request, error, correlation_id)
    return ChallengeResponse(
        challenge_token=challenge.challenge_token,
        method=challenge.method,
        destination_hint=challenge.destination_hint,
    )


@router.post("/mfa/verify", response_model=CompletionResponse)
async def verify_challenge(
    payload: VerifyCodeRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> CompletionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        result = await mfa_control.verify_challenge(
            payload.challenge_token, payload.code, correlation_id
        )
    except MFAError as error:
        return problem(request, error, correlation_id)
    return completion_response(result)


@router.post("/mfa/totp/setup", response_model=TOTPSetupResponse)
async def setup_totp(
    payload: TOTPSetupRequest, request: Request
) -> TOTPSetupResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        result = await mfa_control.setup_totp(payload.workflow_token, payload.label)
    except MFAError as error:
        return problem(request, error, correlation_id)
    return TOTPSetupResponse(
        enrollment_token=result.enrollment_token,
        provisioning_uri=result.provisioning_uri,
        manual_secret=result.manual_secret,
    )


@router.post("/mfa/totp/confirm", response_model=CompletionResponse)
async def confirm_totp(
    payload: TOTPConfirmRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> CompletionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        result = await mfa_control.confirm_totp(
            payload.enrollment_token, payload.code, correlation_id
        )
    except MFAError as error:
        return problem(request, error, correlation_id)
    return completion_response(result)


@router.post("/mfa/passkeys/options", response_model=PasskeyOptionsResponse)
async def passkey_registration_options(
    payload: PasskeyRegistrationOptionsRequest, request: Request
) -> PasskeyOptionsResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        result = await mfa_control.passkey_registration_options(
            payload.workflow_token, payload.label
        )
    except MFAError as error:
        return problem(request, error, correlation_id)
    return PasskeyOptionsResponse(
        challenge_token=result.challenge_token, public_key=result.public_key
    )


@router.post("/mfa/passkeys/confirm", response_model=CompletionResponse)
async def confirm_passkey_registration(
    payload: PasskeyConfirmRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> CompletionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        result = await mfa_control.confirm_passkey_registration(
            payload.challenge_token, payload.credential, correlation_id
        )
    except MFAError as error:
        return problem(request, error, correlation_id)
    return completion_response(result)


@router.post("/passkeys/options", response_model=PasskeyOptionsResponse)
async def passkey_authentication_options(
    payload: PasskeyAuthenticationOptionsRequest, request: Request
) -> PasskeyOptionsResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        result = await mfa_control.passkey_authentication_options(payload.workflow_token)
    except MFAError as error:
        return problem(request, error, correlation_id)
    return PasskeyOptionsResponse(
        challenge_token=result.challenge_token, public_key=result.public_key
    )


@router.post("/passkeys/verify", response_model=CompletionResponse)
async def verify_passkey(
    payload: PasskeyConfirmRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> CompletionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        result = await mfa_control.verify_passkey(
            payload.challenge_token, payload.credential, correlation_id
        )
    except MFAError as error:
        return problem(request, error, correlation_id)
    return completion_response(result)


@router.post("/identities/collision/prove", response_model=CompletionResponse)
async def prove_collision_password(
    payload: CollisionPasswordProofRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> CompletionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        result = await mfa_control.prove_collision_password(
            payload.workflow_token, payload.password, correlation_id
        )
    except MFAError as error:
        return problem(request, error, correlation_id)
    return completion_response(result)


@router.get("/mfa/devices", response_model=FactorsResponse)
async def list_factors(
    request: Request,
    workflow_token: Annotated[str, Query(min_length=20, max_length=512)],
) -> FactorsResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        factors = await mfa_control.list_factors(workflow_token)
    except MFAError as error:
        return problem(request, error, correlation_id)
    return FactorsResponse(
        factors=[
            FactorResponse(
                mfa_id=factor.mfa_id,
                factor_type=factor.factor_type,
                label=factor.label,
            )
            for factor in factors
        ]
    )


@router.delete("/mfa/devices/{mfa_id}", response_model=CompletionResponse)
async def revoke_factor(
    mfa_id: UUID,
    payload: FactorRevokeRequest,
    request: Request,
    x_request_id: Annotated[str | None, Header()] = None,
) -> CompletionResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        result = await mfa_control.revoke_factor(
            payload.workflow_token, mfa_id, correlation_id
        )
    except MFAError as error:
        return problem(request, error, correlation_id)
    return completion_response(result)
