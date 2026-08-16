from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field

from auth_core.boundary.http.registration import request_id
from auth_core.boundary.http.session import access_claims
from auth_core.config import get_settings
from auth_core.control.workspace import WorkspaceControl
from auth_core.entity.session import SessionError
from auth_core.entity.workspace import (
    ReferralRecord,
    WorkspaceError,
    WorkspaceSummary,
    WorkspaceType,
)
from auth_core.infrastructure.database import session_factory
from auth_core.infrastructure.persistence.workspace_repository import (
    SqlAlchemyWorkspaceRepository,
)
from auth_core.infrastructure.providers.notifications import MailpitEmailProvider
from auth_core.infrastructure.redis_store import security_store

router = APIRouter(prefix="/api/v1", tags=["workspaces"])
settings = get_settings()
workspace_control = WorkspaceControl(
    repository=SqlAlchemyWorkspaceRepository(session_factory),
    notifications=MailpitEmailProvider(
        settings.smtp_host, settings.smtp_port, settings.email_sender
    ),
    rate_store=security_store,
    referral_base_url=settings.referral_base_url,
    token_pepper=settings.workspace_token_hmac_secret.encode(),
)


class CreateOrganizationRequest(BaseModel):
    name: str = Field(min_length=2, max_length=180)


class WorkspaceResponse(BaseModel):
    workspace_id: UUID
    name: str
    slug: str
    workspace_type: WorkspaceType
    roles: list[str]


class WorkspacesResponse(BaseModel):
    workspaces: list[WorkspaceResponse]


class CreateReferralRequest(BaseModel):
    email: EmailStr


class ReferralResponse(BaseModel):
    referral_id: UUID
    invitee_hint: str
    state: str
    created_at: datetime
    expires_at: datetime
    registered_at: datetime | None
    verified_at: datetime | None


class ReferralsResponse(BaseModel):
    referrals: list[ReferralResponse]


def problem(
    request: Request,
    error: SessionError | WorkspaceError,
    correlation_id: UUID,
) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        media_type="application/problem+json",
        content={
            "type": f"https://auth.vittavaan.com/problems/{error.code.value.lower()}",
            "title": "The workspace operation could not be completed",
            "status": error.status_code,
            "detail": error.message,
            "instance": request.url.path,
            "code": error.code.value,
            "request_id": str(correlation_id),
        },
    )


@router.get("/workspaces", response_model=WorkspacesResponse)
async def list_workspaces(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> WorkspacesResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        claims = await access_claims(authorization)
        workspaces = await workspace_control.list_workspaces(claims.user_id)
    except (SessionError, WorkspaceError) as error:
        return problem(request, error, correlation_id)
    return WorkspacesResponse(workspaces=[workspace_model(item) for item in workspaces])


@router.post("/organizations", response_model=WorkspaceResponse, status_code=201)
async def create_organization(
    payload: CreateOrganizationRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> WorkspaceResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        workspace = await workspace_control.create_organization(
            claims.user_id, payload.name, correlation_id
        )
    except (SessionError, WorkspaceError) as error:
        return problem(request, error, correlation_id)
    return workspace_model(workspace)


@router.post("/referrals", response_model=ReferralResponse, status_code=201)
async def create_referral(
    payload: CreateReferralRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> ReferralResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        referral = await workspace_control.invite_referral(
            claims.user_id, str(payload.email), correlation_id
        )
    except (SessionError, WorkspaceError) as error:
        return problem(request, error, correlation_id)
    return referral_model(referral)


@router.get("/referrals", response_model=ReferralsResponse)
async def list_referrals(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> ReferralsResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        claims = await access_claims(authorization)
        referrals = await workspace_control.list_referrals(claims.user_id)
    except (SessionError, WorkspaceError) as error:
        return problem(request, error, correlation_id)
    return ReferralsResponse(referrals=[referral_model(item) for item in referrals])


def workspace_model(value: WorkspaceSummary) -> WorkspaceResponse:
    return WorkspaceResponse(
        workspace_id=value.workspace_id,
        name=value.name,
        slug=value.slug,
        workspace_type=value.workspace_type,
        roles=list(value.roles),
    )


def referral_model(value: ReferralRecord) -> ReferralResponse:
    local, _, domain = value.invitee_email.partition("@")
    visible = local[:1] if local else "*"
    hint = f"{visible}***@{domain}" if domain else "hidden"
    return ReferralResponse(
        referral_id=value.referral_id,
        invitee_hint=hint,
        state=value.state,
        created_at=value.created_at,
        expires_at=value.expires_at,
        registered_at=value.registered_at,
        verified_at=value.verified_at,
    )
