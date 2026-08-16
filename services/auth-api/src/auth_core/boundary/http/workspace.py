from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Header, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field

from auth_core.boundary.http.registration import request_id
from auth_core.boundary.http.session import access_claims, session_control
from auth_core.config import get_settings
from auth_core.control.workspace import WorkspaceControl
from auth_core.entity.session import SessionError
from auth_core.entity.workspace import (
    InvitationRecord,
    MemberSummary,
    OrganizationRole,
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
    token_issuer=session_control,
    invitation_base_url=settings.organization_invitation_base_url,
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


class OrganizationInvitationRequest(BaseModel):
    email: EmailStr
    role: OrganizationRole


class OrganizationInvitationAcceptRequest(BaseModel):
    invitation_token: str = Field(min_length=20, max_length=512)


class InvitationResponse(BaseModel):
    invitation_id: UUID
    workspace_id: UUID
    invitee_hint: str
    role: OrganizationRole
    state: str
    created_at: datetime
    expires_at: datetime


class MemberRoleRequest(BaseModel):
    role: OrganizationRole


class MemberResponse(BaseModel):
    user_id: UUID
    email_hint: str | None
    display_name: str
    roles: list[OrganizationRole]


class MembersResponse(BaseModel):
    members: list[MemberResponse]


class WorkspaceSwitchRequest(BaseModel):
    workspace_id: UUID


class WorkspaceTokenResponse(BaseModel):
    token_type: str = "Bearer"
    access_token: str
    access_expires_at: datetime
    workspace: WorkspaceResponse


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


@router.post(
    "/organizations/{workspace_id}/invitations",
    response_model=InvitationResponse,
    status_code=201,
)
async def invite_organization_member(
    workspace_id: UUID,
    payload: OrganizationInvitationRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> InvitationResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        invitation = await workspace_control.invite_organization_member(
            claims.user_id,
            workspace_id,
            str(payload.email),
            payload.role,
            correlation_id,
        )
    except (SessionError, WorkspaceError) as error:
        return problem(request, error, correlation_id)
    return invitation_model(invitation)


@router.post(
    "/organizations/invitations/accept",
    response_model=WorkspaceResponse,
)
async def accept_organization_invitation(
    payload: OrganizationInvitationAcceptRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> WorkspaceResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        workspace = await workspace_control.accept_organization_invitation(
            claims.user_id, payload.invitation_token, correlation_id
        )
    except (SessionError, WorkspaceError) as error:
        return problem(request, error, correlation_id)
    return workspace_model(workspace)


@router.get(
    "/organizations/{workspace_id}/members",
    response_model=MembersResponse,
)
async def list_organization_members(
    workspace_id: UUID,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> MembersResponse | JSONResponse:
    correlation_id = request_id(None)
    try:
        claims = await access_claims(authorization)
        members = await workspace_control.list_members(claims.user_id, workspace_id)
    except (SessionError, WorkspaceError) as error:
        return problem(request, error, correlation_id)
    return MembersResponse(members=[member_model(item) for item in members])


@router.put(
    "/organizations/{workspace_id}/members/{member_user_id}/roles",
    response_model=MemberResponse,
)
async def replace_organization_member_role(
    workspace_id: UUID,
    member_user_id: UUID,
    payload: MemberRoleRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> MemberResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        member = await workspace_control.replace_member_role(
            claims.user_id,
            workspace_id,
            member_user_id,
            payload.role,
            correlation_id,
        )
    except (SessionError, WorkspaceError) as error:
        return problem(request, error, correlation_id)
    return member_model(member)


@router.delete(
    "/organizations/{workspace_id}/members/{member_user_id}",
    status_code=204,
    response_class=Response,
    response_model=None,
)
async def offboard_organization_member(
    workspace_id: UUID,
    member_user_id: UUID,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> Response | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        await workspace_control.offboard_member(
            claims.user_id, workspace_id, member_user_id, correlation_id
        )
    except (SessionError, WorkspaceError) as error:
        return problem(request, error, correlation_id)
    return Response(status_code=204)


@router.post("/auth/workspace/switch", response_model=WorkspaceTokenResponse)
@router.post("/auth/org/switch", response_model=WorkspaceTokenResponse, include_in_schema=False)
async def switch_workspace(
    payload: WorkspaceSwitchRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> WorkspaceTokenResponse | JSONResponse:
    correlation_id = request_id(x_request_id)
    try:
        claims = await access_claims(authorization)
        token, expires_at, workspace = await workspace_control.switch_workspace(
            claims, payload.workspace_id, correlation_id
        )
    except (SessionError, WorkspaceError) as error:
        return problem(request, error, correlation_id)
    return WorkspaceTokenResponse(
        access_token=token,
        access_expires_at=expires_at,
        workspace=workspace_model(workspace),
    )


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


def invitation_model(value: InvitationRecord) -> InvitationResponse:
    return InvitationResponse(
        invitation_id=value.invitation_id,
        workspace_id=value.workspace_id,
        invitee_hint=mask_email(value.invitee_email) or "hidden",
        role=value.role,
        state=value.state,
        created_at=value.created_at,
        expires_at=value.expires_at,
    )


def member_model(value: MemberSummary) -> MemberResponse:
    display_name = " ".join(
        part for part in (value.given_name, value.family_name) if part
    ).strip()
    return MemberResponse(
        user_id=value.user_id,
        email_hint=mask_email(value.email),
        display_name=display_name or "Member",
        roles=list(value.roles),
    )


def mask_email(value: str | None) -> str | None:
    if not value:
        return None
    local, _, domain = value.partition("@")
    visible = local[:1] if local else "*"
    return f"{visible}***@{domain}" if domain else "hidden"
