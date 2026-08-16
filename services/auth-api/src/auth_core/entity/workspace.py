from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class WorkspaceType(StrEnum):
    PERSONAL = "personal"
    ORGANIZATION = "organization"


class WorkspaceErrorCode(StrEnum):
    FORBIDDEN = "AUTH_WORKSPACE_FORBIDDEN"
    NOT_FOUND = "AUTH_WORKSPACE_NOT_FOUND"
    INVALID = "AUTH_WORKSPACE_INVALID"
    REFERRAL_INELIGIBLE = "AUTH_REFERRAL_INELIGIBLE"
    RATE_LIMITED = "AUTH_REFERRAL_RATE_LIMITED"
    PROVIDER_UNAVAILABLE = "AUTH_PROVIDER_UNAVAILABLE"
    INVITATION_INVALID = "AUTH_INVITATION_INVALID"
    MEMBER_NOT_FOUND = "AUTH_MEMBER_NOT_FOUND"
    LAST_OWNER = "AUTH_LAST_OWNER_REQUIRED"


class WorkspaceError(Exception):
    def __init__(self, code: WorkspaceErrorCode, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class LastOwnerError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class WorkspaceSummary:
    workspace_id: UUID
    name: str
    slug: str
    workspace_type: WorkspaceType
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReferralRecord:
    referral_id: UUID
    invitee_email: str
    state: str
    created_at: datetime
    expires_at: datetime
    registered_at: datetime | None
    verified_at: datetime | None


class ReferralEligibility(StrEnum):
    ELIGIBLE = "eligible"
    SELF = "self"
    EXISTING_USER = "existing_user"


class OrganizationRole(StrEnum):
    OWNER = "OWNER"
    MEMBER = "MEMBER"
    VIEWER = "VIEWER"


@dataclass(frozen=True, slots=True)
class InvitationRecord:
    invitation_id: UUID
    workspace_id: UUID
    invitee_email: str
    role: OrganizationRole
    state: str
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class MemberSummary:
    user_id: UUID
    email: str | None
    given_name: str | None
    family_name: str | None
    roles: tuple[OrganizationRole, ...]


@dataclass(frozen=True, slots=True)
class OffboardResult:
    user_id: UUID
    revoked_access_jtis: tuple[UUID, ...]
