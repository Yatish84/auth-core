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


class WorkspaceError(Exception):
    def __init__(self, code: WorkspaceErrorCode, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


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
