from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class RecoveryErrorCode(StrEnum):
    TOKEN_INVALID = "AUTH_RECOVERY_TOKEN_INVALID"
    PASSWORD_REUSED = "AUTH_PASSWORD_REUSED"
    PASSWORD_POLICY = "AUTH_PASSWORD_POLICY"
    PASSWORD_BREACHED = "AUTH_PASSWORD_BREACHED"
    RATE_LIMITED = "AUTH_RECOVERY_RATE_LIMITED"
    PROVIDER_UNAVAILABLE = "AUTH_PROVIDER_UNAVAILABLE"
    CONTACT_INVALID = "AUTH_CONTACT_CHANGE_INVALID"
    CONTACT_CONFLICT = "AUTH_CONTACT_CONFLICT"
    RECENT_MFA_REQUIRED = "AUTH_RECENT_MFA_REQUIRED"
    STAFF_FORBIDDEN = "AUTH_STAFF_FORBIDDEN"
    TARGET_NOT_FOUND = "AUTH_TARGET_NOT_FOUND"
    GOVERNED_INVALID = "AUTH_GOVERNED_REQUEST_INVALID"
    FOUR_EYES_REQUIRED = "AUTH_FOUR_EYES_REQUIRED"
    GOVERNED_TOO_EARLY = "AUTH_GOVERNED_TOO_EARLY"
    TARGET_CHANGED = "AUTH_GOVERNED_TARGET_CHANGED"


class RecoveryError(Exception):
    def __init__(self, code: RecoveryErrorCode, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class PasswordResetOutcome(StrEnum):
    UPDATED = "updated"
    INVALID = "invalid"
    REUSED = "reused"


class ContactType(StrEnum):
    EMAIL = "email"
    PHONE = "phone"


class ContactProof(StrEnum):
    OLD = "old"
    NEW = "new"


class StaffRole(StrEnum):
    SUPPORT_AGENT_L2 = "SUPPORT_AGENT_L2"
    SECURITY_SUPERVISOR_L3 = "SECURITY_SUPERVISOR_L3"
    ACCOUNT_ADMIN = "ACCOUNT_ADMIN"


@dataclass(frozen=True, slots=True)
class RecoveryUser:
    user_id: UUID
    email: str | None
    phone_e164: str | None
    state: str
    version: int


@dataclass(frozen=True, slots=True)
class ContactChangeRecord:
    request_id: UUID
    user_id: UUID
    contact_type: ContactType
    old_value: str
    new_value: str
    expires_at: datetime
    old_verified_at: datetime | None = None
    new_verified_at: datetime | None = None
    applied_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class GovernedResetRecord:
    request_id: UUID
    target_user_id: UUID
    initiator_user_id: UUID
    approver_user_id: UUID | None
    state: str
    initiated_at: datetime
    execute_after: datetime
    approved_at: datetime | None
    executed_at: datetime | None
    ticket_reference: str | None
