from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID


class PrivacyErrorCode(StrEnum):
    RECENT_MFA_REQUIRED = "AUTH_RECENT_MFA_REQUIRED"
    AUDIT_FORBIDDEN = "AUTH_AUDIT_FORBIDDEN"
    AUDIT_CURSOR_INVALID = "AUTH_AUDIT_CURSOR_INVALID"


class PrivacyError(Exception):
    def __init__(self, code: PrivacyErrorCode, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class AuditSearchFilter:
    subject_user_id: UUID | None = None
    event_type: str | None = None
    outcome: str | None = None
    occurred_from: datetime | None = None
    occurred_to: datetime | None = None


@dataclass(frozen=True, slots=True)
class AuditRecord:
    audit_id: UUID
    actor_user_id: UUID | None
    subject_user_id: UUID | None
    org_id: UUID | None
    event_type: str
    outcome: str
    correlation_id: UUID
    metadata: dict[str, Any]
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class AuditPage:
    items: tuple[AuditRecord, ...]
    next_cursor: str | None
