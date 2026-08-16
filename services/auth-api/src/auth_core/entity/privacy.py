from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID


class PrivacyErrorCode(StrEnum):
    RECENT_MFA_REQUIRED = "AUTH_RECENT_MFA_REQUIRED"
    AUDIT_FORBIDDEN = "AUTH_AUDIT_FORBIDDEN"
    AUDIT_CURSOR_INVALID = "AUTH_AUDIT_CURSOR_INVALID"
    REQUEST_NOT_FOUND = "AUTH_PRIVACY_REQUEST_NOT_FOUND"
    EXPORT_UNAVAILABLE = "AUTH_PRIVACY_EXPORT_UNAVAILABLE"
    EXPORT_INTEGRITY_FAILED = "AUTH_PRIVACY_EXPORT_INTEGRITY_FAILED"


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


@dataclass(frozen=True, slots=True)
class PrivacyRequestRecord:
    request_id: UUID
    user_id: UUID
    request_type: str
    state: str
    requested_at: datetime
    completed_at: datetime | None
    artifact_expires_at: datetime | None
    failure_code: str | None


@dataclass(frozen=True, slots=True)
class EncryptedExportArtifact:
    request_id: UUID
    encrypted_content: bytes
    content_digest: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ExportDownload:
    request_id: UUID
    content: bytes
    expires_at: datetime
