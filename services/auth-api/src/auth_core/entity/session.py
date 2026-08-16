from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class ClientType(StrEnum):
    WEB = "WEB"
    MOBILE = "MOBILE"


class SessionErrorCode(StrEnum):
    WORKFLOW_INVALID = "AUTH_SESSION_WORKFLOW_INVALID"
    TOKEN_INVALID = "AUTH_TOKEN_INVALID"
    TOKEN_REUSED = "AUTH_TOKEN_REUSED"
    SESSION_EXPIRED = "AUTH_SESSION_EXPIRED"
    SESSION_NOT_FOUND = "AUTH_SESSION_NOT_FOUND"
    CSRF_INVALID = "AUTH_CSRF_INVALID"
    CLIENT_MISMATCH = "AUTH_CLIENT_MISMATCH"


class RotationStatus(StrEnum):
    ROTATED = "rotated"
    INVALID = "invalid"
    REUSED = "reused"
    EXPIRED = "expired"
    CLIENT_MISMATCH = "client_mismatch"


class SessionError(Exception):
    def __init__(self, code: SessionErrorCode, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class AccessClaims:
    user_id: UUID
    session_id: UUID
    family_id: UUID
    jti: UUID
    issued_at: datetime
    expires_at: datetime
    client_type: ClientType
    assurance: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime
    session_id: UUID
    csrf_token: str | None = None


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_id: UUID
    family_id: UUID
    user_id: UUID
    access_jti: UUID
    client_type: ClientType
    device_fingerprint_hash: str
    ip_address: str | None
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class RefreshRecord:
    family_id: UUID
    session_id: UUID
    user_id: UUID
    access_jti: UUID
    client_type: ClientType
    device_fingerprint_hash: str
    generation: int
    token_used: bool
    token_revoked: bool
    family_revoked: bool
    token_expires_at: datetime
    family_expires_at: datetime
    session_expires_at: datetime
    last_activity_at: datetime


@dataclass(frozen=True, slots=True)
class SessionSummary:
    session_id: UUID
    client_type: ClientType
    device_hint: str
    ip_address: str | None
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime
    current: bool


@dataclass(frozen=True, slots=True)
class RevocationResult:
    user_id: UUID
    family_id: UUID
    access_jti: UUID


@dataclass(frozen=True, slots=True)
class CreatedSession:
    record: SessionRecord
    evicted: tuple[RevocationResult, ...]


@dataclass(frozen=True, slots=True)
class RotationResult:
    status: RotationStatus
    record: SessionRecord | None = None
    revoked: RevocationResult | None = None
