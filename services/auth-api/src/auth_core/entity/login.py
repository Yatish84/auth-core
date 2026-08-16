from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class LoginDecisionType(StrEnum):
    SESSION_READY = "session_ready"
    MFA_REQUIRED = "mfa_required"
    COLLISION_PROOF_REQUIRED = "collision_proof_required"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class LoginErrorCode(StrEnum):
    INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
    TEMPORARILY_LOCKED = "AUTH_TEMPORARILY_LOCKED"
    OTP_INVALID = "AUTH_OTP_INVALID"
    CAPTCHA_INVALID = "AUTH_CAPTCHA_INVALID"
    WORKFLOW_INVALID = "AUTH_WORKFLOW_INVALID"
    OIDC_INVALID = "AUTH_OIDC_INVALID"
    PROVIDER_UNAVAILABLE = "AUTH_PROVIDER_UNAVAILABLE"


class LoginError(Exception):
    def __init__(self, code: LoginErrorCode, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class LoginIdentity:
    user_id: UUID
    state: str
    password_hash: str | None
    verified: bool
    has_phone: bool


@dataclass(frozen=True, slots=True)
class DeviceSignals:
    known: bool
    trusted: bool
    ip_changed: bool


@dataclass(frozen=True, slots=True)
class LoginDecision:
    decision: LoginDecisionType
    risk: RiskLevel
    workflow_token: str
    allowed_methods: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OIDCProfile:
    provider: str
    subject: str
    email: str
    email_verified: bool
    given_name: str | None = None
    family_name: str | None = None
