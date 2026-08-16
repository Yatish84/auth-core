from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID


class MFAMethod(StrEnum):
    TOTP = "totp"
    EMAIL_OTP = "email_otp"
    SMS_OTP = "sms_otp"
    PASSKEY = "passkey"
    BACKUP_CODE = "backup_code"


class MFACompletionType(StrEnum):
    SESSION_READY = "session_ready"
    IDENTITY_LINKED = "identity_linked"


class MFAErrorCode(StrEnum):
    WORKFLOW_INVALID = "AUTH_MFA_WORKFLOW_INVALID"
    METHOD_UNAVAILABLE = "AUTH_MFA_METHOD_UNAVAILABLE"
    CHALLENGE_INVALID = "AUTH_MFA_CHALLENGE_INVALID"
    CODE_INVALID = "AUTH_MFA_CODE_INVALID"
    FACTOR_LOCKED = "AUTH_MFA_FACTOR_LOCKED"
    ENROLLMENT_INVALID = "AUTH_MFA_ENROLLMENT_INVALID"
    PASSKEY_INVALID = "AUTH_PASSKEY_INVALID"
    LAST_FACTOR = "AUTH_MFA_LAST_FACTOR"
    PROVIDER_UNAVAILABLE = "AUTH_MFA_PROVIDER_UNAVAILABLE"


class MFAError(Exception):
    def __init__(self, code: MFAErrorCode, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class MFAUserProfile:
    user_id: UUID
    state: str
    email: str | None
    phone_e164: str | None


@dataclass(frozen=True, slots=True)
class MFAFactor:
    mfa_id: UUID
    user_id: UUID
    factor_type: str
    status: str
    label: str | None
    encrypted_secret: bytes | None = None
    last_totp_step: int | None = None


@dataclass(frozen=True, slots=True)
class MFAFactorSummary:
    mfa_id: UUID
    factor_type: str
    label: str | None


@dataclass(frozen=True, slots=True)
class StoredPasskey:
    credential_id: bytes
    mfa_id: UUID
    user_id: UUID
    public_key: bytes
    sign_count: int
    transports: tuple[str, ...]
    backup_eligible: bool
    backup_state: bool


@dataclass(frozen=True, slots=True)
class MFAChallenge:
    challenge_token: str
    method: MFAMethod
    destination_hint: str | None = None


@dataclass(frozen=True, slots=True)
class TOTPEnrollment:
    enrollment_token: str
    provisioning_uri: str
    manual_secret: str


@dataclass(frozen=True, slots=True)
class MFACompletion:
    result: MFACompletionType
    workflow_token: str | None
    backup_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PasskeyOptions:
    challenge_token: str
    public_key: dict[str, Any]
