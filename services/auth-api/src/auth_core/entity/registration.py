from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class RegistrationErrorCode(StrEnum):
    CAPTCHA_INVALID = "AUTH_CAPTCHA_INVALID"
    PASSWORD_BREACHED = "AUTH_PASSWORD_BREACHED"
    PASSWORD_POLICY = "AUTH_PASSWORD_POLICY"
    VERIFICATION_INVALID = "AUTH_VERIFICATION_INVALID"
    OTP_INVALID = "AUTH_OTP_INVALID"
    RATE_LIMITED = "AUTH_RATE_LIMITED"
    PROVIDER_UNAVAILABLE = "AUTH_PROVIDER_UNAVAILABLE"


class RegistrationError(Exception):
    def __init__(self, code: RegistrationErrorCode, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class DuplicateContactError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class PendingContact:
    user_id: UUID
    state: str


@dataclass(frozen=True, slots=True)
class EmailVerification:
    user_id: UUID
    email: str
    token: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RegistrationAccepted:
    status: str = "accepted"
