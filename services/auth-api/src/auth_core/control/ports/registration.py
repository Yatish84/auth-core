from datetime import datetime
from typing import Protocol
from uuid import UUID

from auth_core.entity.registration import PendingContact


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...


class BreachPasswordProvider(Protocol):
    async def breach_count(self, password: str) -> int: ...


class CaptchaProvider(Protocol):
    async def verify(self, token: str, remote_ip: str | None, action: str) -> bool: ...


class EmailProvider(Protocol):
    async def send_verification(self, email: str, verification_url: str) -> None: ...


class SMSProvider(Protocol):
    async def send_verification(self, phone_e164: str, code: str) -> None: ...


class RegistrationRepository(Protocol):
    async def get_by_email(self, email: str) -> PendingContact | None: ...

    async def get_by_phone(self, phone_e164: str) -> PendingContact | None: ...

    async def create_email_registration(
        self,
        email: str,
        given_name: str,
        family_name: str,
        password_hash: str,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
        referral_token_hash: str | None,
    ) -> UUID: ...

    async def issue_email_verification(
        self,
        user_id: UUID,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> None: ...

    async def verify_email(self, token_hash: str, now: datetime, correlation_id: UUID) -> bool: ...

    async def create_phone_registration(
        self,
        phone_e164: str,
        given_name: str | None,
        family_name: str | None,
        correlation_id: UUID,
    ) -> UUID: ...

    async def verify_phone(self, user_id: UUID, correlation_id: UUID) -> bool: ...
