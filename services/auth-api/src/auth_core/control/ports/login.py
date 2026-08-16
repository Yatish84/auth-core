from typing import Protocol
from uuid import UUID

from auth_core.entity.login import DeviceSignals, LoginIdentity, OIDCProfile


class LoginRepository(Protocol):
    async def password_identity(self, email: str) -> LoginIdentity | None: ...

    async def phone_identity(self, phone_e164: str) -> LoginIdentity | None: ...

    async def oidc_identity(self, provider: str, subject: str) -> LoginIdentity | None: ...

    async def active_user_by_email(self, email: str) -> LoginIdentity | None: ...

    async def provision_oidc(self, profile: OIDCProfile, correlation_id: UUID) -> LoginIdentity: ...

    async def device_signals(
        self, user_id: UUID, fingerprint_hash: str, ip_address: str | None
    ) -> DeviceSignals: ...

    async def fallback_methods(self, user_id: UUID) -> tuple[str, ...]: ...

    async def update_password_hash(self, user_id: UUID, password_hash: str) -> None: ...

    async def audit(
        self,
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        subject_user_id: UUID | None,
        metadata: dict[str, str],
    ) -> None: ...


class LoginPasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...

    def verify(self, password_hash: str, password: str) -> bool: ...

    def needs_rehash(self, password_hash: str) -> bool: ...


class LoginCaptchaProvider(Protocol):
    async def verify(self, token: str, remote_ip: str | None, action: str) -> bool: ...


class LoginSMSProvider(Protocol):
    async def send_verification(self, phone_e164: str, code: str) -> None: ...


class OIDCProvider(Protocol):
    def authorization_url(
        self, provider: str, state: str, nonce: str, code_challenge: str
    ) -> str: ...

    async def verify_callback(
        self, provider: str, code: str, nonce: str, code_verifier: str
    ) -> OIDCProfile: ...
