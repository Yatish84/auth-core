from typing import Any, Protocol
from uuid import UUID

from auth_core.entity.mfa import MFAFactor, MFAUserProfile, StoredPasskey


class MFARepository(Protocol):
    async def user_profile(self, user_id: UUID) -> MFAUserProfile | None: ...

    async def password_hash(self, user_id: UUID) -> str | None: ...

    async def active_factors(self, user_id: UUID) -> tuple[MFAFactor, ...]: ...

    async def create_pending_totp(
        self, user_id: UUID, encrypted_secret: bytes, label: str
    ) -> MFAFactor: ...

    async def factor(self, user_id: UUID, mfa_id: UUID) -> MFAFactor | None: ...

    async def activate_totp(self, user_id: UUID, mfa_id: UUID, accepted_step: int) -> bool: ...

    async def advance_totp_step(
        self, mfa_id: UUID, previous_step: int | None, accepted_step: int
    ) -> bool: ...

    async def store_backup_codes(self, user_id: UUID, hashes: tuple[str, ...]) -> None: ...

    async def consume_backup_code(self, user_id: UUID, candidate_hash: str) -> bool: ...

    async def passkeys(self, user_id: UUID) -> tuple[StoredPasskey, ...]: ...

    async def passkey(self, credential_id: bytes) -> StoredPasskey | None: ...

    async def create_passkey(
        self,
        user_id: UUID,
        label: str,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: tuple[str, ...],
        backup_eligible: bool,
        backup_state: bool,
    ) -> None: ...

    async def update_passkey_counter(
        self,
        credential_id: bytes,
        previous_count: int,
        new_count: int,
        backup_state: bool,
    ) -> bool: ...

    async def revoke_factor(self, user_id: UUID, mfa_id: UUID) -> bool: ...

    async def link_oidc_identity(self, user_id: UUID, provider: str, subject: str) -> bool: ...

    async def audit(
        self,
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        user_id: UUID | None,
        metadata: dict[str, str],
    ) -> None: ...


class SecretCipher(Protocol):
    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes: ...

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes: ...


class TOTPProvider(Protocol):
    def generate_secret(self) -> str: ...

    def provisioning_uri(self, secret: str, account_name: str) -> str: ...

    def verify(self, secret: str, code: str, last_step: int | None) -> int | None: ...


class MFANotificationProvider(Protocol):
    async def send_email_code(self, email: str, code: str) -> None: ...

    async def send_sms_code(self, phone_e164: str, code: str) -> None: ...


class WebAuthnProvider(Protocol):
    def registration_options(
        self,
        user_id: UUID,
        user_name: str,
        existing_credentials: tuple[bytes, ...],
    ) -> tuple[dict[str, Any], bytes]: ...

    def verify_registration(
        self, credential: dict[str, Any], expected_challenge: bytes
    ) -> tuple[bytes, bytes, int, tuple[str, ...], bool, bool]: ...

    def authentication_options(
        self, credentials: tuple[StoredPasskey, ...]
    ) -> tuple[dict[str, Any], bytes]: ...

    def credential_id(self, credential: dict[str, Any]) -> bytes: ...

    def verify_authentication(
        self,
        credential: dict[str, Any],
        expected_challenge: bytes,
        stored: StoredPasskey,
    ) -> tuple[int, bool]: ...
