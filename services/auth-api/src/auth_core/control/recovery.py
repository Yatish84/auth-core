import asyncio
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

from auth_core.control.ports.recovery import (
    BreachPasswordProvider,
    GlobalSessionRevoker,
    PasswordHasher,
    RecoveryNotificationProvider,
    RecoveryRateStore,
    RecoveryRepository,
)
from auth_core.entity.password_policy import enforce_password_policy
from auth_core.entity.recovery import (
    ContactChangeRecord,
    ContactProof,
    ContactType,
    GovernedResetRecord,
    PasswordResetOutcome,
    RecoveryError,
    RecoveryErrorCode,
    StaffRole,
)
from auth_core.entity.registration import RegistrationError
from auth_core.entity.session import AccessClaims
from auth_core.entity.user import normalize_email

RESET_TTL = timedelta(minutes=15)
CONTACT_CHANGE_TTL = timedelta(minutes=10)
GOVERNED_DELAY = timedelta(hours=12)
PASSWORD_RESET_LIMIT = 3
PASSWORD_RESET_WINDOW_SECONDS = 3600
CONTACT_CODE_PATTERN = re.compile(r"^\d{6}$")
PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")
STRONG_METHODS = {"totp", "passkey", "email", "sms", "backup_code", "backup_codes"}


class RecoveryControl:
    def __init__(
        self,
        repository: RecoveryRepository,
        password_hasher: PasswordHasher,
        breach_provider: BreachPasswordProvider,
        notifications: RecoveryNotificationProvider,
        rate_store: RecoveryRateStore,
        session_revoker: GlobalSessionRevoker,
        reset_base_url: str,
        token_pepper: bytes,
        otp_pepper: bytes,
    ) -> None:
        self._repository = repository
        self._password_hasher = password_hasher
        self._breach_provider = breach_provider
        self._notifications = notifications
        self._rate_store = rate_store
        self._session_revoker = session_revoker
        self._reset_base_url = reset_base_url.rstrip("/")
        self._token_pepper = token_pepper
        self._otp_pepper = otp_pepper

    async def request_password_reset(self, email: str, correlation_id: UUID) -> None:
        normalized = normalize_email(email)
        count = await self._rate_store.increment_rate_limit(
            "password_reset", normalized, PASSWORD_RESET_WINDOW_SECONDS
        )
        if count > PASSWORD_RESET_LIMIT:
            raise RecoveryError(
                RecoveryErrorCode.RATE_LIMITED,
                "Too many requests. Please wait and try again.",
                429,
            )
        user = await self._repository.eligible_user_by_email(normalized)
        if user is None or user.email is None:
            return
        token = secrets.token_urlsafe(32)
        await self._repository.issue_password_reset(
            user.user_id,
            self._token_hash(token),
            "password_reset",
            datetime.now(UTC) + RESET_TTL,
            correlation_id,
        )
        try:
            await self._notifications.send_password_reset(
                user.email, f"{self._reset_base_url}?token={token}"
            )
        except Exception:
            return

    async def reset_password(
        self, token: str, password: str, correlation_id: UUID
    ) -> None:
        try:
            enforce_password_policy(password)
        except RegistrationError as error:
            raise RecoveryError(
                RecoveryErrorCode.PASSWORD_POLICY, error.message, error.status_code
            ) from error
        try:
            if await self._breach_provider.breach_count(password) > 0:
                raise RecoveryError(
                    RecoveryErrorCode.PASSWORD_BREACHED,
                    "Choose a password that has not appeared in a known public breach.",
                    400,
                )
        except RecoveryError:
            raise
        except Exception as error:
            raise RecoveryError(
                RecoveryErrorCode.PROVIDER_UNAVAILABLE,
                "A required security service is temporarily unavailable. Please try again.",
                503,
            ) from error
        password_hash = await asyncio.to_thread(self._password_hasher.hash, password)
        outcome, user = await self._repository.consume_password_reset(
            self._token_hash(token),
            password,
            password_hash,
            datetime.now(UTC),
            correlation_id,
        )
        if outcome is PasswordResetOutcome.REUSED:
            raise RecoveryError(
                RecoveryErrorCode.PASSWORD_REUSED,
                "Choose a password you have not used recently.",
                400,
            )
        if outcome is not PasswordResetOutcome.UPDATED or user is None:
            raise RecoveryError(
                RecoveryErrorCode.TOKEN_INVALID,
                "This recovery link is invalid, expired, or has already been used.",
                400,
            )
        await self._session_revoker.revoke_user_access(user.user_id, "password_reset")
        if user.email:
            await self._notifications.send_password_changed(user.email)

    async def start_contact_change(
        self,
        claims: AccessClaims,
        contact_type: ContactType,
        new_value: str,
        correlation_id: UUID,
    ) -> ContactChangeRecord:
        self.require_recent_mfa(claims)
        normalized = self._normalize_contact(contact_type, new_value)
        old_code = f"{secrets.randbelow(1_000_000):06d}"
        new_code = f"{secrets.randbelow(1_000_000):06d}"
        record = await self._repository.create_contact_change(
            claims.user_id,
            contact_type,
            normalized,
            self._otp_hash(old_code),
            self._otp_hash(new_code),
            datetime.now(UTC) + CONTACT_CHANGE_TTL,
            correlation_id,
        )
        if record is None:
            raise self._contact_invalid()
        await self._notifications.send_contact_code(record.old_value, old_code, ContactProof.OLD)
        await self._notifications.send_contact_code(record.new_value, new_code, ContactProof.NEW)
        return record

    async def verify_contact_change(
        self,
        claims: AccessClaims,
        request_id: UUID,
        proof: ContactProof,
        code: str,
        correlation_id: UUID,
    ) -> ContactChangeRecord:
        self.require_recent_mfa(claims)
        if not CONTACT_CODE_PATTERN.fullmatch(code):
            raise self._contact_invalid()
        record = await self._repository.verify_contact_change(
            claims.user_id,
            request_id,
            proof,
            self._otp_hash(code),
            datetime.now(UTC),
            correlation_id,
        )
        if record is None:
            raise self._contact_invalid()
        if record.applied_at is not None:
            await self._session_revoker.revoke_user_access(claims.user_id, "contact_change")
            await self._notifications.send_contact_changed(record.old_value)
            await self._notifications.send_contact_changed(record.new_value)
        return record

    @staticmethod
    def require_recent_mfa(claims: AccessClaims) -> None:
        if not STRONG_METHODS.intersection(claims.assurance):
            raise RecoveryError(
                RecoveryErrorCode.RECENT_MFA_REQUIRED,
                "Complete a recent extra security check before continuing.",
                403,
            )

    def _token_hash(self, token: str) -> str:
        return hmac.new(self._token_pepper, token.encode(), sha256).hexdigest()

    def _otp_hash(self, code: str) -> str:
        return hmac.new(self._otp_pepper, code.encode(), sha256).hexdigest()

    @staticmethod
    def _normalize_contact(contact_type: ContactType, value: str) -> str:
        if contact_type is ContactType.EMAIL:
            return normalize_email(value)
        normalized = re.sub(r"[\s()-]", "", value)
        if not PHONE_PATTERN.fullmatch(normalized):
            raise RecoveryControl._contact_invalid()
        return normalized

    @staticmethod
    def _contact_invalid() -> RecoveryError:
        return RecoveryError(
            RecoveryErrorCode.CONTACT_INVALID,
            "The contact-change request or verification code is invalid or expired.",
            400,
        )


class SupportAdminControl:
    def __init__(
        self,
        repository: RecoveryRepository,
        notifications: RecoveryNotificationProvider,
        session_revoker: GlobalSessionRevoker,
        reset_base_url: str,
        token_pepper: bytes,
    ) -> None:
        self._repository = repository
        self._notifications = notifications
        self._session_revoker = session_revoker
        self._reset_base_url = reset_base_url.rstrip("/")
        self._token_pepper = token_pepper

    async def unlock(
        self,
        claims: AccessClaims,
        target_user_id: UUID,
        ticket_reference: str,
        correlation_id: UUID,
    ) -> None:
        await self._authorize(claims, StaffRole.SUPPORT_AGENT_L2)
        user = await self._repository.unlock_user(
            claims.user_id, target_user_id, ticket_reference, correlation_id
        )
        if user is None:
            raise self._target_missing()

    async def suspend(
        self,
        claims: AccessClaims,
        target_user_id: UUID,
        ticket_reference: str,
        reason: str,
        correlation_id: UUID,
    ) -> None:
        await self._authorize(claims, StaffRole.ACCOUNT_ADMIN)
        user = await self._repository.suspend_user(
            claims.user_id, target_user_id, ticket_reference, reason, correlation_id
        )
        if user is None:
            raise self._target_missing()
        await self._session_revoker.revoke_user_access(target_user_id, "account_suspended")

    async def support_recovery(
        self,
        claims: AccessClaims,
        target_user_id: UUID,
        ticket_reference: str,
        evidence_reference: str,
        correlation_id: UUID,
    ) -> None:
        await self._authorize(claims, StaffRole.SUPPORT_AGENT_L2)
        user = await self._repository.unlock_user(
            claims.user_id, target_user_id, ticket_reference, correlation_id
        )
        if user is None or user.email is None:
            raise self._target_missing()
        token = secrets.token_urlsafe(32)
        await self._repository.issue_password_reset(
            target_user_id,
            self._token_hash(token),
            "support_recovery",
            datetime.now(UTC) + RESET_TTL,
            correlation_id,
            claims.user_id,
            f"{ticket_reference}:{evidence_reference}",
        )
        await self._notifications.send_support_recovery(
            user.email, f"{self._reset_base_url}?token={token}"
        )

    async def initiate_mfa_reset(
        self,
        claims: AccessClaims,
        target_user_id: UUID,
        ticket_reference: str,
        correlation_id: UUID,
    ) -> GovernedResetRecord:
        await self._authorize(claims, StaffRole.SUPPORT_AGENT_L2)
        result = await self._repository.initiate_mfa_reset(
            claims.user_id,
            target_user_id,
            ticket_reference,
            datetime.now(UTC) + GOVERNED_DELAY,
            correlation_id,
        )
        if result is None:
            raise self._target_missing()
        record, user = result
        destination = user.email or user.phone_e164
        if destination:
            await self._notifications.send_mfa_reset_requested(
                destination, record.execute_after
            )
        return record

    async def approve_mfa_reset(
        self, claims: AccessClaims, request_id: UUID, correlation_id: UUID
    ) -> GovernedResetRecord:
        await self._authorize(claims, StaffRole.SECURITY_SUPERVISOR_L3)
        record = await self._repository.approve_mfa_reset(
            claims.user_id, request_id, datetime.now(UTC), correlation_id
        )
        if record is None:
            raise self._governed_invalid()
        return record

    async def execute_mfa_reset(
        self, claims: AccessClaims, request_id: UUID, correlation_id: UUID
    ) -> GovernedResetRecord:
        await self._authorize(claims, StaffRole.SECURITY_SUPERVISOR_L3)
        result = await self._repository.execute_mfa_reset(
            claims.user_id, request_id, datetime.now(UTC), correlation_id
        )
        if result is None:
            raise self._governed_invalid()
        record, user = result
        await self._session_revoker.revoke_user_access(user.user_id, "governed_mfa_reset")
        destination = user.email or user.phone_e164
        if destination:
            await self._notifications.send_mfa_reset_completed(destination)
        return record

    async def get_mfa_reset(
        self, claims: AccessClaims, request_id: UUID
    ) -> GovernedResetRecord:
        RecoveryControl.require_recent_mfa(claims)
        allowed = await self._repository.staff_has_role(
            claims.user_id, StaffRole.SUPPORT_AGENT_L2
        ) or await self._repository.staff_has_role(
            claims.user_id, StaffRole.SECURITY_SUPERVISOR_L3
        )
        if not allowed:
            raise self._forbidden()
        record = await self._repository.get_mfa_reset(request_id)
        if record is None:
            raise self._governed_invalid()
        return record

    async def _authorize(self, claims: AccessClaims, role: StaffRole) -> None:
        RecoveryControl.require_recent_mfa(claims)
        if not await self._repository.staff_has_role(claims.user_id, role):
            raise self._forbidden()

    def _token_hash(self, token: str) -> str:
        return hmac.new(self._token_pepper, token.encode(), sha256).hexdigest()

    @staticmethod
    def _forbidden() -> RecoveryError:
        return RecoveryError(
            RecoveryErrorCode.STAFF_FORBIDDEN,
            "This staff action is not authorized.",
            403,
        )

    @staticmethod
    def _target_missing() -> RecoveryError:
        return RecoveryError(
            RecoveryErrorCode.TARGET_NOT_FOUND,
            "The target account is unavailable for this action.",
            404,
        )

    @staticmethod
    def _governed_invalid() -> RecoveryError:
        return RecoveryError(
            RecoveryErrorCode.GOVERNED_INVALID,
            "This governed request is unavailable in its current state.",
            409,
        )
