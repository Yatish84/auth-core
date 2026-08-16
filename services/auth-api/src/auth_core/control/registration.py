import asyncio
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID, uuid4

from auth_core.control.ports.registration import (
    BreachPasswordProvider,
    CaptchaProvider,
    EmailProvider,
    PasswordHasher,
    RegistrationRepository,
    SMSProvider,
)
from auth_core.entity.password_policy import enforce_password_policy
from auth_core.entity.registration import (
    DuplicateContactError,
    RegistrationAccepted,
    RegistrationError,
    RegistrationErrorCode,
)
from auth_core.entity.user import normalize_email
from auth_core.infrastructure.redis_security import RedisSecurityStore

EMAIL_TOKEN_LIFETIME = timedelta(minutes=15)
PHONE_RATE_WINDOW_SECONDS = 60
PHONE_RATE_LIMIT = 3
EMAIL_RATE_WINDOW_SECONDS = 60
EMAIL_RATE_LIMIT = 5
OTP_MAX_ATTEMPTS = 3
PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")


class RegistrationControl:
    def __init__(
        self,
        repository: RegistrationRepository,
        password_hasher: PasswordHasher,
        breach_provider: BreachPasswordProvider,
        captcha_provider: CaptchaProvider,
        email_provider: EmailProvider,
        sms_provider: SMSProvider,
        redis_store: RedisSecurityStore,
        verification_base_url: str,
        otp_pepper: bytes,
    ) -> None:
        self._repository = repository
        self._password_hasher = password_hasher
        self._breach_provider = breach_provider
        self._captcha_provider = captcha_provider
        self._email_provider = email_provider
        self._sms_provider = sms_provider
        self._redis_store = redis_store
        self._verification_base_url = verification_base_url.rstrip("/")
        self._otp_pepper = otp_pepper

    async def register_email(
        self,
        email: str,
        password: str,
        given_name: str,
        family_name: str,
        captcha_token: str,
        remote_ip: str | None,
        correlation_id: UUID | None = None,
    ) -> RegistrationAccepted:
        normalized_email = normalize_email(email)
        await self._verify_captcha(captcha_token, remote_ip, "signup_email")
        await self._limit("signup_email", normalized_email, EMAIL_RATE_LIMIT, 60)
        enforce_password_policy(password)
        try:
            if await self._breach_provider.breach_count(password) > 0:
                raise RegistrationError(
                    RegistrationErrorCode.PASSWORD_BREACHED,
                    "Choose a password that has not appeared in a known public breach.",
                    400,
                )
        except RegistrationError:
            raise
        except Exception as error:
            raise self._provider_unavailable() from error

        existing = await self._repository.get_by_email(normalized_email)
        if existing is not None:
            if existing.state == "pending":
                await self._send_email_token(existing.user_id, normalized_email, correlation_id)
            return RegistrationAccepted()

        raw_token, token_hash, expires_at = self._new_email_token()
        password_hash = await asyncio.to_thread(self._password_hasher.hash, password)
        event_id = correlation_id or uuid4()
        try:
            await self._repository.create_email_registration(
                normalized_email,
                given_name,
                family_name,
                password_hash,
                token_hash,
                expires_at,
                event_id,
            )
        except DuplicateContactError:
            return RegistrationAccepted()
        await self._send_email(normalized_email, raw_token)
        return RegistrationAccepted()

    async def request_email_verification(
        self,
        email: str,
        captcha_token: str,
        remote_ip: str | None,
        correlation_id: UUID | None = None,
    ) -> RegistrationAccepted:
        normalized_email = normalize_email(email)
        await self._verify_captcha(captcha_token, remote_ip, "verify_email_request")
        await self._limit("verify_email_request", normalized_email, 3, 900)
        existing = await self._repository.get_by_email(normalized_email)
        if existing is not None and existing.state == "pending":
            await self._send_email_token(existing.user_id, normalized_email, correlation_id)
        return RegistrationAccepted()

    async def verify_email(self, token: str, correlation_id: UUID | None = None) -> None:
        valid = await self._repository.verify_email(
            self._token_hash(token), datetime.now(UTC), correlation_id or uuid4()
        )
        if not valid:
            raise RegistrationError(
                RegistrationErrorCode.VERIFICATION_INVALID,
                "This verification link is invalid, expired, or has already been used.",
                400,
            )

    async def register_phone(
        self,
        phone_e164: str,
        captcha_token: str,
        remote_ip: str | None,
        given_name: str | None = None,
        family_name: str | None = None,
        correlation_id: UUID | None = None,
    ) -> RegistrationAccepted:
        phone = self._normalize_phone(phone_e164)
        await self._verify_captcha(captcha_token, remote_ip, "signup_phone")
        await self._limit("signup_phone", phone, PHONE_RATE_LIMIT, PHONE_RATE_WINDOW_SECONDS)
        existing = await self._repository.get_by_phone(phone)
        user_id: UUID
        if existing is None:
            try:
                user_id = await self._repository.create_phone_registration(
                    phone, given_name, family_name, correlation_id or uuid4()
                )
            except DuplicateContactError:
                return RegistrationAccepted()
        elif existing.state == "pending":
            user_id = existing.user_id
        else:
            return RegistrationAccepted()
        await self._send_phone_otp(user_id, phone)
        return RegistrationAccepted()

    async def request_phone_verification(
        self,
        phone_e164: str,
        captcha_token: str,
        remote_ip: str | None,
    ) -> RegistrationAccepted:
        phone = self._normalize_phone(phone_e164)
        await self._verify_captcha(captcha_token, remote_ip, "verify_phone_request")
        await self._limit(
            "verify_phone_request", phone, PHONE_RATE_LIMIT, PHONE_RATE_WINDOW_SECONDS
        )
        existing = await self._repository.get_by_phone(phone)
        if existing is not None and existing.state == "pending":
            await self._send_phone_otp(existing.user_id, phone)
        return RegistrationAccepted()

    async def verify_phone(
        self,
        phone_e164: str,
        code: str,
        captcha_token: str,
        remote_ip: str | None,
        correlation_id: UUID | None = None,
    ) -> None:
        phone = self._normalize_phone(phone_e164)
        await self._verify_captcha(captcha_token, remote_ip, "verify_phone_confirm")
        existing = await self._repository.get_by_phone(phone)
        if existing is None or existing.state != "pending":
            raise self._invalid_otp()
        outcome = await self._redis_store.verify_and_consume_otp(
            existing.user_id, "phone_verify", self._otp_hash(code), OTP_MAX_ATTEMPTS
        )
        if outcome != 1:
            raise self._invalid_otp()
        if not await self._repository.verify_phone(existing.user_id, correlation_id or uuid4()):
            raise self._invalid_otp()

    async def _verify_captcha(
        self, token: str, remote_ip: str | None, action: str
    ) -> None:
        try:
            valid = await self._captcha_provider.verify(token, remote_ip, action)
        except Exception as error:
            raise self._provider_unavailable() from error
        if not valid:
            raise RegistrationError(
                RegistrationErrorCode.CAPTCHA_INVALID,
                "The security check could not be verified. Please try again.",
                400,
            )

    async def _limit(self, route: str, subject: str, limit: int, window: int) -> None:
        try:
            count = await self._redis_store.increment_rate_limit(route, subject, window)
        except Exception as error:
            raise self._provider_unavailable() from error
        if count > limit:
            raise RegistrationError(
                RegistrationErrorCode.RATE_LIMITED,
                "Too many requests. Please wait and try again.",
                429,
            )

    async def _send_email_token(
        self, user_id: UUID, email: str, correlation_id: UUID | None
    ) -> None:
        raw_token, token_hash, expires_at = self._new_email_token()
        await self._repository.issue_email_verification(
            user_id, token_hash, expires_at, correlation_id or uuid4()
        )
        await self._send_email(email, raw_token)

    async def _send_email(self, email: str, raw_token: str) -> None:
        try:
            await self._email_provider.send_verification(
                email, f"{self._verification_base_url}?token={raw_token}"
            )
        except Exception as error:
            raise self._provider_unavailable() from error

    async def _send_phone_otp(self, user_id: UUID, phone: str) -> None:
        code = f"{secrets.randbelow(1_000_000):06d}"
        await self._redis_store.store_otp_hash(user_id, "phone_verify", self._otp_hash(code))
        try:
            await self._sms_provider.send_verification(phone, code)
        except Exception as error:
            await self._redis_store.consume_otp(user_id, "phone_verify")
            raise self._provider_unavailable() from error

    def _new_email_token(self) -> tuple[str, str, datetime]:
        token = secrets.token_urlsafe(32)
        return token, self._token_hash(token), datetime.now(UTC) + EMAIL_TOKEN_LIFETIME

    @staticmethod
    def _token_hash(token: str) -> str:
        return sha256(token.encode()).hexdigest()

    def _otp_hash(self, code: str) -> str:
        return hmac.new(self._otp_pepper, code.encode(), sha256).hexdigest()

    @staticmethod
    def _normalize_phone(phone: str) -> str:
        normalized = re.sub(r"[\s()-]", "", phone)
        if not PHONE_PATTERN.fullmatch(normalized):
            raise RegistrationError(
                RegistrationErrorCode.VERIFICATION_INVALID,
                "Enter a valid international phone number, including the country code.",
                400,
            )
        return normalized

    @staticmethod
    def _invalid_otp() -> RegistrationError:
        return RegistrationError(
            RegistrationErrorCode.OTP_INVALID,
            "The verification code is invalid or expired.",
            400,
        )

    @staticmethod
    def _provider_unavailable() -> RegistrationError:
        return RegistrationError(
            RegistrationErrorCode.PROVIDER_UNAVAILABLE,
            "A required verification service is temporarily unavailable. Please try again.",
            503,
        )
