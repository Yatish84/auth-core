from dataclasses import dataclass
from datetime import datetime
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from auth_core.control.registration import RegistrationControl
from auth_core.entity.registration import PendingContact, RegistrationError, RegistrationErrorCode


class FakeRepository:
    def __init__(self) -> None:
        self.contacts: dict[str, PendingContact] = {}
        self.email_token_hash = ""
        self.verified_user: UUID | None = None

    async def get_by_email(self, email: str) -> PendingContact | None:
        return self.contacts.get(email)

    async def get_by_phone(self, phone_e164: str) -> PendingContact | None:
        return self.contacts.get(phone_e164)

    async def create_email_registration(
        self,
        email: str,
        given_name: str,
        family_name: str,
        password_hash: str,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> UUID:
        del given_name, family_name, password_hash, expires_at, correlation_id
        user_id = uuid4()
        self.contacts[email] = PendingContact(user_id, "pending")
        self.email_token_hash = token_hash
        return user_id

    async def issue_email_verification(
        self,
        user_id: UUID,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> None:
        del user_id, expires_at, correlation_id
        self.email_token_hash = token_hash

    async def verify_email(self, token_hash: str, now: datetime, correlation_id: UUID) -> bool:
        del now, correlation_id
        return token_hash == self.email_token_hash

    async def create_phone_registration(
        self,
        phone_e164: str,
        given_name: str | None,
        family_name: str | None,
        correlation_id: UUID,
    ) -> UUID:
        del given_name, family_name, correlation_id
        user_id = uuid4()
        self.contacts[phone_e164] = PendingContact(user_id, "pending")
        return user_id

    async def verify_phone(self, user_id: UUID, correlation_id: UUID) -> bool:
        del correlation_id
        self.verified_user = user_id
        return True


class FakeRedis:
    def __init__(self) -> None:
        self.otp_hash: dict[tuple[UUID, str], str] = {}
        self.attempts = 0
        self.rates: dict[tuple[str, str], int] = {}

    async def store_otp_hash(self, user_id: UUID, purpose: str, otp_hash: str) -> None:
        self.otp_hash[(user_id, purpose)] = otp_hash
        self.attempts = 0

    async def get_otp_hash(self, user_id: UUID, purpose: str) -> str | None:
        return self.otp_hash.get((user_id, purpose))

    async def record_otp_failure(self, user_id: UUID, purpose: str) -> int:
        del user_id, purpose
        self.attempts += 1
        return self.attempts

    async def consume_otp(self, user_id: UUID, purpose: str) -> None:
        self.otp_hash.pop((user_id, purpose), None)

    async def verify_and_consume_otp(
        self, user_id: UUID, purpose: str, candidate_hash: str, max_attempts: int
    ) -> int:
        stored = self.otp_hash.get((user_id, purpose))
        if stored is None:
            return -1
        if stored == candidate_hash:
            await self.consume_otp(user_id, purpose)
            return 1
        self.attempts += 1
        if self.attempts >= max_attempts:
            await self.consume_otp(user_id, purpose)
        return 0

    async def increment_rate_limit(self, route: str, subject: str, window: int) -> int:
        del window
        key = (route, subject)
        self.rates[key] = self.rates.get(key, 0) + 1
        return self.rates[key]


class FakeHasher:
    def hash(self, password: str) -> str:
        return f"argon2:{len(password)}"


@dataclass
class FakeBreach:
    count: int = 0

    async def breach_count(self, password: str) -> int:
        del password
        return self.count


class FakeCaptcha:
    async def verify(self, token: str, remote_ip: str | None, action: str) -> bool:
        del remote_ip, action
        return token == "valid-captcha"


class CapturingEmail:
    def __init__(self) -> None:
        self.url = ""

    async def send_verification(self, email: str, verification_url: str) -> None:
        del email
        self.url = verification_url


class CapturingSMS:
    def __init__(self) -> None:
        self.code = ""

    async def send_verification(self, phone_e164: str, code: str) -> None:
        del phone_e164
        self.code = code


def control(
    breach_count: int = 0,
) -> tuple[RegistrationControl, FakeRepository, CapturingEmail, CapturingSMS]:
    repository = FakeRepository()
    email = CapturingEmail()
    sms = CapturingSMS()
    instance = RegistrationControl(
        repository=repository,
        password_hasher=FakeHasher(),
        breach_provider=FakeBreach(breach_count),
        captcha_provider=FakeCaptcha(),
        email_provider=email,
        sms_provider=sms,
        redis_store=FakeRedis(),  # type: ignore[arg-type]
        verification_base_url="http://localhost:3000/verify-email",
        otp_pepper=b"test-otp-pepper-long-enough",
    )
    return instance, repository, email, sms


@pytest.mark.asyncio
async def test_email_registration_and_verification() -> None:
    instance, _, email, _ = control()
    result = await instance.register_email(
        " Person@Example.com ",
        "correct horse battery staple",
        "Ada",
        "Lovelace",
        "valid-captcha",
        "127.0.0.1",
    )
    token = email.url.split("token=", 1)[1]

    await instance.verify_email(token)

    assert result.status == "accepted"


@pytest.mark.asyncio
async def test_breached_password_is_rejected() -> None:
    instance, _, _, _ = control(breach_count=42)

    with pytest.raises(RegistrationError) as raised:
        await instance.register_email(
            "person@example.com",
            "known breached password",
            "Ada",
            "Lovelace",
            "valid-captcha",
            None,
        )

    assert raised.value.code == RegistrationErrorCode.PASSWORD_BREACHED


@pytest.mark.asyncio
async def test_phone_registration_and_verification() -> None:
    instance, repository, _, sms = control()

    await instance.register_phone("+1 (604) 555-0100", "valid-captcha", None)
    await instance.verify_phone(
        "+16045550100", sms.code, "valid-captcha", "127.0.0.1"
    )

    assert repository.verified_user is not None


@pytest.mark.asyncio
async def test_phone_request_is_limited_after_three_attempts() -> None:
    instance, _, _, _ = control()

    for _ in range(3):
        await instance.register_phone("+16045550101", "valid-captcha", None)

    with pytest.raises(RegistrationError) as raised:
        await instance.register_phone("+16045550101", "valid-captcha", None)

    assert raised.value.code == RegistrationErrorCode.RATE_LIMITED


@pytest.mark.asyncio
async def test_notification_failure_returns_safe_provider_error() -> None:
    instance, _, email, _ = control()
    email.send_verification = AsyncMock(side_effect=ConnectionError)  # type: ignore[method-assign]

    with pytest.raises(RegistrationError) as raised:
        await instance.register_email(
            "provider-failure@example.com",
            "correct horse battery staple",
            "Ada",
            "Lovelace",
            "valid-captcha",
            None,
        )

    assert raised.value.code == RegistrationErrorCode.PROVIDER_UNAVAILABLE


@pytest.mark.asyncio
async def test_three_wrong_phone_codes_consume_the_otp() -> None:
    instance, _, _, sms = control()
    await instance.register_phone("+16045550102", "valid-captcha", None)
    wrong_code = "000000" if sms.code != "000000" else "000001"

    for _ in range(3):
        with pytest.raises(RegistrationError):
            await instance.verify_phone(
                "+16045550102", wrong_code, "valid-captcha", None
            )

    with pytest.raises(RegistrationError) as replay:
        await instance.verify_phone(
            "+16045550102", sms.code, "valid-captcha", None
        )

    assert replay.value.code == RegistrationErrorCode.OTP_INVALID
