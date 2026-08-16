from urllib.parse import parse_qs, urlparse

import pytest
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_core.control.registration import RegistrationControl
from auth_core.infrastructure.persistence.models import EphemeralToken, Identity, User
from auth_core.infrastructure.persistence.registration_repository import (
    SqlAlchemyRegistrationRepository,
)
from auth_core.infrastructure.redis_security import RedisSecurityStore, SecurityKeyFactory
from auth_core.infrastructure.security.passwords import Argon2idPasswordHasher

pytestmark = pytest.mark.integration


class CleanBreachProvider:
    async def breach_count(self, password: str) -> int:
        del password
        return 0


class ValidCaptchaProvider:
    async def verify(self, token: str, remote_ip: str | None, action: str) -> bool:
        del remote_ip, action
        return token == "valid-captcha"


class CapturingEmailProvider:
    def __init__(self) -> None:
        self.url = ""

    async def send_verification(self, email: str, verification_url: str) -> None:
        del email
        self.url = verification_url


class CapturingSMSProvider:
    def __init__(self) -> None:
        self.code = ""

    async def send_verification(self, phone_e164: str, code: str) -> None:
        del phone_e164
        self.code = code


def build_control(
    database_url: str, redis: Redis
) -> tuple[RegistrationControl, CapturingEmailProvider, CapturingSMSProvider]:
    engine = create_async_engine(database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    email = CapturingEmailProvider()
    sms = CapturingSMSProvider()
    control = RegistrationControl(
        repository=SqlAlchemyRegistrationRepository(sessions),
        password_hasher=Argon2idPasswordHasher(),
        breach_provider=CleanBreachProvider(),
        captcha_provider=ValidCaptchaProvider(),
        email_provider=email,
        sms_provider=sms,
        redis_store=RedisSecurityStore(
            redis, SecurityKeyFactory(b"integration-key-long-enough")
        ),
        verification_base_url="http://localhost:3000/verify-email",
        otp_pepper=b"integration-otp-key-long-enough",
        referral_token_pepper=b"integration-referral-key-long-enough",
    )
    return control, email, sms


@pytest.mark.asyncio
async def test_email_registration_hashes_password_and_consumes_token(
    migrated_database_url: str, integration_redis: Redis
) -> None:
    control, email, _ = build_control(migrated_database_url, integration_redis)

    await control.register_email(
        "integration-email@example.com",
        "correct horse battery staple",
        "Ada",
        "Lovelace",
        "valid-captcha",
        "127.0.0.1",
    )
    raw_token = parse_qs(urlparse(email.url).query)["token"][0]
    await control.verify_email(raw_token)

    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session:
        user = await session.scalar(
            select(User).where(User.email == "integration-email@example.com")
        )
        assert user is not None
        identity = await session.scalar(
            select(Identity).where(Identity.user_id == user.user_id)
        )
        token = await session.scalar(
            select(EphemeralToken).where(EphemeralToken.user_id == user.user_id)
        )
        assert user.state == "active"
        assert identity is not None and identity.password_hash is not None
        assert identity.password_hash.startswith("$argon2id$")
        assert identity.verified is True
        assert token is not None and token.consumed_at is not None
        assert raw_token not in token.token_hash
    await engine.dispose()


@pytest.mark.asyncio
async def test_phone_registration_uses_hashed_redis_otp_and_activates_user(
    migrated_database_url: str, integration_redis: Redis
) -> None:
    control, _, sms = build_control(migrated_database_url, integration_redis)

    await control.register_phone("+16045550199", "valid-captcha", "127.0.0.1")
    assert sms.code.isdigit() and len(sms.code) == 6
    assert sms.code not in " ".join(await integration_redis.keys("*"))
    await control.verify_phone(
        "+16045550199", sms.code, "valid-captcha", "127.0.0.1"
    )

    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session:
        user = await session.scalar(select(User).where(User.phone_e164 == "+16045550199"))
        assert user is not None and user.state == "active"
        identity = await session.scalar(
            select(Identity).where(Identity.user_id == user.user_id)
        )
        assert identity is not None and identity.verified is True
    await engine.dispose()
