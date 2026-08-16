from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_core.control.login import LoginControl
from auth_core.control.mfa import MFAControl
from auth_core.control.registration import RegistrationControl
from auth_core.entity.mfa import MFACompletionType, MFAMethod
from auth_core.infrastructure.persistence.login_repository import SqlAlchemyLoginRepository
from auth_core.infrastructure.persistence.mfa_repository import SqlAlchemyMFARepository
from auth_core.infrastructure.persistence.models import MFADevice, User
from auth_core.infrastructure.persistence.registration_repository import (
    SqlAlchemyRegistrationRepository,
)
from auth_core.infrastructure.providers.oidc import LocalOIDCProvider
from auth_core.infrastructure.providers.totp import PyOTPProvider
from auth_core.infrastructure.providers.webauthn import PyWebAuthnProvider
from auth_core.infrastructure.redis_security import RedisSecurityStore, SecurityKeyFactory
from auth_core.infrastructure.security.passwords import Argon2idPasswordHasher
from auth_core.infrastructure.security.secrets import LocalAESGCMSecretCipher

pytestmark = pytest.mark.integration
TEST_KEY = "bG9jYWwtbWZhLWtleS1jaGFuZ2UtbWUtMzItYnl0ZXM="


class CleanBreach:
    async def breach_count(self, password: str) -> int:
        del password
        return 0


class ValidCaptcha:
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
    async def send_verification(self, phone_e164: str, code: str) -> None:
        del phone_e164, code


class CapturingMFA:
    def __init__(self) -> None:
        self.email_code = ""

    async def send_email_code(self, email: str, code: str) -> None:
        del email
        self.email_code = code

    async def send_sms_code(self, phone_e164: str, code: str) -> None:
        del phone_e164, code


@pytest.mark.asyncio
async def test_real_email_mfa_totp_enrollment_and_backup_storage(
    migrated_database_url: str, integration_redis: Redis
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    store = RedisSecurityStore(
        integration_redis, SecurityKeyFactory(b"integration-mfa-key-long-enough")
    )
    hasher = Argon2idPasswordHasher()
    email = CapturingEmail()
    registration = RegistrationControl(
        SqlAlchemyRegistrationRepository(sessions),
        hasher,
        CleanBreach(),
        ValidCaptcha(),
        email,
        CapturingSMS(),
        store,
        "http://localhost:3000/verify-email",
        b"integration-mfa-otp-pepper",
    )
    login = LoginControl(
        SqlAlchemyLoginRepository(sessions),
        hasher,
        ValidCaptcha(),
        CapturingSMS(),
        LocalOIDCProvider(b"integration-oidc-secret", "http://localhost:3000"),
        store,
        b"integration-device-signal-key",
        b"integration-mfa-otp-pepper",
    )
    notifications = CapturingMFA()
    mfa = MFAControl(
        SqlAlchemyMFARepository(sessions),
        hasher,
        LocalAESGCMSecretCipher(TEST_KEY),
        PyOTPProvider("Vittavaan Integration"),
        notifications,
        PyWebAuthnProvider(
            "localhost", "Vittavaan Integration", ["http://localhost:3000"]
        ),
        store,
        b"integration-mfa-otp-pepper",
        b"integration-backup-pepper",
    )
    try:
        await registration.register_email(
            "mfa@example.com",
            "correct horse battery staple",
            "Ada",
            "Lovelace",
            "valid-captcha",
            "127.0.0.1",
        )
        verification_token = parse_qs(urlparse(email.url).query)["token"][0]
        await registration.verify_email(verification_token)

        first_login = await login.login_password(
            "mfa@example.com",
            "correct horse battery staple",
            "first-browser-fingerprint",
            "127.0.0.1",
        )
        challenge = await mfa.issue_challenge(
            first_login.workflow_token, MFAMethod.EMAIL_OTP
        )
        email_completion = await mfa.verify_challenge(
            challenge.challenge_token, notifications.email_code
        )

        second_login = await login.login_password(
            "mfa@example.com",
            "correct horse battery staple",
            "second-browser-fingerprint",
            "127.0.0.1",
        )
        enrollment = await mfa.setup_totp(
            second_login.workflow_token, "Integration authenticator"
        )
        totp_completion = await mfa.confirm_totp(
            enrollment.enrollment_token, pyotp.TOTP(enrollment.manual_secret).now()
        )

        async with sessions() as session:
            user = await session.scalar(select(User).where(User.email == "mfa@example.com"))
            assert user is not None
            factors = (
                await session.scalars(
                    select(MFADevice).where(MFADevice.user_id == user.user_id)
                )
            ).all()
        totp_factor = next(item for item in factors if item.factor_type == "totp")
        backup_factor = next(
            item for item in factors if item.factor_type == "backup_codes"
        )
        assert email_completion.result == MFACompletionType.SESSION_READY
        assert totp_completion.result == MFACompletionType.SESSION_READY
        assert len(totp_completion.backup_codes) == 10
        assert totp_factor.status == "active"
        assert totp_factor.encrypted_secret is not None
        assert enrollment.manual_secret.encode() not in totp_factor.encrypted_secret
        assert backup_factor.encrypted_secret is not None
        assert all(
            code.encode() not in backup_factor.encrypted_secret
            for code in totp_completion.backup_codes
        )
    finally:
        await engine.dispose()
