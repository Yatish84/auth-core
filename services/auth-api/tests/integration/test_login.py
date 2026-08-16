from urllib.parse import parse_qs, urlparse

import pytest
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_core.control.login import LoginControl
from auth_core.control.registration import RegistrationControl
from auth_core.entity.login import LoginDecisionType, OIDCProfile
from auth_core.infrastructure.persistence.login_repository import SqlAlchemyLoginRepository
from auth_core.infrastructure.persistence.models import AuditLog, Identity, TrustedDevice, User
from auth_core.infrastructure.persistence.registration_repository import (
    SqlAlchemyRegistrationRepository,
)
from auth_core.infrastructure.redis_security import RedisSecurityStore, SecurityKeyFactory
from auth_core.infrastructure.security.passwords import Argon2idPasswordHasher

pytestmark = pytest.mark.integration


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


class CollisionOIDC:
    def authorization_url(
        self, provider: str, state: str, nonce: str, code_challenge: str
    ) -> str:
        del provider, nonce, code_challenge
        return f"https://accounts.example.test/authorize?state={state}"

    async def verify_callback(
        self, provider: str, code: str, nonce: str, code_verifier: str
    ) -> OIDCProfile:
        del code, nonce, code_verifier
        return OIDCProfile(provider, "provider-subject", "login@example.com", True)


@pytest.mark.asyncio
async def test_real_password_login_and_oidc_collision_are_safely_persisted(
    migrated_database_url: str, integration_redis: Redis
) -> None:
    engine = create_async_engine(migrated_database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    store = RedisSecurityStore(
        integration_redis, SecurityKeyFactory(b"integration-login-key-long-enough")
    )
    hasher = Argon2idPasswordHasher()
    email = CapturingEmail()
    registration = RegistrationControl(
        repository=SqlAlchemyRegistrationRepository(sessions),
        password_hasher=hasher,
        breach_provider=CleanBreach(),
        captcha_provider=ValidCaptcha(),
        email_provider=email,
        sms_provider=CapturingSMS(),
        redis_store=store,
        verification_base_url="http://localhost:3000/verify-email",
        otp_pepper=b"integration-login-otp-key",
    )
    login = LoginControl(
        repository=SqlAlchemyLoginRepository(sessions),
        password_hasher=hasher,
        captcha_provider=ValidCaptcha(),
        sms_provider=CapturingSMS(),
        oidc_provider=CollisionOIDC(),
        redis_store=store,
        signal_hmac_secret=b"integration-device-signal-key",
        otp_pepper=b"integration-login-otp-key",
    )
    try:
        await registration.register_email(
            "login@example.com",
            "correct horse battery staple",
            "Ada",
            "Lovelace",
            "valid-captcha",
            "127.0.0.1",
        )
        token = parse_qs(urlparse(email.url).query)["token"][0]
        await registration.verify_email(token)

        decision = await login.login_password(
            "login@example.com",
            "correct horse battery staple",
            "raw-browser-fingerprint",
            "127.0.0.1",
        )
        _, state = await login.start_oidc("google")
        collision = await login.login_oidc(
            "google", state, "signed-provider-code", "raw-browser-fingerprint", "127.0.0.1"
        )

        async with sessions() as session:
            user = await session.scalar(select(User).where(User.email == "login@example.com"))
            assert user is not None
            device = await session.scalar(
                select(TrustedDevice).where(TrustedDevice.user_id == user.user_id)
            )
            google_identity = await session.scalar(
                select(Identity).where(
                    Identity.user_id == user.user_id, Identity.provider == "google"
                )
            )
            audit = await session.scalar(
                select(AuditLog).where(
                    AuditLog.subject_user_id == user.user_id,
                    AuditLog.event_type == "OIDC_ACCOUNT_COLLISION_DETECTED",
                )
            )

        assert decision.decision == LoginDecisionType.MFA_REQUIRED
        assert collision.decision == LoginDecisionType.COLLISION_PROOF_REQUIRED
        assert device is not None and device.fingerprint_hash != "raw-browser-fingerprint"
        assert google_identity is None
        assert audit is not None and audit.outcome == "denied"
    finally:
        await engine.dispose()
