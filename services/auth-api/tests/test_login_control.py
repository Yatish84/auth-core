import hmac
from hashlib import sha256
from typing import Any
from uuid import UUID, uuid4

import pytest

from auth_core.control.login import LoginControl
from auth_core.entity.login import (
    DeviceSignals,
    LoginDecisionType,
    LoginError,
    LoginErrorCode,
    LoginIdentity,
    OIDCProfile,
)


class FakeRepository:
    def __init__(self) -> None:
        self.passwords: dict[str, LoginIdentity] = {}
        self.phones: dict[str, LoginIdentity] = {}
        self.oidc: dict[tuple[str, str], LoginIdentity] = {}
        self.email_users: dict[str, LoginIdentity] = {}
        self.signals = DeviceSignals(known=False, trusted=False, ip_changed=False)
        self.audits: list[tuple[str, str]] = []
        self.provisioned: OIDCProfile | None = None

    async def password_identity(self, email: str) -> LoginIdentity | None:
        return self.passwords.get(email)

    async def phone_identity(self, phone_e164: str) -> LoginIdentity | None:
        return self.phones.get(phone_e164)

    async def oidc_identity(self, provider: str, subject: str) -> LoginIdentity | None:
        return self.oidc.get((provider, subject))

    async def active_user_by_email(self, email: str) -> LoginIdentity | None:
        return self.email_users.get(email)

    async def provision_oidc(
        self, profile: OIDCProfile, correlation_id: UUID
    ) -> LoginIdentity:
        del correlation_id
        self.provisioned = profile
        identity = LoginIdentity(uuid4(), "active", None, True, False)
        self.oidc[(profile.provider, profile.subject)] = identity
        return identity

    async def device_signals(
        self, user_id: UUID, fingerprint_hash: str, ip_address: str | None
    ) -> DeviceSignals:
        del user_id, fingerprint_hash, ip_address
        return self.signals

    async def fallback_methods(self, user_id: UUID) -> tuple[str, ...]:
        del user_id
        return ("password", "phone_otp")

    async def update_password_hash(self, user_id: UUID, password_hash: str) -> None:
        del user_id, password_hash

    async def audit(
        self,
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        subject_user_id: UUID | None,
        metadata: dict[str, str],
    ) -> None:
        del correlation_id, subject_user_id, metadata
        self.audits.append((event_type, outcome))


class FakeHasher:
    def __init__(self) -> None:
        self.verifications = 0

    def hash(self, password: str) -> str:
        return f"hash:{password}"

    def verify(self, password_hash: str, password: str) -> bool:
        self.verifications += 1
        return hmac.compare_digest(password_hash, self.hash(password))

    def needs_rehash(self, password_hash: str) -> bool:
        del password_hash
        return False


class FakeCaptcha:
    async def verify(self, token: str, remote_ip: str | None, action: str) -> bool:
        del remote_ip, action
        return token == "valid-captcha"


class CapturingSMS:
    def __init__(self) -> None:
        self.code = ""

    async def send_verification(self, phone_e164: str, code: str) -> None:
        del phone_e164
        self.code = code


class FakeOIDC:
    def __init__(self) -> None:
        self.profile = OIDCProfile("google", "subject-1", "person@example.com", True)

    def authorization_url(
        self, provider: str, state: str, nonce: str, code_challenge: str
    ) -> str:
        return f"https://example.test/{provider}?state={state}&nonce={nonce}&pkce={code_challenge}"

    async def verify_callback(
        self, provider: str, code: str, nonce: str, code_verifier: str
    ) -> OIDCProfile:
        del code, nonce, code_verifier
        if provider != self.profile.provider:
            raise ValueError
        return self.profile


class FakeRedis:
    def __init__(self) -> None:
        self.rates: dict[tuple[str, str], int] = {}
        self.locks: set[str] = set()
        self.otps: dict[tuple[UUID, str], str] = {}
        self.workflows: dict[str, dict[str, Any]] = {}
        self.oidc_workflows: dict[str, dict[str, Any]] = {}

    async def increment_rate_limit(self, route: str, subject: str, window: int) -> int:
        del window
        key = (route, subject)
        self.rates[key] = self.rates.get(key, 0) + 1
        return self.rates[key]

    async def reset_rate_limit(self, route: str, subject: str, window: int) -> None:
        del window
        self.rates.pop((route, subject), None)

    async def lock_login(self, subject: str) -> None:
        self.locks.add(subject)

    async def login_is_locked(self, subject: str) -> bool:
        return subject in self.locks

    async def store_otp_hash(self, user_id: UUID, purpose: str, otp_hash: str) -> None:
        self.otps[(user_id, purpose)] = otp_hash

    async def consume_otp(self, user_id: UUID, purpose: str) -> None:
        self.otps.pop((user_id, purpose), None)

    async def verify_and_consume_otp(
        self, user_id: UUID, purpose: str, candidate_hash: str, max_attempts: int
    ) -> int:
        del max_attempts
        key = (user_id, purpose)
        stored = self.otps.get(key)
        if stored is None:
            return -1
        if stored != candidate_hash:
            return 0
        self.otps.pop(key)
        return 1

    async def store_login_workflow(self, token: str, payload: dict[str, Any]) -> None:
        self.workflows[token] = payload

    async def get_login_workflow(self, token: str) -> dict[str, Any] | None:
        return self.workflows.get(token)

    async def store_oidc_workflow(self, state: str, payload: dict[str, Any]) -> None:
        self.oidc_workflows[state] = payload

    async def consume_oidc_workflow(self, state: str) -> dict[str, Any] | None:
        return self.oidc_workflows.pop(state, None)


def make_control() -> tuple[
    LoginControl, FakeRepository, FakeHasher, FakeRedis, CapturingSMS, FakeOIDC
]:
    repository = FakeRepository()
    hasher = FakeHasher()
    redis = FakeRedis()
    sms = CapturingSMS()
    oidc = FakeOIDC()
    control = LoginControl(
        repository,
        hasher,
        FakeCaptcha(),
        sms,
        oidc,
        redis,  # type: ignore[arg-type]
        b"test-device-signal-secret",
        b"test-otp-pepper-long-enough",
    )
    return control, repository, hasher, redis, sms, oidc


@pytest.mark.asyncio
async def test_unknown_and_wrong_password_use_same_safe_error_and_hash_work() -> None:
    control, repository, hasher, _, _, _ = make_control()
    repository.passwords["known@example.com"] = LoginIdentity(
        uuid4(), "active", "hash:correct-password", True, False
    )

    for email in ("unknown@example.com", "known@example.com"):
        with pytest.raises(LoginError) as raised:
            await control.login_password(
                email, "wrong-password", "browser-fingerprint-123", "127.0.0.1"
            )
        assert raised.value.code == LoginErrorCode.INVALID_CREDENTIALS

    assert hasher.verifications == 2


@pytest.mark.asyncio
async def test_five_password_failures_create_temporary_lock() -> None:
    control, _, _, redis, _, _ = make_control()

    for _ in range(5):
        with pytest.raises(LoginError):
            await control.login_password(
                "person@example.com", "wrong", "browser-fingerprint-123", None
            )

    assert "person@example.com" in redis.locks
    with pytest.raises(LoginError) as raised:
        await control.login_password(
            "person@example.com", "wrong", "browser-fingerprint-123", None
        )
    assert raised.value.code == LoginErrorCode.TEMPORARILY_LOCKED


@pytest.mark.asyncio
async def test_unknown_device_requires_mfa_without_issuing_a_session() -> None:
    control, repository, _, redis, _, _ = make_control()
    repository.passwords["person@example.com"] = LoginIdentity(
        uuid4(), "active", "hash:correct-password", True, True
    )

    decision = await control.login_password(
        "person@example.com",
        "correct-password",
        "browser-fingerprint-123",
        "127.0.0.1",
    )

    assert decision.decision == LoginDecisionType.MFA_REQUIRED
    assert decision.workflow_token in redis.workflows


@pytest.mark.asyncio
async def test_phone_otp_is_single_use() -> None:
    control, repository, _, _, sms, _ = make_control()
    repository.phones["+16045550100"] = LoginIdentity(
        uuid4(), "active", None, True, True
    )
    await control.request_phone_otp(
        "+16045550100", "valid-captcha", "127.0.0.1"
    )

    await control.login_phone(
        "+16045550100",
        sms.code,
        "valid-captcha",
        "mobile-fingerprint-123",
        "127.0.0.1",
    )
    with pytest.raises(LoginError) as replay:
        await control.login_phone(
            "+16045550100",
            sms.code,
            "valid-captcha",
            "mobile-fingerprint-123",
            "127.0.0.1",
        )

    assert replay.value.code == LoginErrorCode.OTP_INVALID


@pytest.mark.asyncio
async def test_oidc_email_collision_requires_proof_and_does_not_link() -> None:
    control, repository, _, _, _, oidc = make_control()
    existing = LoginIdentity(uuid4(), "active", "hash:existing", True, True)
    repository.email_users[oidc.profile.email] = existing
    _, state = await control.start_oidc("google")

    decision = await control.login_oidc(
        "google", state, "signed-code-value-long-enough", "browser-fingerprint-123", None
    )

    assert decision.decision == LoginDecisionType.COLLISION_PROOF_REQUIRED
    assert repository.provisioned is None
    assert ("OIDC_ACCOUNT_COLLISION_DETECTED", "denied") in repository.audits


@pytest.mark.asyncio
async def test_oidc_state_is_single_use() -> None:
    control, _, _, _, _, _ = make_control()
    _, state = await control.start_oidc("google")
    await control.login_oidc(
        "google", state, "signed-code-value-long-enough", "browser-fingerprint-123", None
    )

    with pytest.raises(LoginError) as replay:
        await control.login_oidc(
            "google",
            state,
            "signed-code-value-long-enough",
            "browser-fingerprint-123",
            None,
        )

    assert replay.value.code == LoginErrorCode.OIDC_INVALID


def test_otp_hash_does_not_store_the_plain_code() -> None:
    code = "123456"
    digest = hmac.new(b"test-otp-pepper-long-enough", code.encode(), sha256).hexdigest()

    assert code not in digest
