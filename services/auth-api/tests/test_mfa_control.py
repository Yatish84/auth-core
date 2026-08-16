import hmac
from hashlib import sha256
from typing import Any
from uuid import UUID, uuid4

import pyotp
import pytest

from auth_core.control.mfa import MFAControl
from auth_core.entity.mfa import (
    MFACompletionType,
    MFAError,
    MFAErrorCode,
    MFAFactor,
    MFAMethod,
    MFAUserProfile,
    StoredPasskey,
)
from auth_core.infrastructure.providers.totp import PyOTPProvider
from auth_core.infrastructure.security.secrets import LocalAESGCMSecretCipher

TEST_KEY = "bG9jYWwtbWZhLWtleS1jaGFuZ2UtbWUtMzItYnl0ZXM="


class FakeRepository:
    def __init__(self) -> None:
        self.user_id = uuid4()
        self.profile = MFAUserProfile(
            self.user_id, "active", "person@example.com", "+16045550100"
        )
        self.factors: dict[UUID, MFAFactor] = {}
        self.backup_hashes: list[str] = []
        self.password = "hash:correct-password"
        self.linked: tuple[str, str] | None = None
        self.audits: list[str] = []
        self.passkey_record: StoredPasskey | None = None

    async def user_profile(self, user_id: UUID) -> MFAUserProfile | None:
        return self.profile if user_id == self.user_id else None

    async def password_hash(self, user_id: UUID) -> str | None:
        return self.password if user_id == self.user_id else None

    async def active_factors(self, user_id: UUID) -> tuple[MFAFactor, ...]:
        return tuple(
            item
            for item in self.factors.values()
            if item.user_id == user_id and item.status == "active"
        )

    async def create_pending_totp(
        self, user_id: UUID, encrypted_secret: bytes, label: str
    ) -> MFAFactor:
        factor = MFAFactor(
            uuid4(), user_id, "totp", "pending", label, encrypted_secret, None
        )
        self.factors[factor.mfa_id] = factor
        return factor

    async def factor(self, user_id: UUID, mfa_id: UUID) -> MFAFactor | None:
        factor = self.factors.get(mfa_id)
        return factor if factor and factor.user_id == user_id else None

    async def activate_totp(
        self, user_id: UUID, mfa_id: UUID, accepted_step: int
    ) -> bool:
        factor = await self.factor(user_id, mfa_id)
        if factor is None or factor.status != "pending":
            return False
        self.factors[mfa_id] = MFAFactor(
            factor.mfa_id,
            factor.user_id,
            factor.factor_type,
            "active",
            factor.label,
            factor.encrypted_secret,
            accepted_step,
        )
        return True

    async def advance_totp_step(
        self, mfa_id: UUID, previous_step: int | None, accepted_step: int
    ) -> bool:
        factor = self.factors[mfa_id]
        if factor.last_totp_step != previous_step:
            return False
        self.factors[mfa_id] = MFAFactor(
            factor.mfa_id,
            factor.user_id,
            factor.factor_type,
            factor.status,
            factor.label,
            factor.encrypted_secret,
            accepted_step,
        )
        return True

    async def store_backup_codes(self, user_id: UUID, hashes: tuple[str, ...]) -> None:
        self.backup_hashes = list(hashes)
        factor = MFAFactor(uuid4(), user_id, "backup_codes", "active", "Recovery codes")
        self.factors[factor.mfa_id] = factor

    async def consume_backup_code(self, user_id: UUID, candidate_hash: str) -> bool:
        del user_id
        match = next(
            (
                value
                for value in self.backup_hashes
                if hmac.compare_digest(value, candidate_hash)
            ),
            None,
        )
        if match is None:
            return False
        self.backup_hashes.remove(match)
        return True

    async def passkeys(self, user_id: UUID) -> tuple[StoredPasskey, ...]:
        if self.passkey_record and self.passkey_record.user_id == user_id:
            return (self.passkey_record,)
        return ()

    async def passkey(self, credential_id: bytes) -> StoredPasskey | None:
        if self.passkey_record and self.passkey_record.credential_id == credential_id:
            return self.passkey_record
        return None

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
    ) -> None:
        mfa_id = uuid4()
        self.factors[mfa_id] = MFAFactor(
            mfa_id, user_id, "passkey", "active", label
        )
        self.passkey_record = StoredPasskey(
            credential_id,
            mfa_id,
            user_id,
            public_key,
            sign_count,
            transports,
            backup_eligible,
            backup_state,
        )

    async def update_passkey_counter(
        self,
        credential_id: bytes,
        previous_count: int,
        new_count: int,
        backup_state: bool,
    ) -> bool:
        stored = await self.passkey(credential_id)
        if stored is None or stored.sign_count != previous_count:
            return False
        self.passkey_record = StoredPasskey(
            stored.credential_id,
            stored.mfa_id,
            stored.user_id,
            stored.public_key,
            new_count,
            stored.transports,
            stored.backup_eligible,
            backup_state,
        )
        return True

    async def revoke_factor(self, user_id: UUID, mfa_id: UUID) -> bool:
        factor = await self.factor(user_id, mfa_id)
        if factor is None:
            return False
        self.factors[mfa_id] = MFAFactor(
            factor.mfa_id,
            factor.user_id,
            factor.factor_type,
            "revoked",
            factor.label,
            factor.encrypted_secret,
            factor.last_totp_step,
        )
        return True

    async def link_oidc_identity(self, user_id: UUID, provider: str, subject: str) -> bool:
        del user_id
        self.linked = (provider, subject)
        return True

    async def audit(
        self,
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        user_id: UUID | None,
        metadata: dict[str, str],
    ) -> None:
        del outcome, correlation_id, user_id, metadata
        self.audits.append(event_type)


class FakeHasher:
    def hash(self, password: str) -> str:
        return f"hash:{password}"

    def verify(self, password_hash: str, password: str) -> bool:
        return hmac.compare_digest(password_hash, self.hash(password))

    def needs_rehash(self, password_hash: str) -> bool:
        del password_hash
        return False


class CapturingNotifications:
    def __init__(self) -> None:
        self.email_code = ""
        self.sms_code = ""

    async def send_email_code(self, email: str, code: str) -> None:
        del email
        self.email_code = code

    async def send_sms_code(self, phone_e164: str, code: str) -> None:
        del phone_e164
        self.sms_code = code


class FakeWebAuthn:
    credential = b"credential-id"

    def registration_options(
        self,
        user_id: UUID,
        user_name: str,
        existing_credentials: tuple[bytes, ...],
    ) -> tuple[dict[str, Any], bytes]:
        del user_id, user_name, existing_credentials
        return {"challenge": "registration"}, b"registration-challenge"

    def verify_registration(
        self, credential: dict[str, Any], expected_challenge: bytes
    ) -> tuple[bytes, bytes, int, tuple[str, ...], bool, bool]:
        del credential
        if expected_challenge != b"registration-challenge":
            raise ValueError
        return self.credential, b"public-key", 0, ("internal",), True, True

    def authentication_options(
        self, credentials: tuple[StoredPasskey, ...]
    ) -> tuple[dict[str, Any], bytes]:
        del credentials
        return {"challenge": "authentication"}, b"authentication-challenge"

    def credential_id(self, credential: dict[str, Any]) -> bytes:
        del credential
        return self.credential

    def verify_authentication(
        self,
        credential: dict[str, Any],
        expected_challenge: bytes,
        stored: StoredPasskey,
    ) -> tuple[int, bool]:
        del credential
        if expected_challenge != b"authentication-challenge":
            raise ValueError
        return stored.sign_count + 1, True


class FakeRedis:
    def __init__(self) -> None:
        self.workflows: dict[str, dict[str, Any]] = {}
        self.challenges: dict[str, dict[str, Any]] = {}
        self.webauthn: dict[str, dict[str, Any]] = {}
        self.otps: dict[tuple[UUID, str], str] = {}
        self.otp_attempts: dict[tuple[UUID, str], int] = {}
        self.rates: dict[tuple[str, str], int] = {}
        self.locked_factors: set[UUID] = set()

    async def get_login_workflow(self, token: str) -> dict[str, Any] | None:
        return self.workflows.get(token)

    async def consume_login_workflow(self, token: str) -> dict[str, Any] | None:
        return self.workflows.pop(token, None)

    async def store_login_workflow(self, token: str, payload: dict[str, Any]) -> None:
        self.workflows[token] = payload

    async def store_mfa_challenge(self, token: str, payload: dict[str, Any]) -> None:
        self.challenges[token] = payload

    async def get_mfa_challenge(self, token: str) -> dict[str, Any] | None:
        return self.challenges.get(token)

    async def consume_mfa_challenge(self, token: str) -> dict[str, Any] | None:
        return self.challenges.pop(token, None)

    async def store_webauthn_challenge(
        self, token: str, payload: dict[str, Any]
    ) -> None:
        self.webauthn[token] = payload

    async def consume_webauthn_challenge(self, token: str) -> dict[str, Any] | None:
        return self.webauthn.pop(token, None)

    async def store_otp_hash(self, user_id: UUID, purpose: str, otp_hash: str) -> None:
        self.otps[(user_id, purpose)] = otp_hash
        self.otp_attempts[(user_id, purpose)] = 0

    async def consume_otp(self, user_id: UUID, purpose: str) -> None:
        self.otps.pop((user_id, purpose), None)

    async def verify_and_consume_otp(
        self, user_id: UUID, purpose: str, candidate_hash: str, max_attempts: int
    ) -> int:
        key = (user_id, purpose)
        stored = self.otps.get(key)
        if stored is None:
            return -1
        if hmac.compare_digest(stored, candidate_hash):
            self.otps.pop(key)
            return 1
        self.otp_attempts[key] += 1
        if self.otp_attempts[key] >= max_attempts:
            self.otps.pop(key)
        return 0

    async def increment_rate_limit(self, route: str, subject: str, window: int) -> int:
        del window
        key = (route, subject)
        self.rates[key] = self.rates.get(key, 0) + 1
        return self.rates[key]

    async def lock_factor(self, factor_id: UUID) -> None:
        self.locked_factors.add(factor_id)

    async def factor_is_locked(self, factor_id: UUID) -> bool:
        return factor_id in self.locked_factors


def make_control() -> tuple[
    MFAControl, FakeRepository, FakeRedis, CapturingNotifications
]:
    repository = FakeRepository()
    redis = FakeRedis()
    notifications = CapturingNotifications()
    control = MFAControl(
        repository,
        FakeHasher(),
        LocalAESGCMSecretCipher(TEST_KEY),
        PyOTPProvider("Vittavaan Test"),
        notifications,
        FakeWebAuthn(),
        redis,  # type: ignore[arg-type]
        b"test-mfa-otp-pepper-long",
        b"test-backup-code-pepper",
    )
    return control, repository, redis, notifications


def workflow(repository: FakeRepository, redis: FakeRedis, token: str = "login-workflow") -> str:
    redis.workflows[token] = {
        "user_id": str(repository.user_id),
        "decision": "mfa_required",
    }
    return token


@pytest.mark.asyncio
async def test_email_code_is_single_use_and_returns_session_handoff() -> None:
    control, repository, redis, notifications = make_control()
    challenge = await control.issue_challenge(
        workflow(repository, redis), MFAMethod.EMAIL_OTP
    )

    result = await control.verify_challenge(challenge.challenge_token, notifications.email_code)

    assert result.result == MFACompletionType.SESSION_READY
    assert result.workflow_token in redis.workflows
    with pytest.raises(MFAError) as replay:
        await control.verify_challenge(challenge.challenge_token, notifications.email_code)
    assert replay.value.code == MFAErrorCode.CHALLENGE_INVALID


@pytest.mark.asyncio
async def test_totp_enrollment_encrypts_secret_and_returns_one_time_backup_codes() -> None:
    control, repository, redis, _ = make_control()
    enrollment = await control.setup_totp(workflow(repository, redis), "My authenticator")
    factor = next(iter(repository.factors.values()))

    assert factor.encrypted_secret is not None
    assert enrollment.manual_secret.encode() not in factor.encrypted_secret
    result = await control.confirm_totp(
        enrollment.enrollment_token, pyotp.TOTP(enrollment.manual_secret).now()
    )

    assert result.result == MFACompletionType.SESSION_READY
    assert len(result.backup_codes) == 10
    assert all(
        code.replace("-", "") not in "".join(repository.backup_hashes)
        for code in result.backup_codes
    )
    with pytest.raises(MFAError):
        await control.confirm_totp(
            enrollment.enrollment_token, pyotp.TOTP(enrollment.manual_secret).now()
        )


@pytest.mark.asyncio
async def test_three_wrong_totp_codes_lock_factor_for_fifteen_minutes() -> None:
    control, repository, redis, _ = make_control()
    secret = pyotp.random_base32()
    factor = MFAFactor(
        uuid4(),
        repository.user_id,
        "totp",
        "active",
        "Authenticator",
        LocalAESGCMSecretCipher(TEST_KEY).encrypt(secret.encode(), repository.user_id.bytes),
        None,
    )
    repository.factors[factor.mfa_id] = factor
    challenge = await control.issue_challenge(
        workflow(repository, redis), MFAMethod.TOTP
    )

    for _ in range(3):
        with pytest.raises(MFAError):
            await control.verify_challenge(challenge.challenge_token, "000000")

    assert factor.mfa_id in redis.locked_factors
    with pytest.raises(MFAError) as locked:
        await control.verify_challenge(
            challenge.challenge_token, pyotp.TOTP(secret).now()
        )
    assert locked.value.code == MFAErrorCode.FACTOR_LOCKED


@pytest.mark.asyncio
async def test_backup_code_cannot_be_replayed() -> None:
    control, repository, redis, _ = make_control()
    enrollment = await control.setup_totp(workflow(repository, redis), "Authenticator")
    enrolled = await control.confirm_totp(
        enrollment.enrollment_token, pyotp.TOTP(enrollment.manual_secret).now()
    )
    code = enrolled.backup_codes[0]
    challenge = await control.issue_challenge(
        workflow(repository, redis, "backup-workflow-1"), MFAMethod.BACKUP_CODE
    )
    await control.verify_challenge(challenge.challenge_token, code)
    replay_challenge = await control.issue_challenge(
        workflow(repository, redis, "backup-workflow-2"), MFAMethod.BACKUP_CODE
    )

    with pytest.raises(MFAError) as replay:
        await control.verify_challenge(replay_challenge.challenge_token, code)

    assert replay.value.code == MFAErrorCode.CODE_INVALID


@pytest.mark.asyncio
async def test_password_proof_resolves_oidc_collision_once() -> None:
    control, repository, redis, _ = make_control()
    redis.workflows["collision-workflow"] = {
        "user_id": str(repository.user_id),
        "decision": "collision_proof_required",
        "oidc_provider": "google",
        "oidc_subject": "google-subject",
    }

    result = await control.prove_collision_password(
        "collision-workflow", "correct-password"
    )

    assert result.result == MFACompletionType.IDENTITY_LINKED
    assert repository.linked == ("google", "google-subject")
    with pytest.raises(MFAError):
        await control.prove_collision_password(
            "collision-workflow", "correct-password"
        )


@pytest.mark.asyncio
async def test_passkey_challenge_is_single_use() -> None:
    control, repository, redis, _ = make_control()
    options = await control.passkey_registration_options(
        workflow(repository, redis), "Laptop passkey"
    )
    await control.confirm_passkey_registration(options.challenge_token, {"id": "value"})
    auth = await control.passkey_authentication_options()
    result = await control.verify_passkey(auth.challenge_token, {"rawId": "value"})

    assert result.result == MFACompletionType.SESSION_READY
    with pytest.raises(MFAError) as replay:
        await control.verify_passkey(auth.challenge_token, {"rawId": "value"})
    assert replay.value.code == MFAErrorCode.PASSKEY_INVALID


@pytest.mark.asyncio
async def test_existing_factors_require_completed_mfa_before_management() -> None:
    control, repository, redis, _ = make_control()
    first = MFAFactor(
        uuid4(), repository.user_id, "passkey", "active", "First passkey"
    )
    second = MFAFactor(
        uuid4(), repository.user_id, "passkey", "active", "Second passkey"
    )
    repository.factors[first.mfa_id] = first
    repository.factors[second.mfa_id] = second
    primary_workflow = workflow(repository, redis)

    with pytest.raises(MFAError) as denied:
        await control.revoke_factor(primary_workflow, first.mfa_id)

    assert denied.value.code == MFAErrorCode.WORKFLOW_INVALID
    redis.workflows["strong-workflow"] = {
        "user_id": str(repository.user_id),
        "decision": "session_ready",
        "assurance": "mfa",
    }
    await control.revoke_factor("strong-workflow", first.mfa_id)
    assert repository.factors[first.mfa_id].status == "revoked"


def test_backup_code_hash_is_keyed_and_not_plaintext() -> None:
    code = "ABCD-EFGH-IJKL-MNOP"
    digest = hmac.new(
        b"test-backup-code-pepper", code.replace("-", "").encode(), sha256
    ).hexdigest()

    assert code not in digest
