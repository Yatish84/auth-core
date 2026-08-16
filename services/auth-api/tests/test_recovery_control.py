from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from auth_core.control.recovery import RecoveryControl, SupportAdminControl
from auth_core.entity.recovery import (
    ContactChangeRecord,
    ContactProof,
    ContactType,
    GovernedResetRecord,
    PasswordResetOutcome,
    RecoveryError,
    RecoveryErrorCode,
    RecoveryUser,
    StaffRole,
)
from auth_core.entity.session import AccessClaims, ClientType


class FakeHasher:
    def hash(self, password: str) -> str:
        return f"hash:{password}"

    def verify(self, password_hash: str, password: str) -> bool:
        return password_hash == f"hash:{password}"


class FakeBreachProvider:
    def __init__(self, count: int = 0) -> None:
        self.count = count

    async def breach_count(self, password: str) -> int:
        del password
        return self.count


class FakeRateStore:
    async def increment_rate_limit(self, route: str, subject: str, window: int) -> int:
        del route, subject, window
        return 1


class FakeNotifications:
    def __init__(self) -> None:
        self.reset_url = ""
        self.changed: list[str] = []
        self.contact_codes: list[tuple[str, str, ContactProof]] = []
        self.mfa_requested = False
        self.mfa_completed = False

    async def send_password_reset(self, email: str, reset_url: str) -> None:
        del email
        self.reset_url = reset_url

    async def send_password_changed(self, email: str) -> None:
        self.changed.append(email)

    async def send_support_recovery(self, email: str, recovery_url: str) -> None:
        del email
        self.reset_url = recovery_url

    async def send_contact_code(
        self, destination: str, code: str, proof: ContactProof
    ) -> None:
        self.contact_codes.append((destination, code, proof))

    async def send_contact_changed(self, destination: str) -> None:
        self.changed.append(destination)

    async def send_mfa_reset_requested(
        self, destination: str, execute_after: datetime
    ) -> None:
        del destination, execute_after
        self.mfa_requested = True

    async def send_mfa_reset_completed(self, destination: str) -> None:
        del destination
        self.mfa_completed = True


class FakeSessionRevoker:
    def __init__(self) -> None:
        self.revocations: list[tuple[UUID, str]] = []

    async def revoke_user_access(self, user_id: UUID, reason: str) -> int:
        self.revocations.append((user_id, reason))
        return 1


class FakeRecoveryRepository:
    def __init__(self) -> None:
        self.user = RecoveryUser(
            uuid4(), "person@example.com", "+16045550123", "active", 1
        )
        self.reset_outcome = PasswordResetOutcome.UPDATED
        self.issued_hash = ""
        self.contact_record: ContactChangeRecord | None = None
        self.roles: set[StaffRole] = set()
        now = datetime.now(UTC)
        self.governed = GovernedResetRecord(
            uuid4(),
            self.user.user_id,
            uuid4(),
            None,
            "pending",
            now,
            now + timedelta(hours=12),
            None,
            None,
            "T-1",
        )

    async def eligible_user_by_email(self, email: str) -> RecoveryUser | None:
        return self.user if email == self.user.email else None

    async def issue_password_reset(
        self,
        user_id: UUID,
        token_hash: str,
        purpose: str,
        expires_at: datetime,
        correlation_id: UUID,
        actor_user_id: UUID | None = None,
        ticket_reference: str | None = None,
    ) -> None:
        del user_id, purpose, expires_at, correlation_id, actor_user_id, ticket_reference
        self.issued_hash = token_hash

    async def consume_password_reset(
        self,
        token_hash: str,
        password: str,
        password_hash: str,
        now: datetime,
        correlation_id: UUID,
    ) -> tuple[PasswordResetOutcome, RecoveryUser | None]:
        del token_hash, password, password_hash, now, correlation_id
        return self.reset_outcome, self.user

    async def create_contact_change(
        self,
        user_id: UUID,
        contact_type: ContactType,
        new_value: str,
        old_code_hash: str,
        new_code_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> ContactChangeRecord | None:
        del old_code_hash, new_code_hash, correlation_id
        old_value = self.user.email if contact_type is ContactType.EMAIL else self.user.phone_e164
        assert old_value is not None
        self.contact_record = ContactChangeRecord(
            uuid4(), user_id, contact_type, old_value, new_value, expires_at
        )
        return self.contact_record

    async def verify_contact_change(
        self,
        user_id: UUID,
        request_id: UUID,
        proof: ContactProof,
        code_hash: str,
        now: datetime,
        correlation_id: UUID,
    ) -> ContactChangeRecord | None:
        del user_id, request_id, code_hash, correlation_id
        assert self.contact_record is not None
        old_verified = now if proof is ContactProof.OLD else self.contact_record.old_verified_at
        new_verified = now if proof is ContactProof.NEW else self.contact_record.new_verified_at
        applied = now if old_verified and new_verified else None
        self.contact_record = ContactChangeRecord(
            self.contact_record.request_id,
            self.contact_record.user_id,
            self.contact_record.contact_type,
            self.contact_record.old_value,
            self.contact_record.new_value,
            self.contact_record.expires_at,
            old_verified,
            new_verified,
            applied,
        )
        return self.contact_record

    async def staff_has_role(self, user_id: UUID, role: StaffRole) -> bool:
        del user_id
        return role in self.roles

    async def unlock_user(
        self, actor: UUID, target: UUID, ticket: str, correlation: UUID
    ) -> RecoveryUser | None:
        del actor, ticket, correlation
        return self.user if target == self.user.user_id else None

    async def suspend_user(
        self, actor: UUID, target: UUID, ticket: str, reason: str, correlation: UUID
    ) -> RecoveryUser | None:
        del actor, ticket, reason, correlation
        return self.user if target == self.user.user_id else None

    async def initiate_mfa_reset(
        self,
        actor: UUID,
        target: UUID,
        ticket: str,
        execute_after: datetime,
        correlation: UUID,
    ) -> tuple[GovernedResetRecord, RecoveryUser] | None:
        del actor, target, ticket, execute_after, correlation
        return self.governed, self.user

    async def approve_mfa_reset(
        self, actor: UUID, request_id: UUID, now: datetime, correlation: UUID
    ) -> GovernedResetRecord | None:
        del actor, request_id, now, correlation
        return self.governed

    async def get_mfa_reset(self, request_id: UUID) -> GovernedResetRecord | None:
        del request_id
        return self.governed

    async def execute_mfa_reset(
        self, actor: UUID, request_id: UUID, now: datetime, correlation: UUID
    ) -> tuple[GovernedResetRecord, RecoveryUser] | None:
        del actor, request_id, now, correlation
        return self.governed, self.user


def claims(user_id: UUID, strong: bool = True) -> AccessClaims:
    now = datetime.now(UTC)
    return AccessClaims(
        user_id,
        uuid4(),
        uuid4(),
        uuid4(),
        now,
        now + timedelta(minutes=15),
        ClientType.WEB,
        ("totp",) if strong else ("password",),
    )


def build_recovery() -> tuple[
    RecoveryControl, FakeRecoveryRepository, FakeNotifications, FakeSessionRevoker
]:
    repository = FakeRecoveryRepository()
    notifications = FakeNotifications()
    revoker = FakeSessionRevoker()
    control = RecoveryControl(
        repository,
        FakeHasher(),
        FakeBreachProvider(),
        notifications,
        FakeRateStore(),
        revoker,
        "https://grox.test/reset-password",
        b"recovery-test-pepper",
        b"otp-test-pepper",
    )
    return control, repository, notifications, revoker


@pytest.mark.asyncio
async def test_unknown_password_reset_request_is_generic() -> None:
    control, repository, notifications, _ = build_recovery()

    await control.request_password_reset("unknown@example.com", uuid4())

    assert repository.issued_hash == ""
    assert notifications.reset_url == ""


@pytest.mark.asyncio
async def test_password_reset_token_is_hashed_and_raw_value_only_enters_link() -> None:
    control, repository, notifications, _ = build_recovery()

    await control.request_password_reset("PERSON@example.com", uuid4())

    raw_token = notifications.reset_url.split("token=", 1)[1]
    assert raw_token not in repository.issued_hash
    assert len(repository.issued_hash) == 64


@pytest.mark.asyncio
async def test_successful_password_reset_revokes_sessions_and_notifies_user() -> None:
    control, repository, notifications, revoker = build_recovery()

    await control.reset_password(
        "valid-token-value-long-enough", "Unique secure phrase 2026!", uuid4()
    )

    assert revoker.revocations == [(repository.user.user_id, "password_reset")]
    assert notifications.changed == ["person@example.com"]


@pytest.mark.asyncio
async def test_recent_password_cannot_be_reused() -> None:
    control, repository, _, revoker = build_recovery()
    repository.reset_outcome = PasswordResetOutcome.REUSED

    with pytest.raises(RecoveryError) as raised:
        await control.reset_password(
            "valid-token-value-long-enough", "Unique secure phrase 2026!", uuid4()
        )

    assert raised.value.code is RecoveryErrorCode.PASSWORD_REUSED
    assert revoker.revocations == []


@pytest.mark.asyncio
async def test_contact_change_requires_recent_mfa() -> None:
    control, repository, _, _ = build_recovery()

    with pytest.raises(RecoveryError) as raised:
        await control.start_contact_change(
            claims(repository.user.user_id, strong=False),
            ContactType.EMAIL,
            "new@example.com",
            uuid4(),
        )

    assert raised.value.code is RecoveryErrorCode.RECENT_MFA_REQUIRED


@pytest.mark.asyncio
async def test_contact_change_requires_both_codes_before_revoking_sessions() -> None:
    control, repository, notifications, revoker = build_recovery()
    actor = claims(repository.user.user_id)
    started = await control.start_contact_change(
        actor, ContactType.EMAIL, "new@example.com", uuid4()
    )
    old_code = next(
        code for _, code, proof in notifications.contact_codes if proof is ContactProof.OLD
    )
    new_code = next(
        code for _, code, proof in notifications.contact_codes if proof is ContactProof.NEW
    )

    first = await control.verify_contact_change(
        actor, started.request_id, ContactProof.OLD, old_code, uuid4()
    )
    assert first.applied_at is None
    assert revoker.revocations == []
    completed = await control.verify_contact_change(
        actor, started.request_id, ContactProof.NEW, new_code, uuid4()
    )

    assert completed.applied_at is not None
    assert revoker.revocations == [(repository.user.user_id, "contact_change")]


@pytest.mark.asyncio
async def test_admin_action_requires_database_backed_role() -> None:
    repository = FakeRecoveryRepository()
    control = SupportAdminControl(
        repository,
        FakeNotifications(),
        FakeSessionRevoker(),
        "https://grox.test/reset-password",
        b"recovery-test-pepper",
    )

    with pytest.raises(RecoveryError) as raised:
        await control.unlock(
            claims(uuid4()), repository.user.user_id, "TICKET-1", uuid4()
        )

    assert raised.value.code is RecoveryErrorCode.STAFF_FORBIDDEN


@pytest.mark.asyncio
async def test_account_suspension_revokes_all_access() -> None:
    repository = FakeRecoveryRepository()
    repository.roles = {StaffRole.ACCOUNT_ADMIN}
    revoker = FakeSessionRevoker()
    control = SupportAdminControl(
        repository,
        FakeNotifications(),
        revoker,
        "https://grox.test/reset-password",
        b"recovery-test-pepper",
    )

    await control.suspend(
        claims(uuid4()), repository.user.user_id, "TICKET-3", "verified fraud", uuid4()
    )

    assert revoker.revocations == [(repository.user.user_id, "account_suspended")]


@pytest.mark.asyncio
async def test_support_recovery_issues_hashed_single_use_link() -> None:
    repository = FakeRecoveryRepository()
    repository.roles = {StaffRole.SUPPORT_AGENT_L2}
    notifications = FakeNotifications()
    control = SupportAdminControl(
        repository,
        notifications,
        FakeSessionRevoker(),
        "https://grox.test/reset-password",
        b"recovery-test-pepper",
    )

    await control.support_recovery(
        claims(uuid4()),
        repository.user.user_id,
        "TICKET-4",
        "verification-checklist-9",
        uuid4(),
    )

    raw_token = notifications.reset_url.split("token=", 1)[1]
    assert raw_token not in repository.issued_hash
    assert len(repository.issued_hash) == 64


@pytest.mark.asyncio
async def test_governed_mfa_reset_uses_separate_staff_roles_and_revokes_sessions() -> None:
    repository = FakeRecoveryRepository()
    repository.roles = {StaffRole.SUPPORT_AGENT_L2, StaffRole.SECURITY_SUPERVISOR_L3}
    notifications = FakeNotifications()
    revoker = FakeSessionRevoker()
    control = SupportAdminControl(
        repository,
        notifications,
        revoker,
        "https://grox.test/reset-password",
        b"recovery-test-pepper",
    )
    actor = claims(uuid4())

    initiated = await control.initiate_mfa_reset(
        actor, repository.user.user_id, "TICKET-2", uuid4()
    )
    await control.approve_mfa_reset(actor, initiated.request_id, uuid4())
    await control.execute_mfa_reset(actor, initiated.request_id, uuid4())

    assert notifications.mfa_requested is True
    assert notifications.mfa_completed is True
    assert revoker.revocations == [(repository.user.user_id, "governed_mfa_reset")]
