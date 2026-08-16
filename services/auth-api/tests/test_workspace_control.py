from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from auth_core.control.workspace import WorkspaceControl
from auth_core.entity.workspace import (
    ReferralEligibility,
    ReferralRecord,
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceSummary,
    WorkspaceType,
)


class FakeWorkspaceRepository:
    def __init__(self) -> None:
        self.user_id = uuid4()
        self.personal = WorkspaceSummary(
            uuid4(), "My Personal Portfolio", "personal-test", WorkspaceType.PERSONAL, ("OWNER",)
        )
        self.referrals: list[ReferralRecord] = []
        self.eligibility = ReferralEligibility.ELIGIBLE
        self.last_token_hash = ""

    async def ensure_personal_workspace(self, user_id: UUID) -> WorkspaceSummary:
        assert user_id == self.user_id
        return self.personal

    async def list_workspaces(self, user_id: UUID) -> tuple[WorkspaceSummary, ...]:
        assert user_id == self.user_id
        return (self.personal,)

    async def create_organization(
        self, user_id: UUID, name: str, slug: str, correlation_id: UUID
    ) -> WorkspaceSummary:
        del correlation_id
        assert user_id == self.user_id
        return WorkspaceSummary(uuid4(), name, slug, WorkspaceType.ORGANIZATION, ("OWNER",))

    async def referral_eligibility(
        self, referrer_user_id: UUID, invitee_email: str
    ) -> ReferralEligibility:
        del referrer_user_id, invitee_email
        return self.eligibility

    async def create_referral(
        self,
        referrer_user_id: UUID,
        invitee_email: str,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> ReferralRecord:
        del referrer_user_id, correlation_id
        self.last_token_hash = token_hash
        referral = ReferralRecord(
            uuid4(),
            invitee_email,
            "invited",
            datetime.now(UTC),
            expires_at,
            None,
            None,
        )
        self.referrals.append(referral)
        return referral

    async def revoke_referral(self, referrer_user_id: UUID, referral_id: UUID) -> None:
        del referrer_user_id, referral_id

    async def list_referrals(
        self, referrer_user_id: UUID, now: datetime
    ) -> tuple[ReferralRecord, ...]:
        del referrer_user_id, now
        return tuple(self.referrals)


class CapturingNotifications:
    def __init__(self) -> None:
        self.email = ""
        self.url = ""

    async def send_referral(self, email: str, referral_url: str) -> None:
        self.email = email
        self.url = referral_url


class FakeRateStore:
    async def increment_rate_limit(self, route: str, subject: str, window: int) -> int:
        del route, subject, window
        return 1


def build_control() -> tuple[WorkspaceControl, FakeWorkspaceRepository, CapturingNotifications]:
    repository = FakeWorkspaceRepository()
    notifications = CapturingNotifications()
    control = WorkspaceControl(
        repository,
        notifications,
        FakeRateStore(),
        "https://grox.test/signup",
        b"workspace-test-pepper",
    )
    return control, repository, notifications


@pytest.mark.asyncio
async def test_personal_workspace_is_always_listed() -> None:
    control, repository, _ = build_control()

    result = await control.list_workspaces(repository.user_id)

    assert result == (repository.personal,)
    assert result[0].workspace_type is WorkspaceType.PERSONAL


@pytest.mark.asyncio
async def test_referral_sends_opaque_link_and_tracks_no_login_activity() -> None:
    control, repository, notifications = build_control()

    result = await control.invite_referral(
        repository.user_id, " Friend@Example.com ", uuid4()
    )

    raw_token = notifications.url.split("referral_token=", 1)[1]
    assert notifications.email == "friend@example.com"
    assert raw_token not in repository.last_token_hash
    assert result.registered_at is None
    assert result.verified_at is None
    assert result.expires_at > datetime.now(UTC) + timedelta(days=29)


@pytest.mark.asyncio
async def test_self_or_existing_user_referral_is_rejected_generically() -> None:
    control, repository, _ = build_control()
    repository.eligibility = ReferralEligibility.SELF

    with pytest.raises(WorkspaceError) as raised:
        await control.invite_referral(repository.user_id, "self@example.com", uuid4())

    assert raised.value.code is WorkspaceErrorCode.REFERRAL_INELIGIBLE
