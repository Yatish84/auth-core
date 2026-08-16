from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from auth_core.control.workspace import WorkspaceControl
from auth_core.entity.session import AccessClaims
from auth_core.entity.workspace import (
    InvitationRecord,
    MemberSummary,
    OffboardResult,
    OrganizationRole,
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
        self.organization = WorkspaceSummary(
            uuid4(), "Example Organization", "example-org", WorkspaceType.ORGANIZATION, ("OWNER",)
        )
        self.revoked_invitation: UUID | None = None

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

    async def get_workspace_access(
        self, user_id: UUID, workspace_id: UUID
    ) -> WorkspaceSummary | None:
        del user_id
        return self.organization if workspace_id == self.organization.workspace_id else None

    async def create_organization_invitation(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        invitee_email: str,
        role: OrganizationRole,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> InvitationRecord | None:
        del actor_user_id, correlation_id
        self.last_token_hash = token_hash
        return InvitationRecord(
            uuid4(),
            workspace_id,
            invitee_email,
            role,
            "pending",
            datetime.now(UTC),
            expires_at,
        )

    async def revoke_organization_invitation(
        self, actor_user_id: UUID, workspace_id: UUID, invitation_id: UUID
    ) -> None:
        del actor_user_id, workspace_id
        self.revoked_invitation = invitation_id

    async def accept_organization_invitation(
        self,
        user_id: UUID,
        token_hash: str,
        now: datetime,
        correlation_id: UUID,
    ) -> WorkspaceSummary | None:
        del user_id, token_hash, now, correlation_id
        return self.organization

    async def list_members(
        self, actor_user_id: UUID, workspace_id: UUID
    ) -> tuple[MemberSummary, ...] | None:
        del actor_user_id, workspace_id
        return ()

    async def replace_member_role(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        member_user_id: UUID,
        role: OrganizationRole,
        now: datetime,
        correlation_id: UUID,
    ) -> MemberSummary | None:
        del actor_user_id, workspace_id, now, correlation_id
        return MemberSummary(member_user_id, None, None, None, (role,))

    async def offboard_member(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        member_user_id: UUID,
        now: datetime,
        correlation_id: UUID,
    ) -> OffboardResult | None:
        del actor_user_id, workspace_id, now, correlation_id
        return OffboardResult(member_user_id, (uuid4(),))


class CapturingNotifications:
    def __init__(self) -> None:
        self.email = ""
        self.url = ""

    async def send_referral(self, email: str, referral_url: str) -> None:
        self.email = email
        self.url = referral_url

    async def send_organization_invitation(
        self, email: str, organization_name: str, invitation_url: str
    ) -> None:
        del organization_name
        self.email = email
        self.url = invitation_url


class FakeRateStore:
    async def increment_rate_limit(self, route: str, subject: str, window: int) -> int:
        del route, subject, window
        return 1


class FakeTokenIssuer:
    def __init__(self) -> None:
        self.revoked_user: UUID | None = None

    async def issue_workspace_scope(
        self,
        claims: AccessClaims,
        workspace: WorkspaceSummary,
        correlation_id: UUID,
    ) -> tuple[str, datetime]:
        del claims, workspace, correlation_id
        return "scoped-token", datetime.now(UTC) + timedelta(minutes=15)

    async def revoke_organization_access(
        self,
        user_id: UUID,
        workspace_id: UUID,
        access_jtis: tuple[UUID, ...],
    ) -> None:
        del workspace_id, access_jtis
        self.revoked_user = user_id

    async def restore_organization_access(
        self, user_id: UUID, workspace_id: UUID
    ) -> None:
        del user_id, workspace_id


def build_control() -> tuple[
    WorkspaceControl, FakeWorkspaceRepository, CapturingNotifications, FakeTokenIssuer
]:
    repository = FakeWorkspaceRepository()
    notifications = CapturingNotifications()
    token_issuer = FakeTokenIssuer()
    control = WorkspaceControl(
        repository,
        notifications,
        FakeRateStore(),
        "https://grox.test/signup",
        b"workspace-test-pepper",
        token_issuer,
        "https://grox.test/organization-invitation",
    )
    return control, repository, notifications, token_issuer


@pytest.mark.asyncio
async def test_personal_workspace_is_always_listed() -> None:
    control, repository, _, _ = build_control()

    result = await control.list_workspaces(repository.user_id)

    assert result == (repository.personal,)
    assert result[0].workspace_type is WorkspaceType.PERSONAL


@pytest.mark.asyncio
async def test_referral_sends_opaque_link_and_tracks_no_login_activity() -> None:
    control, repository, notifications, _ = build_control()

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
    control, repository, _, _ = build_control()
    repository.eligibility = ReferralEligibility.SELF

    with pytest.raises(WorkspaceError) as raised:
        await control.invite_referral(repository.user_id, "self@example.com", uuid4())

    assert raised.value.code is WorkspaceErrorCode.REFERRAL_INELIGIBLE


@pytest.mark.asyncio
async def test_organization_invitation_uses_approved_role_and_opaque_token() -> None:
    control, repository, notifications, _ = build_control()

    invitation = await control.invite_organization_member(
        repository.user_id,
        repository.organization.workspace_id,
        "teammate@example.com",
        OrganizationRole.MEMBER,
        uuid4(),
    )

    raw_token = notifications.url.split("invitation_token=", 1)[1]
    assert invitation.role is OrganizationRole.MEMBER
    assert raw_token not in repository.last_token_hash

    with pytest.raises(WorkspaceError) as raised:
        await control.invite_organization_member(
            repository.user_id,
            repository.organization.workspace_id,
            "owner@example.com",
            OrganizationRole.OWNER,
            uuid4(),
        )
    assert raised.value.code is WorkspaceErrorCode.INVALID


@pytest.mark.asyncio
async def test_offboarding_revokes_only_target_organization_access() -> None:
    control, repository, _, token_issuer = build_control()
    member_user_id = uuid4()

    await control.offboard_member(
        repository.user_id,
        repository.organization.workspace_id,
        member_user_id,
        uuid4(),
    )

    assert token_issuer.revoked_user == member_user_id
