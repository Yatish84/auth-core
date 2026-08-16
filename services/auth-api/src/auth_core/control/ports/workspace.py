from datetime import datetime
from typing import Protocol
from uuid import UUID

from auth_core.entity.session import AccessClaims
from auth_core.entity.workspace import (
    InvitationRecord,
    MemberSummary,
    OffboardResult,
    OrganizationRole,
    ReferralEligibility,
    ReferralRecord,
    WorkspaceSummary,
)


class WorkspaceRepository(Protocol):
    async def ensure_personal_workspace(self, user_id: UUID) -> WorkspaceSummary: ...

    async def list_workspaces(self, user_id: UUID) -> tuple[WorkspaceSummary, ...]: ...

    async def create_organization(
        self, user_id: UUID, name: str, slug: str, correlation_id: UUID
    ) -> WorkspaceSummary: ...

    async def referral_eligibility(
        self, referrer_user_id: UUID, invitee_email: str
    ) -> ReferralEligibility: ...

    async def create_referral(
        self,
        referrer_user_id: UUID,
        invitee_email: str,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> ReferralRecord: ...

    async def revoke_referral(self, referrer_user_id: UUID, referral_id: UUID) -> None: ...

    async def list_referrals(
        self, referrer_user_id: UUID, now: datetime
    ) -> tuple[ReferralRecord, ...]: ...

    async def get_workspace_access(
        self, user_id: UUID, workspace_id: UUID
    ) -> WorkspaceSummary | None: ...

    async def create_organization_invitation(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        invitee_email: str,
        role: OrganizationRole,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> InvitationRecord | None: ...

    async def revoke_organization_invitation(
        self, actor_user_id: UUID, workspace_id: UUID, invitation_id: UUID
    ) -> None: ...

    async def accept_organization_invitation(
        self,
        user_id: UUID,
        token_hash: str,
        now: datetime,
        correlation_id: UUID,
    ) -> WorkspaceSummary | None: ...

    async def list_members(
        self, actor_user_id: UUID, workspace_id: UUID
    ) -> tuple[MemberSummary, ...] | None: ...

    async def replace_member_role(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        member_user_id: UUID,
        role: OrganizationRole,
        now: datetime,
        correlation_id: UUID,
    ) -> MemberSummary | None: ...

    async def offboard_member(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        member_user_id: UUID,
        now: datetime,
        correlation_id: UUID,
    ) -> OffboardResult | None: ...


class ReferralNotificationProvider(Protocol):
    async def send_referral(self, email: str, referral_url: str) -> None: ...

    async def send_organization_invitation(
        self, email: str, organization_name: str, invitation_url: str
    ) -> None: ...


class ReferralRateStore(Protocol):
    async def increment_rate_limit(self, route: str, subject: str, window: int) -> int: ...


class WorkspaceTokenIssuer(Protocol):
    async def issue_workspace_scope(
        self,
        claims: AccessClaims,
        workspace: WorkspaceSummary,
        correlation_id: UUID,
    ) -> tuple[str, datetime]: ...

    async def revoke_organization_access(
        self,
        user_id: UUID,
        workspace_id: UUID,
        access_jtis: tuple[UUID, ...],
    ) -> None: ...

    async def restore_organization_access(
        self, user_id: UUID, workspace_id: UUID
    ) -> None: ...
