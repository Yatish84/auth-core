from datetime import datetime
from typing import Protocol
from uuid import UUID

from auth_core.entity.workspace import (
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


class ReferralNotificationProvider(Protocol):
    async def send_referral(self, email: str, referral_url: str) -> None: ...


class ReferralRateStore(Protocol):
    async def increment_rate_limit(self, route: str, subject: str, window: int) -> int: ...
