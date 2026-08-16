import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

from auth_core.control.ports.workspace import (
    ReferralNotificationProvider,
    ReferralRateStore,
    WorkspaceRepository,
    WorkspaceTokenIssuer,
)
from auth_core.entity.session import AccessClaims
from auth_core.entity.user import normalize_email
from auth_core.entity.workspace import (
    InvitationRecord,
    LastOwnerError,
    MemberSummary,
    OrganizationRole,
    ReferralEligibility,
    ReferralRecord,
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceSummary,
)

REFERRAL_LIFETIME = timedelta(days=30)
REFERRAL_LIMIT_PER_DAY = 20
INVITATION_LIFETIME = timedelta(days=7)
ORGANIZATION_INVITATION_LIMIT_PER_DAY = 50


class WorkspaceControl:
    def __init__(
        self,
        repository: WorkspaceRepository,
        notifications: ReferralNotificationProvider,
        rate_store: ReferralRateStore,
        referral_base_url: str,
        token_pepper: bytes,
        token_issuer: WorkspaceTokenIssuer,
        invitation_base_url: str,
    ) -> None:
        self._repository = repository
        self._notifications = notifications
        self._rate_store = rate_store
        self._referral_base_url = referral_base_url.rstrip("/")
        self._token_pepper = token_pepper
        self._token_issuer = token_issuer
        self._invitation_base_url = invitation_base_url.rstrip("/")

    async def list_workspaces(self, user_id: UUID) -> tuple[WorkspaceSummary, ...]:
        await self._repository.ensure_personal_workspace(user_id)
        return await self._repository.list_workspaces(user_id)

    async def create_organization(
        self, user_id: UUID, name: str, correlation_id: UUID
    ) -> WorkspaceSummary:
        normalized_name = " ".join(name.split())
        if len(normalized_name) < 2:
            raise WorkspaceError(
                WorkspaceErrorCode.INVALID,
                "Enter a valid organization name.",
                400,
            )
        slug_base = re.sub(r"[^a-z0-9]+", "-", normalized_name.lower()).strip("-")[:70]
        slug = f"{slug_base or 'organization'}-{secrets.token_hex(4)}"
        return await self._repository.create_organization(
            user_id, normalized_name, slug, correlation_id
        )

    async def invite_referral(
        self,
        referrer_user_id: UUID,
        email: str,
        correlation_id: UUID,
    ) -> ReferralRecord:
        normalized_email = normalize_email(email)
        count = await self._rate_store.increment_rate_limit(
            "referral_invite", str(referrer_user_id), 86400
        )
        if count > REFERRAL_LIMIT_PER_DAY:
            raise WorkspaceError(
                WorkspaceErrorCode.RATE_LIMITED,
                "The daily referral limit has been reached. Please try again tomorrow.",
                429,
            )
        eligibility = await self._repository.referral_eligibility(
            referrer_user_id, normalized_email
        )
        if eligibility is not ReferralEligibility.ELIGIBLE:
            raise WorkspaceError(
                WorkspaceErrorCode.REFERRAL_INELIGIBLE,
                "This referral cannot be created.",
                409,
            )
        raw_token = secrets.token_urlsafe(32)
        token_hash = hmac.new(self._token_pepper, raw_token.encode(), sha256).hexdigest()
        referral = await self._repository.create_referral(
            referrer_user_id,
            normalized_email,
            token_hash,
            datetime.now(UTC) + REFERRAL_LIFETIME,
            correlation_id,
        )
        try:
            await self._notifications.send_referral(
                normalized_email,
                f"{self._referral_base_url}?referral_token={raw_token}",
            )
        except Exception as error:
            await self._repository.revoke_referral(
                referrer_user_id, referral.referral_id
            )
            raise WorkspaceError(
                WorkspaceErrorCode.PROVIDER_UNAVAILABLE,
                "The referral could not be delivered. Please try again.",
                503,
            ) from error
        return referral

    async def list_referrals(self, user_id: UUID) -> tuple[ReferralRecord, ...]:
        return await self._repository.list_referrals(user_id, datetime.now(UTC))

    async def invite_organization_member(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        email: str,
        role: OrganizationRole,
        correlation_id: UUID,
    ) -> InvitationRecord:
        if role not in {OrganizationRole.MEMBER, OrganizationRole.VIEWER}:
            raise WorkspaceError(
                WorkspaceErrorCode.INVALID,
                "Select an approved invitation role.",
                400,
            )
        workspace = await self._repository.get_workspace_access(actor_user_id, workspace_id)
        if workspace is None or "OWNER" not in workspace.roles:
            raise self._forbidden()
        normalized_email = normalize_email(email)
        count = await self._rate_store.increment_rate_limit(
            "organization_invite", f"{actor_user_id}:{workspace_id}", 86400
        )
        if count > ORGANIZATION_INVITATION_LIMIT_PER_DAY:
            raise WorkspaceError(
                WorkspaceErrorCode.RATE_LIMITED,
                "The daily organization invitation limit has been reached.",
                429,
            )
        raw_token = secrets.token_urlsafe(32)
        token_hash = hmac.new(self._token_pepper, raw_token.encode(), sha256).hexdigest()
        invitation = await self._repository.create_organization_invitation(
            actor_user_id,
            workspace_id,
            normalized_email,
            role,
            token_hash,
            datetime.now(UTC) + INVITATION_LIFETIME,
            correlation_id,
        )
        if invitation is None:
            raise self._forbidden()
        try:
            await self._notifications.send_organization_invitation(
                normalized_email,
                workspace.name,
                f"{self._invitation_base_url}?invitation_token={raw_token}",
            )
        except Exception as error:
            await self._repository.revoke_organization_invitation(
                actor_user_id, workspace_id, invitation.invitation_id
            )
            raise WorkspaceError(
                WorkspaceErrorCode.PROVIDER_UNAVAILABLE,
                "The organization invitation could not be delivered. Please try again.",
                503,
            ) from error
        return invitation

    async def accept_organization_invitation(
        self, user_id: UUID, token: str, correlation_id: UUID
    ) -> WorkspaceSummary:
        token_hash = hmac.new(self._token_pepper, token.encode(), sha256).hexdigest()
        workspace = await self._repository.accept_organization_invitation(
            user_id, token_hash, datetime.now(UTC), correlation_id
        )
        if workspace is None:
            raise WorkspaceError(
                WorkspaceErrorCode.INVITATION_INVALID,
                "This invitation is invalid, expired, or cannot be accepted by this account.",
                400,
            )
        await self._token_issuer.restore_organization_access(
            user_id, workspace.workspace_id
        )
        return workspace

    async def list_members(
        self, actor_user_id: UUID, workspace_id: UUID
    ) -> tuple[MemberSummary, ...]:
        members = await self._repository.list_members(actor_user_id, workspace_id)
        if members is None:
            raise self._forbidden()
        return members

    async def replace_member_role(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        member_user_id: UUID,
        role: OrganizationRole,
        correlation_id: UUID,
    ) -> MemberSummary:
        try:
            member = await self._repository.replace_member_role(
                actor_user_id,
                workspace_id,
                member_user_id,
                role,
                datetime.now(UTC),
                correlation_id,
            )
        except LastOwnerError as error:
            raise self._last_owner() from error
        if member is None:
            raise self._forbidden()
        return member

    async def offboard_member(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        member_user_id: UUID,
        correlation_id: UUID,
    ) -> None:
        try:
            result = await self._repository.offboard_member(
                actor_user_id,
                workspace_id,
                member_user_id,
                datetime.now(UTC),
                correlation_id,
            )
        except LastOwnerError as error:
            raise self._last_owner() from error
        if result is None:
            raise self._forbidden()
        await self._token_issuer.revoke_organization_access(
            result.user_id, workspace_id, result.revoked_access_jtis
        )

    async def switch_workspace(
        self,
        claims: AccessClaims,
        workspace_id: UUID,
        correlation_id: UUID,
    ) -> tuple[str, datetime, WorkspaceSummary]:
        workspace = await self._repository.get_workspace_access(
            claims.user_id, workspace_id
        )
        if workspace is None:
            raise self._forbidden()
        token, expires_at = await self._token_issuer.issue_workspace_scope(
            claims, workspace, correlation_id
        )
        return token, expires_at, workspace

    @staticmethod
    def _forbidden() -> WorkspaceError:
        return WorkspaceError(
            WorkspaceErrorCode.FORBIDDEN,
            "You do not have permission to perform this workspace operation.",
            403,
        )

    @staticmethod
    def _last_owner() -> WorkspaceError:
        return WorkspaceError(
            WorkspaceErrorCode.LAST_OWNER,
            "Transfer ownership before removing or changing the last owner.",
            409,
        )
