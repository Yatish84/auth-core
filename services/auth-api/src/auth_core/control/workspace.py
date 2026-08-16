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
)
from auth_core.entity.user import normalize_email
from auth_core.entity.workspace import (
    ReferralEligibility,
    ReferralRecord,
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceSummary,
)

REFERRAL_LIFETIME = timedelta(days=30)
REFERRAL_LIMIT_PER_DAY = 20


class WorkspaceControl:
    def __init__(
        self,
        repository: WorkspaceRepository,
        notifications: ReferralNotificationProvider,
        rate_store: ReferralRateStore,
        referral_base_url: str,
        token_pepper: bytes,
    ) -> None:
        self._repository = repository
        self._notifications = notifications
        self._rate_store = rate_store
        self._referral_base_url = referral_base_url.rstrip("/")
        self._token_pepper = token_pepper

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
