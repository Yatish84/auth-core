from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import exists, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_core.entity.user import normalize_email
from auth_core.entity.workspace import (
    ReferralEligibility,
    ReferralRecord,
    WorkspaceSummary,
    WorkspaceType,
)
from auth_core.infrastructure.persistence.models import (
    AuditLog,
    Organization,
    Referral,
    RolePermissionCatalog,
    User,
    UserRoleBinding,
    personal_workspace_for,
)
from auth_core.infrastructure.persistence.tenant_context import (
    set_tenant_context,
    set_user_context,
)


class SqlAlchemyWorkspaceRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def ensure_personal_workspace(self, user_id: UUID) -> WorkspaceSummary:
        async with self._sessions.begin() as session:
            await set_user_context(session, user_id)
            workspace = await session.scalar(
                select(Organization)
                .where(
                    Organization.workspace_type == WorkspaceType.PERSONAL.value,
                    Organization.personal_owner_user_id == user_id,
                )
                .with_for_update()
            )
            if workspace is None:
                user = await session.get(User, user_id)
                if user is None or user.anonymized_at is not None:
                    raise LookupError("active user not found")
                workspace = personal_workspace_for(user)
                session.add(workspace)
                await session.flush()
            return self._workspace_summary(workspace, ("OWNER",))

    async def list_workspaces(self, user_id: UUID) -> tuple[WorkspaceSummary, ...]:
        active_membership = exists(
            select(UserRoleBinding.binding_id).where(
                UserRoleBinding.org_id == Organization.org_id,
                UserRoleBinding.user_id == user_id,
                UserRoleBinding.revoked_at.is_(None),
            )
        )
        async with self._sessions() as session:
            await set_user_context(session, user_id)
            workspaces = (
                await session.scalars(
                    select(Organization)
                    .where(
                        Organization.state == "active",
                        or_(
                            Organization.personal_owner_user_id == user_id,
                            active_membership,
                        ),
                    )
                    .order_by(Organization.workspace_type, Organization.name)
                )
            ).all()
            summaries: list[WorkspaceSummary] = []
            for workspace in workspaces:
                roles = ("OWNER",) if workspace.workspace_type == "personal" else await self._roles(
                    session, user_id, workspace.org_id
                )
                summaries.append(self._workspace_summary(workspace, roles))
            return tuple(summaries)

    async def create_organization(
        self, user_id: UUID, name: str, slug: str, correlation_id: UUID
    ) -> WorkspaceSummary:
        async with self._sessions.begin() as session:
            workspace_id = uuid4()
            await set_tenant_context(session, user_id, workspace_id)
            user = await session.get(User, user_id)
            if user is None or user.state != "active":
                raise LookupError("active user not found")
            owner_catalog = (
                await session.scalars(
                    select(RolePermissionCatalog).where(
                        RolePermissionCatalog.role == "OWNER",
                        RolePermissionCatalog.active.is_(True),
                    )
                )
            ).all()
            if not owner_catalog:
                raise RuntimeError("owner role catalog is unavailable")
            workspace = Organization(
                org_id=workspace_id,
                name=name,
                slug=slug,
                workspace_type=WorkspaceType.ORGANIZATION.value,
            )
            session.add(workspace)
            await session.flush()
            session.add_all(
                UserRoleBinding(
                    user_id=user_id,
                    org_id=workspace.org_id,
                    catalog_id=catalog.catalog_id,
                    granted_by_user_id=user_id,
                )
                for catalog in owner_catalog
            )
            session.add(
                self._audit(
                    "ORGANIZATION_CREATED",
                    correlation_id,
                    user_id,
                    workspace.org_id,
                    {"workspace_type": "organization"},
                )
            )
            return self._workspace_summary(workspace, ("OWNER",))

    async def referral_eligibility(
        self, referrer_user_id: UUID, invitee_email: str
    ) -> ReferralEligibility:
        async with self._sessions() as session:
            await set_user_context(session, referrer_user_id)
            referrer = await session.get(User, referrer_user_id)
            if referrer is None or referrer.state != "active":
                return ReferralEligibility.EXISTING_USER
            normalized = normalize_email(invitee_email)
            if referrer.email and normalize_email(referrer.email) == normalized:
                return ReferralEligibility.SELF
            existing = await session.scalar(
                select(User.user_id).where(
                    User.email == normalized,
                    User.anonymized_at.is_(None),
                )
            )
            if existing is not None:
                return ReferralEligibility.EXISTING_USER
            return ReferralEligibility.ELIGIBLE

    async def create_referral(
        self,
        referrer_user_id: UUID,
        invitee_email: str,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> ReferralRecord:
        async with self._sessions.begin() as session:
            await set_user_context(session, referrer_user_id)
            await session.execute(
                update(Referral)
                .where(
                    Referral.referrer_user_id == referrer_user_id,
                    Referral.invitee_email == normalize_email(invitee_email),
                    Referral.state == "invited",
                )
                .values(state="revoked")
            )
            referral = Referral(
                referrer_user_id=referrer_user_id,
                invitee_email=normalize_email(invitee_email),
                token_hash=token_hash,
                expires_at=expires_at,
            )
            session.add(referral)
            await session.flush()
            session.add(
                self._audit(
                    "REFERRAL_CREATED",
                    correlation_id,
                    referrer_user_id,
                    None,
                    {"referral_id": str(referral.referral_id)},
                )
            )
            return self._referral_record(referral)

    async def revoke_referral(self, referrer_user_id: UUID, referral_id: UUID) -> None:
        async with self._sessions.begin() as session:
            await set_user_context(session, referrer_user_id)
            await session.execute(
                update(Referral)
                .where(
                    Referral.referral_id == referral_id,
                    Referral.referrer_user_id == referrer_user_id,
                    Referral.state == "invited",
                )
                .values(state="revoked")
            )

    async def list_referrals(
        self, referrer_user_id: UUID, now: datetime
    ) -> tuple[ReferralRecord, ...]:
        async with self._sessions.begin() as session:
            await set_user_context(session, referrer_user_id)
            await session.execute(
                update(Referral)
                .where(
                    Referral.referrer_user_id == referrer_user_id,
                    Referral.state == "invited",
                    Referral.expires_at <= now,
                )
                .values(state="expired")
            )
            referrals = (
                await session.scalars(
                    select(Referral)
                    .where(Referral.referrer_user_id == referrer_user_id)
                    .order_by(Referral.created_at.desc())
                )
            ).all()
            return tuple(self._referral_record(item) for item in referrals)

    @staticmethod
    async def _roles(session: AsyncSession, user_id: UUID, org_id: UUID) -> tuple[str, ...]:
        roles = (
            await session.scalars(
                select(RolePermissionCatalog.role)
                .join(
                    UserRoleBinding,
                    UserRoleBinding.catalog_id == RolePermissionCatalog.catalog_id,
                )
                .where(
                    UserRoleBinding.user_id == user_id,
                    UserRoleBinding.org_id == org_id,
                    UserRoleBinding.revoked_at.is_(None),
                    RolePermissionCatalog.active.is_(True),
                )
                .distinct()
                .order_by(RolePermissionCatalog.role)
            )
        ).all()
        return tuple(roles)

    @staticmethod
    def _workspace_summary(
        workspace: Organization, roles: tuple[str, ...]
    ) -> WorkspaceSummary:
        return WorkspaceSummary(
            workspace_id=workspace.org_id,
            name=workspace.name,
            slug=workspace.slug,
            workspace_type=WorkspaceType(workspace.workspace_type),
            roles=roles,
        )

    @staticmethod
    def _referral_record(referral: Referral) -> ReferralRecord:
        return ReferralRecord(
            referral_id=referral.referral_id,
            invitee_email=referral.invitee_email,
            state=referral.state,
            created_at=referral.created_at,
            expires_at=referral.expires_at,
            registered_at=referral.registered_at,
            verified_at=referral.verified_at,
        )

    @staticmethod
    def _audit(
        event_type: str,
        correlation_id: UUID,
        actor_user_id: UUID,
        org_id: UUID | None,
        metadata: dict[str, str],
    ) -> AuditLog:
        return AuditLog(
            actor_user_id=actor_user_id,
            org_id=org_id,
            event_type=event_type,
            outcome="success",
            correlation_id=correlation_id,
            metadata_json=metadata,
        )
