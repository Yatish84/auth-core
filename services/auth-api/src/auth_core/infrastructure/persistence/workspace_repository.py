from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import distinct, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_core.entity.user import normalize_email
from auth_core.entity.workspace import (
    InvitationRecord,
    LastOwnerError,
    MemberSummary,
    OffboardResult,
    OrganizationRole,
    ReferralEligibility,
    ReferralRecord,
    WorkspaceSummary,
    WorkspaceType,
)
from auth_core.infrastructure.persistence.models import (
    AuditLog,
    Invitation,
    Organization,
    Referral,
    RolePermissionCatalog,
    Session,
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
        active_membership = func.auth.user_has_org_membership(
            Organization.org_id, user_id
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
                roles: tuple[str, ...]
                if workspace.workspace_type == "personal":
                    roles = ("OWNER",)
                else:
                    await set_tenant_context(session, user_id, workspace.org_id)
                    roles = await self._roles(session, user_id, workspace.org_id)
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

    async def get_workspace_access(
        self, user_id: UUID, workspace_id: UUID
    ) -> WorkspaceSummary | None:
        async with self._sessions() as session:
            await set_user_context(session, user_id)
            workspace = await session.get(Organization, workspace_id)
            if workspace is None or workspace.state != "active":
                return None
            if workspace.workspace_type == WorkspaceType.PERSONAL.value:
                if workspace.personal_owner_user_id != user_id:
                    return None
                return self._workspace_summary(workspace, ("OWNER",))
            await set_tenant_context(session, user_id, workspace_id)
            roles = await self._roles(session, user_id, workspace_id)
            return self._workspace_summary(workspace, roles) if roles else None

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
        async with self._sessions.begin() as session:
            await set_tenant_context(session, actor_user_id, workspace_id)
            workspace = await session.get(Organization, workspace_id)
            if (
                workspace is None
                or workspace.workspace_type != WorkspaceType.ORGANIZATION.value
                or not await self._has_permission(
                    session, actor_user_id, workspace_id, "members.manage"
                )
            ):
                return None
            normalized_email = normalize_email(invitee_email)
            existing_user_id = await session.scalar(
                select(User.user_id).where(
                    User.email == normalized_email,
                    User.anonymized_at.is_(None),
                )
            )
            if existing_user_id is not None and await self._roles(
                session, existing_user_id, workspace_id
            ):
                return None
            await session.execute(
                update(Invitation)
                .where(
                    Invitation.org_id == workspace_id,
                    Invitation.invitee_email == normalized_email,
                    Invitation.state == "pending",
                )
                .values(state="revoked")
            )
            invitation = Invitation(
                org_id=workspace_id,
                invitee_email=normalized_email,
                token_hash=token_hash,
                proposed_roles=[{"role": role.value}],
                issued_by_user_id=actor_user_id,
                expires_at=expires_at,
            )
            session.add(invitation)
            await session.flush()
            session.add(
                self._audit(
                    "ORGANIZATION_INVITATION_CREATED",
                    correlation_id,
                    actor_user_id,
                    workspace_id,
                    {"invitation_id": str(invitation.invitation_id), "role": role.value},
                )
            )
            return self._invitation_record(invitation)

    async def revoke_organization_invitation(
        self, actor_user_id: UUID, workspace_id: UUID, invitation_id: UUID
    ) -> None:
        async with self._sessions.begin() as session:
            await set_tenant_context(session, actor_user_id, workspace_id)
            await session.execute(
                update(Invitation)
                .where(
                    Invitation.invitation_id == invitation_id,
                    Invitation.org_id == workspace_id,
                    Invitation.issued_by_user_id == actor_user_id,
                    Invitation.state == "pending",
                )
                .values(state="revoked")
            )

    async def accept_organization_invitation(
        self,
        user_id: UUID,
        token_hash: str,
        now: datetime,
        correlation_id: UUID,
    ) -> WorkspaceSummary | None:
        async with self._sessions.begin() as session:
            await set_user_context(session, user_id)
            workspace_id = await session.scalar(
                text("SELECT auth.organization_invitation_org(:token_hash)"),
                {"token_hash": token_hash},
            )
            if workspace_id is None:
                return None
            await set_tenant_context(session, user_id, workspace_id)
            invitation = await session.scalar(
                select(Invitation)
                .where(Invitation.token_hash == token_hash)
                .with_for_update()
            )
            user = await session.get(User, user_id)
            if (
                invitation is None
                or user is None
                or user.state != "active"
                or user.email is None
                or invitation.state != "pending"
                or invitation.expires_at <= now
                or normalize_email(user.email) != normalize_email(invitation.invitee_email)
            ):
                return None
            role_value = (
                str(invitation.proposed_roles[0].get("role", ""))
                if invitation.proposed_roles
                else ""
            )
            try:
                role = OrganizationRole(role_value)
            except ValueError:
                return None
            if role not in {OrganizationRole.MEMBER, OrganizationRole.VIEWER}:
                return None
            if await self._roles(session, user_id, invitation.org_id):
                return None
            catalog = await self._catalog_for_role(session, role)
            if not catalog:
                return None
            session.add_all(
                UserRoleBinding(
                    user_id=user_id,
                    org_id=invitation.org_id,
                    catalog_id=item.catalog_id,
                    granted_by_user_id=invitation.issued_by_user_id,
                )
                for item in catalog
            )
            invitation.state = "accepted"
            invitation.accepted_at = now
            workspace = await session.get(Organization, invitation.org_id)
            if workspace is None:
                return None
            session.add(
                self._audit(
                    "ORGANIZATION_INVITATION_ACCEPTED",
                    correlation_id,
                    user_id,
                    invitation.org_id,
                    {"invitation_id": str(invitation.invitation_id), "role": role.value},
                )
            )
            return self._workspace_summary(workspace, (role.value,))

    async def list_members(
        self, actor_user_id: UUID, workspace_id: UUID
    ) -> tuple[MemberSummary, ...] | None:
        async with self._sessions() as session:
            await set_tenant_context(session, actor_user_id, workspace_id)
            if not await self._has_permission(
                session, actor_user_id, workspace_id, "members.manage"
            ):
                return None
            rows = (
                await session.execute(
                    select(User, RolePermissionCatalog.role)
                    .join(UserRoleBinding, UserRoleBinding.user_id == User.user_id)
                    .join(
                        RolePermissionCatalog,
                        RolePermissionCatalog.catalog_id == UserRoleBinding.catalog_id,
                    )
                    .where(
                        UserRoleBinding.org_id == workspace_id,
                        UserRoleBinding.revoked_at.is_(None),
                        RolePermissionCatalog.active.is_(True),
                    )
                    .distinct()
                    .order_by(User.created_at, RolePermissionCatalog.role)
                )
            ).all()
            grouped: dict[UUID, tuple[User, set[OrganizationRole]]] = {}
            for user, role_value in rows:
                role = OrganizationRole(str(role_value))
                if user.user_id not in grouped:
                    grouped[user.user_id] = (user, set())
                grouped[user.user_id][1].add(role)
            return tuple(
                self._member_summary(user, roles)
                for user, roles in grouped.values()
            )

    async def replace_member_role(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        member_user_id: UUID,
        role: OrganizationRole,
        now: datetime,
        correlation_id: UUID,
    ) -> MemberSummary | None:
        async with self._sessions.begin() as session:
            await set_tenant_context(session, actor_user_id, workspace_id)
            if not await self._has_permission(
                session, actor_user_id, workspace_id, "members.manage"
            ):
                return None
            current_roles = await self._roles(session, member_user_id, workspace_id)
            if not current_roles:
                return None
            if "OWNER" in current_roles and role is not OrganizationRole.OWNER:
                if await self._owner_count(session, workspace_id) <= 1:
                    raise LastOwnerError
            catalog = await self._catalog_for_role(session, role)
            if not catalog:
                return None
            await session.execute(
                update(UserRoleBinding)
                .where(
                    UserRoleBinding.user_id == member_user_id,
                    UserRoleBinding.org_id == workspace_id,
                    UserRoleBinding.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            session.add_all(
                UserRoleBinding(
                    user_id=member_user_id,
                    org_id=workspace_id,
                    catalog_id=item.catalog_id,
                    granted_by_user_id=actor_user_id,
                    granted_at=now,
                )
                for item in catalog
            )
            user = await session.get(User, member_user_id)
            if user is None:
                return None
            session.add(
                self._audit(
                    "ORGANIZATION_MEMBER_ROLE_REPLACED",
                    correlation_id,
                    actor_user_id,
                    workspace_id,
                    {"member_user_id": str(member_user_id), "role": role.value},
                )
            )
            return self._member_summary(user, {role})

    async def offboard_member(
        self,
        actor_user_id: UUID,
        workspace_id: UUID,
        member_user_id: UUID,
        now: datetime,
        correlation_id: UUID,
    ) -> OffboardResult | None:
        async with self._sessions.begin() as session:
            await set_tenant_context(session, actor_user_id, workspace_id)
            if not await self._has_permission(
                session, actor_user_id, workspace_id, "members.manage"
            ):
                return None
            current_roles = await self._roles(session, member_user_id, workspace_id)
            if not current_roles:
                return None
            if "OWNER" in current_roles and await self._owner_count(session, workspace_id) <= 1:
                raise LastOwnerError
            await session.execute(
                update(UserRoleBinding)
                .where(
                    UserRoleBinding.user_id == member_user_id,
                    UserRoleBinding.org_id == workspace_id,
                    UserRoleBinding.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            active_sessions = (
                await session.scalars(
                    select(Session)
                    .where(
                        Session.user_id == member_user_id,
                        Session.org_id == workspace_id,
                        Session.revoked_at.is_(None),
                    )
                    .with_for_update()
                )
            ).all()
            access_jtis: list[UUID] = []
            for active_session in active_sessions:
                access_jtis.append(active_session.access_jti)
                active_session.org_id = None
                active_session.access_jti = uuid4()
                active_session.last_activity_at = now
            session.add(
                self._audit(
                    "ORGANIZATION_MEMBER_OFFBOARDED",
                    correlation_id,
                    actor_user_id,
                    workspace_id,
                    {
                        "member_user_id": str(member_user_id),
                        "revoked_scoped_tokens": str(len(access_jtis)),
                    },
                )
            )
            return OffboardResult(member_user_id, tuple(access_jtis))

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
    async def _has_permission(
        session: AsyncSession, user_id: UUID, org_id: UUID, permission: str
    ) -> bool:
        value = await session.scalar(
            select(UserRoleBinding.binding_id)
            .join(
                RolePermissionCatalog,
                RolePermissionCatalog.catalog_id == UserRoleBinding.catalog_id,
            )
            .where(
                UserRoleBinding.user_id == user_id,
                UserRoleBinding.org_id == org_id,
                UserRoleBinding.revoked_at.is_(None),
                RolePermissionCatalog.permission == permission,
                RolePermissionCatalog.active.is_(True),
            )
            .limit(1)
        )
        return value is not None

    @staticmethod
    async def _catalog_for_role(
        session: AsyncSession, role: OrganizationRole
    ) -> tuple[RolePermissionCatalog, ...]:
        values = (
            await session.scalars(
                select(RolePermissionCatalog).where(
                    RolePermissionCatalog.role == role.value,
                    RolePermissionCatalog.active.is_(True),
                )
            )
        ).all()
        return tuple(values)

    @staticmethod
    async def _owner_count(session: AsyncSession, org_id: UUID) -> int:
        value = await session.scalar(
            select(func.count(distinct(UserRoleBinding.user_id)))
            .join(
                RolePermissionCatalog,
                RolePermissionCatalog.catalog_id == UserRoleBinding.catalog_id,
            )
            .where(
                UserRoleBinding.org_id == org_id,
                UserRoleBinding.revoked_at.is_(None),
                RolePermissionCatalog.role == OrganizationRole.OWNER.value,
                RolePermissionCatalog.active.is_(True),
            )
        )
        return int(value or 0)

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
    def _invitation_record(invitation: Invitation) -> InvitationRecord:
        role_value = (
            str(invitation.proposed_roles[0].get("role", ""))
            if invitation.proposed_roles
            else ""
        )
        return InvitationRecord(
            invitation_id=invitation.invitation_id,
            workspace_id=invitation.org_id,
            invitee_email=invitation.invitee_email,
            role=OrganizationRole(role_value),
            state=invitation.state,
            created_at=invitation.created_at,
            expires_at=invitation.expires_at,
        )

    @staticmethod
    def _member_summary(user: User, roles: set[OrganizationRole]) -> MemberSummary:
        return MemberSummary(
            user_id=user.user_id,
            email=user.email,
            given_name=user.given_name,
            family_name=user.family_name,
            roles=tuple(sorted(roles, key=lambda item: item.value)),
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
