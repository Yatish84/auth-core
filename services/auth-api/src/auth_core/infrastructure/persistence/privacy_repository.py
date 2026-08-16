import base64
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_core.entity.privacy import (
    AuditPage,
    AuditRecord,
    AuditSearchFilter,
    EncryptedExportArtifact,
    PrivacyRequestRecord,
)
from auth_core.entity.recovery import StaffRole
from auth_core.infrastructure.persistence.models import (
    AuditLog,
    ContactChangeRequest,
    EphemeralToken,
    GDPRRequest,
    Identity,
    Invitation,
    MFADevice,
    Organization,
    PrivacyExportArtifact,
    Referral,
    RefreshTokenFamily,
    RolePermissionCatalog,
    Session,
    StaffRoleBinding,
    TrustedDevice,
    User,
    UserRoleBinding,
)
from auth_core.infrastructure.persistence.tenant_context import set_user_context


class SqlAlchemyAuditRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def staff_has_role(self, user_id: UUID, role: StaffRole) -> bool:
        async with self._sessions() as database:
            binding = await database.scalar(
                select(StaffRoleBinding.binding_id).where(
                    StaffRoleBinding.user_id == user_id,
                    StaffRoleBinding.role == role.value,
                    StaffRoleBinding.revoked_at.is_(None),
                )
            )
            return binding is not None

    async def search_audit_logs(
        self,
        actor_user_id: UUID,
        filters: AuditSearchFilter,
        cursor: tuple[datetime, UUID] | None,
        limit: int,
        correlation_id: UUID,
    ) -> AuditPage:
        conditions = []
        if filters.subject_user_id:
            conditions.append(AuditLog.subject_user_id == filters.subject_user_id)
        if filters.event_type:
            conditions.append(AuditLog.event_type == filters.event_type)
        if filters.outcome:
            conditions.append(AuditLog.outcome == filters.outcome)
        if filters.occurred_from:
            conditions.append(AuditLog.occurred_at >= filters.occurred_from)
        if filters.occurred_to:
            conditions.append(AuditLog.occurred_at <= filters.occurred_to)
        if cursor:
            occurred_at, audit_id = cursor
            conditions.append(
                or_(
                    AuditLog.occurred_at < occurred_at,
                    and_(
                        AuditLog.occurred_at == occurred_at,
                        AuditLog.audit_id < audit_id,
                    ),
                )
            )

        statement = (
            select(AuditLog)
            .where(*conditions)
            .order_by(AuditLog.occurred_at.desc(), AuditLog.audit_id.desc())
            .limit(limit + 1)
        )
        async with self._sessions.begin() as database:
            await set_user_context(database, actor_user_id)
            records = list((await database.scalars(statement)).all())
            has_more = len(records) > limit
            selected = records[:limit]
            database.add(
                AuditLog(
                    actor_user_id=actor_user_id,
                    subject_user_id=filters.subject_user_id or actor_user_id,
                    event_type="AUDIT_LOGS_QUERIED",
                    outcome="success",
                    correlation_id=correlation_id,
                    metadata_json={
                        "event_filter_applied": filters.event_type is not None,
                        "outcome_filter_applied": filters.outcome is not None,
                        "subject_filter_applied": filters.subject_user_id is not None,
                        "result_count": len(selected),
                    },
                )
            )

        next_cursor = None
        if has_more and selected:
            last = selected[-1]
            next_cursor = self._encode_cursor(last.occurred_at, last.audit_id)
        return AuditPage(tuple(self._record(record) for record in selected), next_cursor)

    @staticmethod
    def _record(record: AuditLog) -> AuditRecord:
        return AuditRecord(
            record.audit_id,
            record.actor_user_id,
            record.subject_user_id,
            record.org_id,
            record.event_type,
            record.outcome,
            record.correlation_id,
            record.metadata_json,
            record.occurred_at,
        )

    @staticmethod
    def _encode_cursor(occurred_at: datetime, audit_id: UUID) -> str:
        value = f"{occurred_at.isoformat()}|{audit_id}".encode()
        return base64.urlsafe_b64encode(value).decode().rstrip("=")


class SqlAlchemyPrivacyRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def get_or_create_export(
        self,
        user_id: UUID,
        idempotency_key_hash: str,
        artifact_expires_at: datetime,
        correlation_id: UUID,
    ) -> tuple[PrivacyRequestRecord, bool]:
        async with self._sessions.begin() as database:
            await set_user_context(database, user_id)
            existing = await database.scalar(
                select(GDPRRequest).where(
                    GDPRRequest.user_id == user_id,
                    GDPRRequest.request_type == "export",
                    GDPRRequest.idempotency_key_hash == idempotency_key_hash,
                )
            )
            if existing:
                return self._request(existing), False
            request = GDPRRequest(
                user_id=user_id,
                request_type="export",
                state="processing",
                artifact_expires_at=artifact_expires_at,
                idempotency_key_hash=idempotency_key_hash,
            )
            database.add(request)
            await database.flush()
            database.add(
                AuditLog(
                    actor_user_id=user_id,
                    subject_user_id=user_id,
                    event_type="PRIVACY_EXPORT_REQUESTED",
                    outcome="success",
                    correlation_id=correlation_id,
                    metadata_json={"request_id": str(request.gdpr_request_id)},
                )
            )
            return self._request(request), True

    async def collect_export_data(self, user_id: UUID) -> dict[str, object]:
        async with self._sessions() as database:
            await set_user_context(database, user_id)
            user = await database.get(User, user_id)
            if user is None:
                return {}
            identities = (
                await database.scalars(select(Identity).where(Identity.user_id == user_id))
            ).all()
            factors = (
                await database.scalars(select(MFADevice).where(MFADevice.user_id == user_id))
            ).all()
            sessions = (
                await database.scalars(select(Session).where(Session.user_id == user_id))
            ).all()
            devices = (
                await database.scalars(
                    select(TrustedDevice).where(TrustedDevice.user_id == user_id)
                )
            ).all()
            roles = (
                await database.execute(
                    select(
                        UserRoleBinding.org_id,
                        Organization.name,
                        RolePermissionCatalog.role,
                        UserRoleBinding.granted_at,
                        UserRoleBinding.revoked_at,
                    )
                    .join(Organization, Organization.org_id == UserRoleBinding.org_id)
                    .join(
                        RolePermissionCatalog,
                        RolePermissionCatalog.catalog_id == UserRoleBinding.catalog_id,
                    )
                    .where(UserRoleBinding.user_id == user_id)
                )
            ).all()
            return {
                "generated_at": datetime.now(UTC).isoformat(),
                "profile": {
                    "user_id": str(user.user_id),
                    "email": user.email,
                    "given_name": user.given_name,
                    "family_name": user.family_name,
                    "phone_e164": user.phone_e164,
                    "state": user.state,
                    "created_at": user.created_at.isoformat(),
                    "updated_at": user.updated_at.isoformat(),
                },
                "identities": [
                    {
                        "provider": item.provider,
                        "provider_subject": item.provider_subject,
                        "verified": item.verified,
                        "created_at": item.created_at.isoformat(),
                        "last_used_at": self._time(item.last_used_at),
                    }
                    for item in identities
                ],
                "mfa_factors": [
                    {
                        "factor_type": item.factor_type,
                        "label": item.label,
                        "status": item.status,
                        "verified_at": self._time(item.verified_at),
                        "last_used_at": self._time(item.last_used_at),
                    }
                    for item in factors
                ],
                "sessions": [
                    {
                        "session_id": str(item.session_id),
                        "workspace_id": str(item.org_id) if item.org_id else None,
                        "client_id": item.client_id,
                        "device_fingerprint_hash": item.device_fingerprint_hash,
                        "ip_address": str(item.ip_address) if item.ip_address else None,
                        "created_at": item.created_at.isoformat(),
                        "last_activity_at": item.last_activity_at.isoformat(),
                        "expires_at": item.expires_at.isoformat(),
                        "revoked_at": self._time(item.revoked_at),
                    }
                    for item in sessions
                ],
                "trusted_devices": [
                    {
                        "fingerprint_hash": item.fingerprint_hash,
                        "trust_state": item.trust_state,
                        "last_ip_address": str(item.last_ip_address)
                        if item.last_ip_address
                        else None,
                        "first_seen_at": item.first_seen_at.isoformat(),
                        "last_seen_at": item.last_seen_at.isoformat(),
                    }
                    for item in devices
                ],
                "workspace_roles": [
                    {
                        "workspace_id": str(org_id),
                        "workspace_name": name,
                        "role": role,
                        "granted_at": granted_at.isoformat(),
                        "revoked_at": self._time(revoked_at),
                    }
                    for org_id, name, role, granted_at, revoked_at in roles
                ],
            }

    async def complete_export(
        self,
        request_id: UUID,
        user_id: UUID,
        encrypted_content: bytes,
        content_digest: str,
        artifact_expires_at: datetime,
        correlation_id: UUID,
    ) -> PrivacyRequestRecord:
        now = datetime.now(UTC)
        async with self._sessions.begin() as database:
            await set_user_context(database, user_id)
            request = await database.scalar(
                select(GDPRRequest)
                .where(
                    GDPRRequest.gdpr_request_id == request_id,
                    GDPRRequest.user_id == user_id,
                )
                .with_for_update()
            )
            if request is None:
                raise LookupError("Privacy request disappeared")
            database.add(
                PrivacyExportArtifact(
                    gdpr_request_id=request_id,
                    user_id=user_id,
                    encrypted_content=encrypted_content,
                    content_digest=content_digest,
                    expires_at=artifact_expires_at,
                )
            )
            request.state = "completed"
            request.completed_at = now
            request.artifact_reference = f"privacy-export:{request_id}"
            request.artifact_expires_at = artifact_expires_at
            database.add(
                AuditLog(
                    actor_user_id=user_id,
                    subject_user_id=user_id,
                    event_type="PRIVACY_EXPORT_COMPLETED",
                    outcome="success",
                    correlation_id=correlation_id,
                    metadata_json={"request_id": str(request_id)},
                )
            )
            return self._request(request)

    async def fail_export(
        self, request_id: UUID, user_id: UUID, failure_code: str
    ) -> None:
        async with self._sessions.begin() as database:
            await set_user_context(database, user_id)
            request = await database.get(GDPRRequest, request_id)
            if request and request.user_id == user_id:
                request.state = "failed"
                request.failure_code = failure_code

    async def get_privacy_request(
        self, user_id: UUID, request_id: UUID
    ) -> PrivacyRequestRecord | None:
        async with self._sessions() as database:
            await set_user_context(database, user_id)
            request = await database.scalar(
                select(GDPRRequest).where(
                    GDPRRequest.gdpr_request_id == request_id,
                    GDPRRequest.user_id == user_id,
                )
            )
            return self._request(request) if request else None

    async def get_export_artifact(
        self, user_id: UUID, request_id: UUID, now: datetime
    ) -> EncryptedExportArtifact | None:
        async with self._sessions() as database:
            await set_user_context(database, user_id)
            artifact = await database.scalar(
                select(PrivacyExportArtifact).where(
                    PrivacyExportArtifact.gdpr_request_id == request_id,
                    PrivacyExportArtifact.user_id == user_id,
                    PrivacyExportArtifact.expires_at > now,
                )
            )
            if artifact is None:
                return None
            return EncryptedExportArtifact(
                artifact.gdpr_request_id,
                artifact.encrypted_content,
                artifact.content_digest,
                artifact.expires_at,
            )

    @staticmethod
    def _request(request: GDPRRequest) -> PrivacyRequestRecord:
        return PrivacyRequestRecord(
            request.gdpr_request_id,
            request.user_id,
            request.request_type,
            request.state,
            request.requested_at,
            request.completed_at,
            request.artifact_expires_at,
            request.failure_code,
            request.backup_purge_due_at,
        )

    @staticmethod
    def _time(value: datetime | None) -> str | None:
        return value.isoformat() if value else None

    async def get_or_create_erasure(
        self,
        user_id: UUID,
        idempotency_key_hash: str,
        correlation_id: UUID,
    ) -> tuple[PrivacyRequestRecord | None, bool]:
        async with self._sessions.begin() as database:
            await set_user_context(database, user_id)
            existing = await database.scalar(
                select(GDPRRequest).where(
                    GDPRRequest.user_id == user_id,
                    GDPRRequest.request_type == "erasure",
                    GDPRRequest.idempotency_key_hash == idempotency_key_hash,
                )
            )
            if existing:
                return self._request(existing), False
            if await self._has_sole_owned_organization(database, user_id):
                return None, False
            request = GDPRRequest(
                user_id=user_id,
                request_type="erasure",
                state="processing",
                idempotency_key_hash=idempotency_key_hash,
            )
            database.add(request)
            await database.flush()
            database.add(
                AuditLog(
                    actor_user_id=user_id,
                    subject_user_id=user_id,
                    event_type="PRIVACY_ERASURE_REQUESTED",
                    outcome="success",
                    correlation_id=correlation_id,
                    metadata_json={"request_id": str(request.gdpr_request_id)},
                )
            )
            return self._request(request), True

    async def execute_erasure(
        self,
        request_id: UUID,
        user_id: UUID,
        pseudonym: str,
        now: datetime,
        backup_purge_due_at: datetime,
        correlation_id: UUID,
    ) -> PrivacyRequestRecord | None:
        async with self._sessions.begin() as database:
            await set_user_context(database, user_id)
            request = await database.scalar(
                select(GDPRRequest)
                .where(
                    GDPRRequest.gdpr_request_id == request_id,
                    GDPRRequest.user_id == user_id,
                    GDPRRequest.request_type == "erasure",
                )
                .with_for_update()
            )
            user = await database.get(User, user_id, with_for_update=True)
            if request is None or user is None:
                return None
            if request.state == "completed":
                return self._request(request)
            if await self._has_sole_owned_organization(database, user_id):
                request.state = "failed"
                request.failure_code = "OWNERSHIP_TRANSFER_REQUIRED"
                return None
            previous_email = user.email
            await database.execute(
                delete(PrivacyExportArtifact).where(
                    PrivacyExportArtifact.user_id == user_id
                )
            )
            await database.execute(
                update(GDPRRequest)
                .where(
                    GDPRRequest.user_id == user_id,
                    GDPRRequest.request_type == "export",
                )
                .values(
                    state="cancelled",
                    artifact_reference=None,
                    artifact_expires_at=None,
                )
            )
            for model in (
                ContactChangeRequest,
                EphemeralToken,
                MFADevice,
                TrustedDevice,
                StaffRoleBinding,
                UserRoleBinding,
            ):
                await database.execute(delete(model).where(model.user_id == user_id))
            await database.execute(delete(Identity).where(Identity.user_id == user_id))
            await database.execute(
                delete(RefreshTokenFamily).where(RefreshTokenFamily.user_id == user_id)
            )
            await database.execute(
                delete(Referral).where(Referral.referrer_user_id == user_id)
            )
            await database.execute(
                update(Referral)
                .where(Referral.referred_user_id == user_id)
                .values(
                    referred_user_id=None,
                    invitee_email=f"erased-{pseudonym}@invalid.local",
                    state="revoked",
                )
            )
            if previous_email:
                await database.execute(
                    update(Invitation)
                    .where(Invitation.invitee_email == previous_email)
                    .values(
                        invitee_email=f"erased-{pseudonym}@invalid.local",
                        state="revoked",
                    )
                )
            await database.execute(
                update(Organization)
                .where(
                    Organization.personal_owner_user_id == user_id,
                    Organization.workspace_type == "personal",
                )
                .values(
                    name="Anonymized Portfolio",
                    slug=f"anonymized-{pseudonym}",
                    state="closed",
                    subscription_metadata={},
                )
            )
            user.email = None
            user.given_name = None
            user.family_name = None
            user.phone_e164 = None
            user.state = "anonymized"
            user.anonymized_at = now
            user.version += 1
            request.state = "completed"
            request.completed_at = now
            request.backup_purge_due_at = backup_purge_due_at
            request.artifact_reference = None
            request.artifact_expires_at = None
            database.add(
                AuditLog(
                    actor_user_id=user_id,
                    subject_user_id=user_id,
                    event_type="PRIVACY_ACCOUNT_ERASED",
                    outcome="success",
                    correlation_id=correlation_id,
                    metadata_json={
                        "request_id": str(request_id),
                        "backup_purge_due_at": backup_purge_due_at.isoformat(),
                    },
                )
            )
            return self._request(request)

    @staticmethod
    async def _has_sole_owned_organization(
        database: AsyncSession, user_id: UUID
    ) -> bool:
        owned_orgs = (
            await database.scalars(
                select(UserRoleBinding.org_id)
                .join(
                    RolePermissionCatalog,
                    RolePermissionCatalog.catalog_id == UserRoleBinding.catalog_id,
                )
                .join(Organization, Organization.org_id == UserRoleBinding.org_id)
                .where(
                    UserRoleBinding.user_id == user_id,
                    UserRoleBinding.revoked_at.is_(None),
                    RolePermissionCatalog.role == "OWNER",
                    Organization.workspace_type == "organization",
                )
            )
        ).all()
        for org_id in owned_orgs:
            other_owners = await database.scalar(
                select(func.count())
                .select_from(UserRoleBinding)
                .join(
                    RolePermissionCatalog,
                    RolePermissionCatalog.catalog_id == UserRoleBinding.catalog_id,
                )
                .where(
                    UserRoleBinding.org_id == org_id,
                    UserRoleBinding.user_id != user_id,
                    UserRoleBinding.revoked_at.is_(None),
                    RolePermissionCatalog.role == "OWNER",
                )
            )
            if not other_owners:
                return True
        return False
