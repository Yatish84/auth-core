import base64
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_core.entity.privacy import AuditPage, AuditRecord, AuditSearchFilter
from auth_core.entity.recovery import StaffRole
from auth_core.infrastructure.persistence.models import AuditLog, StaffRoleBinding
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
