from datetime import datetime
from typing import Protocol
from uuid import UUID

from auth_core.entity.privacy import AuditPage, AuditSearchFilter
from auth_core.entity.recovery import StaffRole


class AuditRepository(Protocol):
    async def staff_has_role(self, user_id: UUID, role: StaffRole) -> bool: ...

    async def search_audit_logs(
        self,
        actor_user_id: UUID,
        filters: AuditSearchFilter,
        cursor: tuple[datetime, UUID] | None,
        limit: int,
        correlation_id: UUID,
    ) -> AuditPage: ...
