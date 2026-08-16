from datetime import datetime
from typing import Protocol
from uuid import UUID

from auth_core.entity.privacy import (
    AuditPage,
    AuditSearchFilter,
    EncryptedExportArtifact,
    PrivacyRequestRecord,
)
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


class PrivacyCipher(Protocol):
    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes: ...

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes: ...


class PrivacySessionRevoker(Protocol):
    async def revoke_user_access(self, user_id: UUID, reason: str) -> int: ...


class PrivacyRepository(Protocol):
    async def get_or_create_export(
        self,
        user_id: UUID,
        idempotency_key_hash: str,
        artifact_expires_at: datetime,
        correlation_id: UUID,
    ) -> tuple[PrivacyRequestRecord, bool]: ...

    async def collect_export_data(self, user_id: UUID) -> dict[str, object]: ...

    async def complete_export(
        self,
        request_id: UUID,
        user_id: UUID,
        encrypted_content: bytes,
        content_digest: str,
        artifact_expires_at: datetime,
        correlation_id: UUID,
    ) -> PrivacyRequestRecord: ...

    async def fail_export(
        self, request_id: UUID, user_id: UUID, failure_code: str
    ) -> None: ...

    async def get_privacy_request(
        self, user_id: UUID, request_id: UUID
    ) -> PrivacyRequestRecord | None: ...

    async def get_export_artifact(
        self, user_id: UUID, request_id: UUID, now: datetime
    ) -> EncryptedExportArtifact | None: ...

    async def get_or_create_erasure(
        self,
        user_id: UUID,
        idempotency_key_hash: str,
        correlation_id: UUID,
    ) -> tuple[PrivacyRequestRecord | None, bool]: ...

    async def execute_erasure(
        self,
        request_id: UUID,
        user_id: UUID,
        pseudonym: str,
        now: datetime,
        backup_purge_due_at: datetime,
        correlation_id: UUID,
    ) -> PrivacyRequestRecord | None: ...
