import base64
import binascii
from datetime import datetime
from typing import Any
from uuid import UUID

from auth_core.control.ports.privacy import AuditRepository
from auth_core.entity.privacy import (
    AuditPage,
    AuditRecord,
    AuditSearchFilter,
    PrivacyError,
    PrivacyErrorCode,
)
from auth_core.entity.recovery import StaffRole
from auth_core.entity.session import AccessClaims

STRONG_METHODS = {"totp", "passkey", "email", "sms", "backup_code", "backup_codes"}
SENSITIVE_METADATA_TERMS = {
    "assertion",
    "code",
    "email",
    "evidence",
    "ip",
    "password",
    "phone",
    "secret",
    "token",
    "user_agent",
}


class AuditQueryControl:
    def __init__(self, repository: AuditRepository) -> None:
        self._repository = repository

    async def search(
        self,
        claims: AccessClaims,
        filters: AuditSearchFilter,
        cursor: str | None,
        limit: int,
        correlation_id: UUID,
    ) -> AuditPage:
        self._require_recent_mfa(claims)
        if not await self._repository.staff_has_role(
            claims.user_id, StaffRole.SECURITY_SUPERVISOR_L3
        ):
            raise PrivacyError(
                PrivacyErrorCode.AUDIT_FORBIDDEN,
                "You are not authorized to review security audit history.",
                403,
            )
        page = await self._repository.search_audit_logs(
            claims.user_id,
            filters,
            self.decode_cursor(cursor) if cursor else None,
            limit,
            correlation_id,
        )
        return AuditPage(
            tuple(self._redact(record) for record in page.items), page.next_cursor
        )

    @staticmethod
    def encode_cursor(occurred_at: datetime, audit_id: UUID) -> str:
        value = f"{occurred_at.isoformat()}|{audit_id}".encode()
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    @staticmethod
    def decode_cursor(cursor: str) -> tuple[datetime, UUID]:
        try:
            padding = "=" * (-len(cursor) % 4)
            decoded = base64.urlsafe_b64decode(cursor + padding).decode()
            occurred_at, audit_id = decoded.split("|", 1)
            parsed_time = datetime.fromisoformat(occurred_at)
            if parsed_time.tzinfo is None:
                raise ValueError
            return parsed_time, UUID(audit_id)
        except (binascii.Error, UnicodeDecodeError, ValueError) as error:
            raise PrivacyError(
                PrivacyErrorCode.AUDIT_CURSOR_INVALID,
                "The audit-page cursor is invalid or expired.",
                400,
            ) from error

    @staticmethod
    def _require_recent_mfa(claims: AccessClaims) -> None:
        if not STRONG_METHODS.intersection(claims.assurance):
            raise PrivacyError(
                PrivacyErrorCode.RECENT_MFA_REQUIRED,
                "Complete a recent extra security check before continuing.",
                403,
            )

    @classmethod
    def _redact(cls, record: AuditRecord) -> AuditRecord:
        return AuditRecord(
            record.audit_id,
            record.actor_user_id,
            record.subject_user_id,
            record.org_id,
            record.event_type,
            record.outcome,
            record.correlation_id,
            cls._safe_metadata(record.metadata),
            record.occurred_at,
        )

    @classmethod
    def _safe_metadata(cls, metadata: dict[str, Any]) -> dict[str, Any]:
        safe: dict[str, Any] = {}
        for key, value in metadata.items():
            normalized_key = key.lower()
            if any(term in normalized_key for term in SENSITIVE_METADATA_TERMS):
                safe[key] = "[REDACTED]"
            else:
                safe[key] = cls._safe_value(value)
        return safe

    @classmethod
    def _safe_value(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return cls._safe_metadata(value)
        if isinstance(value, list):
            return [cls._safe_value(item) for item in value[:20]]
        if isinstance(value, str):
            return value[:120]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return "[REDACTED]"
