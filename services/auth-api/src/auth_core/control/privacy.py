import base64
import binascii
import hmac
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any
from uuid import UUID

from auth_core.control.ports.privacy import AuditRepository, PrivacyCipher, PrivacyRepository
from auth_core.entity.privacy import (
    AuditPage,
    AuditRecord,
    AuditSearchFilter,
    ExportDownload,
    PrivacyError,
    PrivacyErrorCode,
    PrivacyRequestRecord,
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
EXPORT_ARTIFACT_TTL = timedelta(hours=24)


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


class GDPRControl:
    def __init__(
        self,
        repository: PrivacyRepository,
        cipher: PrivacyCipher,
        idempotency_pepper: bytes,
    ) -> None:
        self._repository = repository
        self._cipher = cipher
        self._idempotency_pepper = idempotency_pepper

    async def request_export(
        self,
        claims: AccessClaims,
        idempotency_key: str,
        correlation_id: UUID,
    ) -> PrivacyRequestRecord:
        AuditQueryControl._require_recent_mfa(claims)
        expires_at = datetime.now(UTC) + EXPORT_ARTIFACT_TTL
        request, created = await self._repository.get_or_create_export(
            claims.user_id,
            self._key_hash(idempotency_key),
            expires_at,
            correlation_id,
        )
        if not created:
            return request
        try:
            export_data = await self._repository.collect_export_data(claims.user_id)
            plaintext = json.dumps(
                export_data, sort_keys=True, separators=(",", ":")
            ).encode()
            encrypted = self._cipher.encrypt(
                plaintext, self._associated_data(claims.user_id, request.request_id)
            )
            return await self._repository.complete_export(
                request.request_id,
                claims.user_id,
                encrypted,
                sha256(plaintext).hexdigest(),
                expires_at,
                correlation_id,
            )
        except Exception as error:
            await self._repository.fail_export(
                request.request_id, claims.user_id, "EXPORT_BUILD_FAILED"
            )
            raise PrivacyError(
                PrivacyErrorCode.EXPORT_UNAVAILABLE,
                "The export could not be prepared. Please try again later.",
                503,
            ) from error

    async def get_request(
        self, claims: AccessClaims, request_id: UUID
    ) -> PrivacyRequestRecord:
        request = await self._repository.get_privacy_request(claims.user_id, request_id)
        if request is None:
            raise PrivacyError(
                PrivacyErrorCode.REQUEST_NOT_FOUND,
                "The privacy request was not found.",
                404,
            )
        return request

    async def download_export(
        self, claims: AccessClaims, request_id: UUID
    ) -> ExportDownload:
        AuditQueryControl._require_recent_mfa(claims)
        request = await self.get_request(claims, request_id)
        if request.request_type != "export" or request.state != "completed":
            raise self._export_unavailable()
        artifact = await self._repository.get_export_artifact(
            claims.user_id, request_id, datetime.now(UTC)
        )
        if artifact is None:
            raise self._export_unavailable()
        try:
            plaintext = self._cipher.decrypt(
                artifact.encrypted_content,
                self._associated_data(claims.user_id, request_id),
            )
        except ValueError as error:
            raise PrivacyError(
                PrivacyErrorCode.EXPORT_INTEGRITY_FAILED,
                "The export failed its security verification.",
                500,
            ) from error
        if not hmac.compare_digest(sha256(plaintext).hexdigest(), artifact.content_digest):
            raise PrivacyError(
                PrivacyErrorCode.EXPORT_INTEGRITY_FAILED,
                "The export failed its security verification.",
                500,
            )
        return ExportDownload(request_id, plaintext, artifact.expires_at)

    def _key_hash(self, key: str) -> str:
        return hmac.new(self._idempotency_pepper, key.encode(), sha256).hexdigest()

    @staticmethod
    def _associated_data(user_id: UUID, request_id: UUID) -> bytes:
        return user_id.bytes + request_id.bytes

    @staticmethod
    def _export_unavailable() -> PrivacyError:
        return PrivacyError(
            PrivacyErrorCode.EXPORT_UNAVAILABLE,
            "The export is unavailable, incomplete, or expired.",
            410,
        )
