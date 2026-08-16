import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from auth_core.control.privacy import AuditQueryControl, GDPRControl
from auth_core.entity.privacy import (
    AuditPage,
    AuditRecord,
    AuditSearchFilter,
    EncryptedExportArtifact,
    PrivacyError,
    PrivacyErrorCode,
    PrivacyRequestRecord,
)
from auth_core.entity.recovery import StaffRole
from auth_core.entity.session import AccessClaims, ClientType


def claims(assurance: tuple[str, ...] = ("totp",)) -> AccessClaims:
    now = datetime.now(UTC)
    return AccessClaims(
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        now,
        now + timedelta(minutes=15),
        ClientType.WEB,
        assurance,
    )


class AuditRepositoryFake:
    def __init__(self) -> None:
        self.allowed = True
        self.search_calls = 0
        now = datetime.now(UTC)
        self.page = AuditPage(
            (
                AuditRecord(
                    uuid4(),
                    uuid4(),
                    uuid4(),
                    None,
                    "LOGIN_FAILED",
                    "failure",
                    uuid4(),
                    {
                        "email": "person@example.com",
                        "reason": "invalid credentials" * 20,
                        "nested": {"access_token": "secret", "attempt": 2},
                    },
                    now,
                ),
            ),
            "next-page",
        )

    async def staff_has_role(self, user_id: UUID, role: StaffRole) -> bool:
        del user_id
        return self.allowed and role is StaffRole.SECURITY_SUPERVISOR_L3

    async def search_audit_logs(
        self,
        actor_user_id: UUID,
        filters: AuditSearchFilter,
        cursor: tuple[datetime, UUID] | None,
        limit: int,
        correlation_id: UUID,
    ) -> AuditPage:
        del actor_user_id, filters, cursor, limit, correlation_id
        self.search_calls += 1
        return self.page


@pytest.mark.asyncio
async def test_audit_search_requires_recent_mfa_before_repository_access() -> None:
    repository = AuditRepositoryFake()
    control = AuditQueryControl(repository)

    with pytest.raises(PrivacyError) as raised:
        await control.search(claims(("password",)), AuditSearchFilter(), None, 50, uuid4())

    assert raised.value.code is PrivacyErrorCode.RECENT_MFA_REQUIRED
    assert repository.search_calls == 0


@pytest.mark.asyncio
async def test_audit_search_requires_database_backed_security_role() -> None:
    repository = AuditRepositoryFake()
    repository.allowed = False
    control = AuditQueryControl(repository)

    with pytest.raises(PrivacyError) as raised:
        await control.search(claims(), AuditSearchFilter(), None, 50, uuid4())

    assert raised.value.code is PrivacyErrorCode.AUDIT_FORBIDDEN
    assert repository.search_calls == 0


@pytest.mark.asyncio
async def test_audit_search_redacts_sensitive_metadata_and_bounds_strings() -> None:
    repository = AuditRepositoryFake()
    page = await AuditQueryControl(repository).search(
        claims(), AuditSearchFilter(), None, 50, uuid4()
    )

    metadata = page.items[0].metadata
    assert metadata["email"] == "[REDACTED]"
    assert metadata["nested"]["access_token"] == "[REDACTED]"
    assert metadata["nested"]["attempt"] == 2
    assert len(metadata["reason"]) == 120
    assert page.next_cursor == "next-page"


def test_audit_cursor_round_trip_and_invalid_rejection() -> None:
    now = datetime.now(UTC)
    audit_id = uuid4()
    cursor = AuditQueryControl.encode_cursor(now, audit_id)

    assert AuditQueryControl.decode_cursor(cursor) == (now, audit_id)
    with pytest.raises(PrivacyError) as raised:
        AuditQueryControl.decode_cursor("not-a-valid-cursor")
    assert raised.value.code is PrivacyErrorCode.AUDIT_CURSOR_INVALID


class CipherFake:
    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        return associated_data + b"|" + plaintext[::-1]

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        prefix = associated_data + b"|"
        if not ciphertext.startswith(prefix):
            raise ValueError("wrong owner")
        return ciphertext[len(prefix) :][::-1]


class PrivacyRepositoryFake:
    def __init__(self) -> None:
        self.user_id = uuid4()
        self.request_id = uuid4()
        self.created = True
        self.collect_calls = 0
        self.request = self._request("processing")
        self.artifact: EncryptedExportArtifact | None = None
        self.erasure_blocked = False

    def _request(self, state: str) -> PrivacyRequestRecord:
        now = datetime.now(UTC)
        return PrivacyRequestRecord(
            self.request_id,
            self.user_id,
            "export",
            state,
            now,
            now if state == "completed" else None,
            now + timedelta(hours=24),
            None,
        )

    async def get_or_create_export(
        self,
        user_id: UUID,
        idempotency_key_hash: str,
        artifact_expires_at: datetime,
        correlation_id: UUID,
    ) -> tuple[PrivacyRequestRecord, bool]:
        del idempotency_key_hash, artifact_expires_at, correlation_id
        if self.created:
            self.user_id = user_id
            self.request = self._request("processing")
        return self.request, self.created

    async def collect_export_data(self, user_id: UUID) -> dict[str, object]:
        self.collect_calls += 1
        return {"profile": {"user_id": str(user_id), "email": "owner@example.com"}}

    async def complete_export(
        self,
        request_id: UUID,
        user_id: UUID,
        encrypted_content: bytes,
        content_digest: str,
        artifact_expires_at: datetime,
        correlation_id: UUID,
    ) -> PrivacyRequestRecord:
        del correlation_id
        self.artifact = EncryptedExportArtifact(
            request_id, encrypted_content, content_digest, artifact_expires_at
        )
        self.user_id = user_id
        self.request = self._request("completed")
        return self.request

    async def fail_export(
        self, request_id: UUID, user_id: UUID, failure_code: str
    ) -> None:
        del request_id, user_id, failure_code

    async def get_privacy_request(
        self, user_id: UUID, request_id: UUID
    ) -> PrivacyRequestRecord | None:
        if user_id == self.user_id and request_id == self.request_id:
            return self.request
        return None

    async def get_export_artifact(
        self, user_id: UUID, request_id: UUID, now: datetime
    ) -> EncryptedExportArtifact | None:
        del now
        if user_id == self.user_id and request_id == self.request_id:
            return self.artifact
        return None

    async def get_or_create_erasure(
        self,
        user_id: UUID,
        idempotency_key_hash: str,
        correlation_id: UUID,
    ) -> tuple[PrivacyRequestRecord | None, bool]:
        del idempotency_key_hash, correlation_id
        if self.erasure_blocked:
            return None, False
        self.user_id = user_id
        self.request = PrivacyRequestRecord(
            self.request_id,
            user_id,
            "erasure",
            "processing",
            datetime.now(UTC),
            None,
            None,
            None,
        )
        return self.request, True

    async def execute_erasure(
        self,
        request_id: UUID,
        user_id: UUID,
        pseudonym: str,
        now: datetime,
        backup_purge_due_at: datetime,
        correlation_id: UUID,
    ) -> PrivacyRequestRecord | None:
        del pseudonym, correlation_id
        self.request = PrivacyRequestRecord(
            request_id,
            user_id,
            "erasure",
            "completed",
            now,
            now,
            None,
            None,
            backup_purge_due_at,
        )
        return self.request


class SessionRevokerFake:
    def __init__(self) -> None:
        self.calls = 0

    async def revoke_user_access(self, user_id: UUID, reason: str) -> int:
        del user_id
        assert reason == "privacy_erasure"
        self.calls += 1
        return 2


@pytest.mark.asyncio
async def test_privacy_export_is_encrypted_and_downloaded_for_owner() -> None:
    repository = PrivacyRepositoryFake()
    owner_claims = claims()
    repository.user_id = owner_claims.user_id
    control = GDPRControl(
        repository, CipherFake(), b"idempotency-pepper", SessionRevokerFake()
    )

    request = await control.request_export(owner_claims, "unique-request-key", uuid4())
    download = await control.download_export(owner_claims, request.request_id)

    assert request.state == "completed"
    assert repository.artifact is not None
    assert b"owner@example.com" not in repository.artifact.encrypted_content
    assert json.loads(download.content)["profile"]["user_id"] == str(owner_claims.user_id)


@pytest.mark.asyncio
async def test_duplicate_export_request_reuses_record_without_rebuilding() -> None:
    repository = PrivacyRepositoryFake()
    repository.created = False
    repository.request = repository._request("completed")
    control = GDPRControl(
        repository, CipherFake(), b"idempotency-pepper", SessionRevokerFake()
    )

    result = await control.request_export(claims(), "same-request-key", uuid4())

    assert result.state == "completed"
    assert repository.collect_calls == 0


@pytest.mark.asyncio
async def test_tampered_export_fails_integrity_check() -> None:
    repository = PrivacyRepositoryFake()
    owner_claims = claims()
    repository.user_id = owner_claims.user_id
    control = GDPRControl(
        repository, CipherFake(), b"idempotency-pepper", SessionRevokerFake()
    )
    request = await control.request_export(owner_claims, "tamper-request-key", uuid4())
    assert repository.artifact is not None
    repository.artifact = EncryptedExportArtifact(
        repository.artifact.request_id,
        repository.artifact.encrypted_content,
        "0" * 64,
        repository.artifact.expires_at,
    )

    with pytest.raises(PrivacyError) as raised:
        await control.download_export(owner_claims, request.request_id)

    assert raised.value.code is PrivacyErrorCode.EXPORT_INTEGRITY_FAILED


@pytest.mark.asyncio
async def test_erasure_revokes_access_and_sets_backup_purge_deadline() -> None:
    repository = PrivacyRepositoryFake()
    revoker = SessionRevokerFake()
    owner_claims = claims()
    control = GDPRControl(
        repository, CipherFake(), b"idempotency-pepper", revoker
    )

    result = await control.request_erasure(
        owner_claims, "erasure-request-key", uuid4()
    )

    assert revoker.calls == 1
    assert result.state == "completed"
    assert result.backup_purge_due_at is not None
    assert result.backup_purge_due_at - result.completed_at >= timedelta(days=29)


@pytest.mark.asyncio
async def test_erasure_requires_organization_ownership_transfer() -> None:
    repository = PrivacyRepositoryFake()
    repository.erasure_blocked = True
    revoker = SessionRevokerFake()
    control = GDPRControl(
        repository, CipherFake(), b"idempotency-pepper", revoker
    )

    with pytest.raises(PrivacyError) as raised:
        await control.request_erasure(claims(), "blocked-erasure-key", uuid4())

    assert raised.value.code is PrivacyErrorCode.OWNERSHIP_TRANSFER_REQUIRED
    assert revoker.calls == 0
