from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from auth_core.control.privacy import AuditQueryControl
from auth_core.entity.privacy import (
    AuditPage,
    AuditRecord,
    AuditSearchFilter,
    PrivacyError,
    PrivacyErrorCode,
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
