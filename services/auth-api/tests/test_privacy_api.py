from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from auth_core.entity.privacy import (
    AuditPage,
    AuditRecord,
    ExportDownload,
    PrivacyError,
    PrivacyErrorCode,
    PrivacyRequestRecord,
)
from auth_core.entity.session import AccessClaims, ClientType
from auth_core.main import app


def strong_claims() -> AccessClaims:
    now = datetime.now(UTC)
    return AccessClaims(
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        now,
        now + timedelta(minutes=15),
        ClientType.WEB,
        ("totp",),
    )


@pytest.mark.asyncio
async def test_audit_search_returns_redacted_paginated_contract() -> None:
    now = datetime.now(UTC)
    record = AuditRecord(
        uuid4(),
        uuid4(),
        uuid4(),
        None,
        "LOGIN_FAILED",
        "failure",
        uuid4(),
        {"reason": "invalid_credentials"},
        now,
    )
    with (
        patch(
            "auth_core.boundary.http.privacy.access_claims",
            new_callable=AsyncMock,
            return_value=strong_claims(),
        ),
        patch(
            "auth_core.boundary.http.privacy.audit_control.search",
            new_callable=AsyncMock,
            return_value=AuditPage((record,), "next-page"),
        ) as search,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.get(
                "/api/v1/admin/audit-logs",
                headers={"Authorization": "Bearer test"},
                params={"event_type": "LOGIN_FAILED", "limit": 25},
            )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["items"][0]["event_type"] == "LOGIN_FAILED"
    assert response.json()["next_cursor"] == "next-page"
    assert search.await_args.args[1].event_type == "LOGIN_FAILED"
    assert search.await_args.args[3] == 25


@pytest.mark.asyncio
async def test_audit_search_returns_rfc_7807_for_forbidden_actor() -> None:
    error = PrivacyError(
        PrivacyErrorCode.AUDIT_FORBIDDEN,
        "You are not authorized to review security audit history.",
        403,
    )
    with (
        patch(
            "auth_core.boundary.http.privacy.access_claims",
            new_callable=AsyncMock,
            return_value=strong_claims(),
        ),
        patch(
            "auth_core.boundary.http.privacy.audit_control.search",
            new_callable=AsyncMock,
            side_effect=error,
        ),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.get(
                "/api/v1/admin/audit-logs",
                headers={"Authorization": "Bearer test"},
            )

    assert response.status_code == 403
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "AUTH_AUDIT_FORBIDDEN"


@pytest.mark.asyncio
async def test_export_request_uses_idempotency_header_and_returns_status() -> None:
    now = datetime.now(UTC)
    record = PrivacyRequestRecord(
        uuid4(),
        uuid4(),
        "export",
        "completed",
        now,
        now,
        now + timedelta(hours=24),
        None,
    )
    with (
        patch(
            "auth_core.boundary.http.privacy.access_claims",
            new_callable=AsyncMock,
            return_value=strong_claims(),
        ),
        patch(
            "auth_core.boundary.http.privacy.gdpr_control.request_export",
            new_callable=AsyncMock,
            return_value=record,
        ) as request_export,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.post(
                "/api/v1/privacy/exports",
                headers={
                    "Authorization": "Bearer test",
                    "Idempotency-Key": "export-attempt-001",
                },
            )

    assert response.status_code == 202
    assert response.json()["state"] == "completed"
    assert request_export.await_args.args[1] == "export-attempt-001"


@pytest.mark.asyncio
async def test_export_download_streams_json_as_attachment() -> None:
    request_id = uuid4()
    expires_at = datetime.now(UTC) + timedelta(hours=24)
    with (
        patch(
            "auth_core.boundary.http.privacy.access_claims",
            new_callable=AsyncMock,
            return_value=strong_claims(),
        ),
        patch(
            "auth_core.boundary.http.privacy.gdpr_control.download_export",
            new_callable=AsyncMock,
            return_value=ExportDownload(request_id, b'{"profile":{}}', expires_at),
        ),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.get(
                f"/api/v1/privacy/exports/{request_id}/download",
                headers={"Authorization": "Bearer test"},
            )

    assert response.status_code == 200
    assert response.json() == {"profile": {}}
    assert "attachment" in response.headers["content-disposition"]
    assert response.headers["cache-control"] == "no-store"
