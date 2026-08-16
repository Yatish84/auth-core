from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from auth_core.entity.recovery import RecoveryError, RecoveryErrorCode
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
async def test_forgot_password_returns_generic_accepted_response() -> None:
    with patch(
        "auth_core.boundary.http.recovery.recovery_control.request_password_reset",
        new_callable=AsyncMock,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/password/forgot", json={"email": "person@example.com"}
            )

    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    assert "eligible" in response.json()["message"]
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_used_reset_token_returns_rfc_7807_problem() -> None:
    error = RecoveryError(
        RecoveryErrorCode.TOKEN_INVALID,
        "This recovery link is invalid, expired, or has already been used.",
        400,
    )
    with patch(
        "auth_core.boundary.http.recovery.recovery_control.reset_password",
        new_callable=AsyncMock,
        side_effect=error,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/password/reset",
                json={
                    "token": "used-token-value-that-is-long-enough",
                    "new_password": "Unique secure phrase 2026!",
                },
            )

    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "AUTH_RECOVERY_TOKEN_INVALID"


@pytest.mark.asyncio
async def test_admin_unlock_uses_authenticated_actor_not_request_role() -> None:
    target_user_id = uuid4()
    with (
        patch(
            "auth_core.boundary.http.recovery.access_claims",
            new_callable=AsyncMock,
            return_value=strong_claims(),
        ),
        patch(
            "auth_core.boundary.http.recovery.admin_control.unlock",
            new_callable=AsyncMock,
        ) as unlock,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.post(
                f"/api/v1/admin/users/{target_user_id}/unlock",
                headers={"Authorization": "Bearer test"},
                json={"ticket_reference": "SUPPORT-123"},
            )

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert unlock.await_args.args[1] == target_user_id
