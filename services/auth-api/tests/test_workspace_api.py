from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from auth_core.entity.session import AccessClaims, ClientType
from auth_core.entity.workspace import ReferralRecord, WorkspaceSummary, WorkspaceType
from auth_core.main import app


def claims() -> AccessClaims:
    now = datetime.now(UTC)
    return AccessClaims(
        user_id=uuid4(),
        session_id=uuid4(),
        family_id=uuid4(),
        jti=uuid4(),
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        client_type=ClientType.WEB,
        assurance=("password",),
    )


@pytest.mark.asyncio
async def test_workspace_list_is_available_to_web_and_mobile_tokens() -> None:
    workspace = WorkspaceSummary(
        uuid4(), "My Personal Portfolio", "personal-test", WorkspaceType.PERSONAL, ("OWNER",)
    )
    with (
        patch(
            "auth_core.boundary.http.workspace.access_claims",
            new_callable=AsyncMock,
            return_value=claims(),
        ),
        patch(
            "auth_core.boundary.http.workspace.workspace_control.list_workspaces",
            new_callable=AsyncMock,
            return_value=(workspace,),
        ),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.get(
                "/api/v1/workspaces", headers={"Authorization": "Bearer test"}
            )

    assert response.status_code == 200
    assert response.json()["workspaces"][0]["workspace_type"] == "personal"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_referral_status_masks_invitee_email() -> None:
    now = datetime.now(UTC)
    referral = ReferralRecord(
        uuid4(), "friend@example.com", "registered", now, now + timedelta(days=30), now, None
    )
    with (
        patch(
            "auth_core.boundary.http.workspace.access_claims",
            new_callable=AsyncMock,
            return_value=claims(),
        ),
        patch(
            "auth_core.boundary.http.workspace.workspace_control.list_referrals",
            new_callable=AsyncMock,
            return_value=(referral,),
        ),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.get(
                "/api/v1/referrals", headers={"Authorization": "Bearer test"}
            )

    assert response.status_code == 200
    assert response.json()["referrals"][0]["invitee_hint"] == "f***@example.com"
    assert "friend@example.com" not in response.text
