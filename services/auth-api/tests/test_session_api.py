from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from auth_core.entity.session import TokenPair
from auth_core.main import app


def pair() -> TokenPair:
    now = datetime.now(UTC)
    return TokenPair(
        access_token="signed-access-token",
        refresh_token="opaque-refresh-token-with-enough-characters",
        access_expires_at=now + timedelta(minutes=15),
        refresh_expires_at=now + timedelta(days=1),
        session_id=uuid4(),
        csrf_token="browser-csrf-token",
    )


@pytest.mark.asyncio
async def test_web_session_uses_httponly_cookie_and_hides_refresh_body() -> None:
    with patch(
        "auth_core.boundary.http.session.session_control.create_session",
        new_callable=AsyncMock,
        return_value=pair(),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/session",
                headers={
                    "X-Client-Type": "WEB",
                    "X-Device-Fingerprint": "browser-fingerprint-long",
                },
                json={"workflow_token": "session-ready-workflow-token"},
            )

    assert response.status_code == 200
    assert response.json()["refresh_token"] is None
    assert "__Host-auth_refresh=" in response.headers.get_list("set-cookie")[0]
    assert "HttpOnly" in response.headers.get_list("set-cookie")[0]
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_mobile_session_returns_refresh_token_without_browser_cookie() -> None:
    with patch(
        "auth_core.boundary.http.session.session_control.create_session",
        new_callable=AsyncMock,
        return_value=pair(),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/session",
                headers={
                    "X-Client-Type": "MOBILE",
                    "X-Device-Fingerprint": "mobile-fingerprint-long",
                },
                json={"workflow_token": "session-ready-workflow-token"},
            )

    assert response.status_code == 200
    assert response.json()["refresh_token"].startswith("opaque-refresh")
    assert "set-cookie" not in response.headers


@pytest.mark.asyncio
async def test_web_refresh_requires_double_submit_csrf_token() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://test"
    ) as client:
        response = await client.post(
            "/api/v1/auth/refresh",
            headers={
                "X-Client-Type": "WEB",
                "X-Device-Fingerprint": "browser-fingerprint-long",
            },
            json={},
        )

    assert response.status_code == 403
    assert response.json()["code"] == "AUTH_CSRF_INVALID"


@pytest.mark.asyncio
async def test_jwks_exposes_only_public_verification_material() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://test"
    ) as client:
        response = await client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    assert response.json()["keys"][0]["kty"] == "RSA"
    assert "d" not in response.json()["keys"][0]
