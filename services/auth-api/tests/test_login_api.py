from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from auth_core.entity.login import (
    LoginDecision,
    LoginDecisionType,
    LoginError,
    LoginErrorCode,
    RiskLevel,
)
from auth_core.main import app


@pytest.mark.asyncio
async def test_password_login_returns_reusable_workflow_decision() -> None:
    decision = LoginDecision(
        LoginDecisionType.MFA_REQUIRED,
        RiskLevel.HIGH,
        "opaque-login-workflow-token",
        ("password", "phone_otp"),
    )
    with patch(
        "auth_core.boundary.http.login.login_control.login_password",
        new_callable=AsyncMock,
        return_value=decision,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "person@example.com",
                    "password": "correct horse battery staple",
                    "device_fingerprint": "browser-fingerprint-123",
                },
            )

    assert result.status_code == 200
    assert result.json() == {
        "decision": "mfa_required",
        "risk": "high",
        "workflow_token": "opaque-login-workflow-token",
        "allowed_methods": ["password", "phone_otp"],
    }
    assert "access_token" not in result.text
    assert "refresh_token" not in result.text
    assert result.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_invalid_password_uses_problem_json() -> None:
    error = LoginError(
        LoginErrorCode.INVALID_CREDENTIALS,
        "The supplied credentials could not be verified.",
        401,
    )
    with patch(
        "auth_core.boundary.http.login.login_control.login_password",
        new_callable=AsyncMock,
        side_effect=error,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "unknown@example.com",
                    "password": "wrong-password",
                    "device_fingerprint": "browser-fingerprint-123",
                },
            )

    assert result.status_code == 401
    assert result.headers["content-type"].startswith("application/problem+json")
    assert result.json()["code"] == "AUTH_INVALID_CREDENTIALS"


@pytest.mark.asyncio
async def test_phone_login_request_is_always_generic() -> None:
    with patch(
        "auth_core.boundary.http.login.login_control.request_phone_otp",
        new_callable=AsyncMock,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post(
                "/api/v1/auth/login/phone/request",
                json={"phone": "+16045550100", "captcha_token": "valid-captcha"},
            )

    assert result.status_code == 202
    assert result.json()["status"] == "accepted"


@pytest.mark.asyncio
async def test_oidc_authorize_returns_redirect_details() -> None:
    with patch(
        "auth_core.boundary.http.login.login_control.start_oidc",
        new_callable=AsyncMock,
        return_value=("https://accounts.example.test/authorize", "opaque-oidc-state-value"),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post("/api/v1/auth/sso/google/authorize")

    assert result.status_code == 200
    assert result.json()["state"] == "opaque-oidc-state-value"
