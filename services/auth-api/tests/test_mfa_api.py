from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from auth_core.entity.mfa import (
    MFAChallenge,
    MFACompletion,
    MFACompletionType,
    MFAError,
    MFAErrorCode,
    MFAMethod,
    PasskeyOptions,
)
from auth_core.main import app


@pytest.mark.asyncio
async def test_mfa_challenge_contract_is_shared_and_privacy_safe() -> None:
    challenge = MFAChallenge(
        "opaque-mfa-challenge-token", MFAMethod.EMAIL_OTP, "p***@example.com"
    )
    with patch(
        "auth_core.boundary.http.mfa.mfa_control.issue_challenge",
        new_callable=AsyncMock,
        return_value=challenge,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/mfa/challenge",
                json={
                    "workflow_token": "opaque-login-workflow-token",
                    "method": "email_otp",
                },
            )

    assert response.status_code == 200
    assert response.json()["destination_hint"] == "p***@example.com"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_mfa_completion_returns_handoff_without_premature_tokens() -> None:
    completion = MFACompletion(
        MFACompletionType.SESSION_READY, "session-ready-workflow-token"
    )
    with patch(
        "auth_core.boundary.http.mfa.mfa_control.verify_challenge",
        new_callable=AsyncMock,
        return_value=completion,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/mfa/verify",
                json={
                    "challenge_token": "opaque-mfa-challenge-token",
                    "code": "123456",
                },
            )

    assert response.status_code == 200
    assert response.json()["result"] == "session_ready"
    assert "access_token" not in response.text
    assert "refresh_token" not in response.text


@pytest.mark.asyncio
async def test_passkey_options_preserve_browser_standard_payload() -> None:
    options = PasskeyOptions(
        "opaque-passkey-challenge",
        {"challenge": "base64url-value", "rpId": "localhost"},
    )
    with patch(
        "auth_core.boundary.http.mfa.mfa_control.passkey_authentication_options",
        new_callable=AsyncMock,
        return_value=options,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/auth/passkeys/options", json={})

    assert response.status_code == 200
    assert response.json()["public_key"]["rpId"] == "localhost"


@pytest.mark.asyncio
async def test_mfa_error_uses_problem_json() -> None:
    error = MFAError(
        MFAErrorCode.FACTOR_LOCKED,
        "This security method is temporarily locked. Please wait and try again.",
        429,
    )
    with patch(
        "auth_core.boundary.http.mfa.mfa_control.verify_challenge",
        new_callable=AsyncMock,
        side_effect=error,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/mfa/verify",
                json={
                    "challenge_token": "opaque-mfa-challenge-token",
                    "code": "000000",
                },
            )

    assert response.status_code == 429
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "AUTH_MFA_FACTOR_LOCKED"
