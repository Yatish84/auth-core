from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from auth_core.entity.registration import RegistrationError, RegistrationErrorCode
from auth_core.main import app


@pytest.mark.asyncio
async def test_email_signup_returns_safe_acceptance() -> None:
    with patch(
        "auth_core.boundary.http.registration.registration_control.register_email",
        new_callable=AsyncMock,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/signup",
                json={
                    "email": "person@example.com",
                    "password": "correct horse battery staple",
                    "given_name": "Ada",
                    "family_name": "Lovelace",
                    "captcha_token": "valid-captcha",
                },
            )

    assert response.status_code == 201
    assert response.json()["status"] == "accepted"


@pytest.mark.asyncio
async def test_registration_error_uses_problem_json() -> None:
    error = RegistrationError(
        RegistrationErrorCode.CAPTCHA_INVALID,
        "The security check could not be verified. Please try again.",
        400,
    )
    with patch(
        "auth_core.boundary.http.registration.registration_control.register_email",
        new_callable=AsyncMock,
        side_effect=error,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/signup",
                json={
                    "email": "person@example.com",
                    "password": "correct horse battery staple",
                    "given_name": "Ada",
                    "family_name": "Lovelace",
                    "captcha_token": "invalid",
                },
            )

    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "AUTH_CAPTCHA_INVALID"
