from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from auth_core.main import app


@pytest.mark.asyncio
async def test_liveness_returns_service_status() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {
        "service": "auth-core",
        "status": "up",
        "components": None,
    }


@pytest.mark.asyncio
async def test_readiness_reports_available_dependencies() -> None:
    with (
        patch("auth_core.boundary.http.health.check_database", new_callable=AsyncMock),
        patch("auth_core.boundary.http.health.check_redis", new_callable=AsyncMock),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_readiness_reports_unavailable_dependency() -> None:
    with (
        patch(
            "auth_core.boundary.http.health.check_database",
            new_callable=AsyncMock,
            side_effect=ConnectionError,
        ),
        patch("auth_core.boundary.http.health.check_redis", new_callable=AsyncMock),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["components"]["postgresql"]["status"] == "down"
