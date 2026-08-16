from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from auth_core.entity.session import (
    AccessClaims,
    ClientType,
    CreatedSession,
    RevocationResult,
    RotationResult,
    SessionSummary,
)


class SessionRepository(Protocol):
    async def user_is_active(self, user_id: UUID) -> bool: ...

    async def create_session(
        self,
        user_id: UUID,
        client_type: ClientType,
        device_fingerprint_hash: str,
        ip_address: str | None,
        refresh_token_hash: str,
        access_jti: UUID,
        family_expires_at: datetime,
        session_expires_at: datetime,
        refresh_expires_at: datetime,
    ) -> CreatedSession: ...

    async def rotate_refresh_token(
        self,
        token_hash: str,
        replacement_hash: str,
        replacement_expires_at: datetime,
        new_access_jti: UUID,
        client_type: ClientType,
        device_fingerprint_hash: str,
        idle_timeout_seconds: int,
        now: datetime,
    ) -> RotationResult: ...

    async def revoke_session(
        self, user_id: UUID, session_id: UUID, reason: str, now: datetime
    ) -> RevocationResult | None: ...

    async def revoke_all(
        self, user_id: UUID, reason: str, now: datetime
    ) -> tuple[RevocationResult, ...]: ...

    async def list_sessions(
        self, user_id: UUID, now: datetime
    ) -> tuple[SessionSummary, ...]: ...

    async def session_is_active(self, session_id: UUID, now: datetime) -> bool: ...

    async def audit(
        self,
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        user_id: UUID,
        metadata: dict[str, str | int | bool],
    ) -> None: ...


class AccessTokenProvider(Protocol):
    def issue(
        self,
        user_id: UUID,
        session_id: UUID,
        family_id: UUID,
        jti: UUID,
        client_type: ClientType,
        assurance: tuple[str, ...],
        now: datetime,
    ) -> tuple[str, datetime]: ...

    def verify(self, token: str, now: datetime) -> AccessClaims: ...

    def jwks(self) -> Mapping[str, object]: ...


class SessionSecurityStore(Protocol):
    async def consume_login_workflow(self, token: str) -> dict[str, Any] | None: ...

    async def revoke_access_token(self, jti: UUID, remaining_lifetime: int) -> None: ...

    async def access_token_is_revoked(self, jti: UUID) -> bool: ...

    async def revoke_family(self, family_id: UUID, remaining_lifetime: int) -> None: ...

    async def family_is_revoked(self, family_id: UUID) -> bool: ...

    async def revoke_user(self, user_id: UUID, issued_before: datetime) -> None: ...

    async def user_revoked_at(self, user_id: UUID) -> datetime | None: ...
