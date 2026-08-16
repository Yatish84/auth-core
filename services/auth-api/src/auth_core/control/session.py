import hmac
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID, uuid4

from auth_core.control.ports.session import (
    AccessTokenProvider,
    SessionRepository,
    SessionSecurityStore,
)
from auth_core.entity.session import (
    AccessClaims,
    ClientType,
    RevocationResult,
    RotationStatus,
    SessionError,
    SessionErrorCode,
    SessionSummary,
    TokenPair,
)

ACCESS_TTL_SECONDS = 900
IDLE_TIMEOUT_SECONDS = 900
SESSION_ABSOLUTE_SECONDS = 86_400
REFRESH_FAMILY_SECONDS = 2_592_000


class SessionControl:
    def __init__(
        self,
        repository: SessionRepository,
        tokens: AccessTokenProvider,
        redis_store: SessionSecurityStore,
        token_pepper: bytes,
        fingerprint_pepper: bytes,
    ) -> None:
        self._repository = repository
        self._tokens = tokens
        self._redis = redis_store
        self._token_pepper = token_pepper
        self._fingerprint_pepper = fingerprint_pepper

    async def create_session(
        self,
        workflow_token: str,
        client_type: ClientType,
        device_fingerprint: str,
        ip_address: str | None,
        correlation_id: UUID,
    ) -> TokenPair:
        workflow = await self._redis.consume_login_workflow(workflow_token)
        if workflow is None or workflow.get("decision") != "session_ready":
            raise self._workflow_invalid()
        try:
            user_id = UUID(str(workflow["user_id"]))
        except (KeyError, ValueError) as error:
            raise self._workflow_invalid() from error
        if not await self._repository.user_is_active(user_id):
            raise self._workflow_invalid()

        now = datetime.now(UTC)
        refresh_token = secrets.token_urlsafe(48)
        csrf_token = secrets.token_urlsafe(32) if client_type == ClientType.WEB else None
        access_jti = uuid4()
        family_expires_at = now + timedelta(seconds=REFRESH_FAMILY_SECONDS)
        session_expires_at = now + timedelta(seconds=SESSION_ABSOLUTE_SECONDS)
        created = await self._repository.create_session(
            user_id=user_id,
            client_type=client_type,
            device_fingerprint_hash=self._fingerprint_hash(device_fingerprint),
            ip_address=ip_address,
            refresh_token_hash=self._token_hash(refresh_token),
            access_jti=access_jti,
            family_expires_at=family_expires_at,
            session_expires_at=session_expires_at,
            refresh_expires_at=family_expires_at,
        )
        assurance = self._assurance(workflow)
        access_token, access_expires_at = self._tokens.issue(
            user_id,
            created.record.session_id,
            created.record.family_id,
            access_jti,
            client_type,
            assurance,
            now,
        )
        for item in created.evicted:
            await self._apply_revocation(item, now)
        await self._repository.audit(
            "SESSION_CREATED",
            "success",
            correlation_id,
            user_id,
            {"client_type": client_type.value, "evicted_sessions": len(created.evicted)},
        )
        return TokenPair(
            access_token,
            refresh_token,
            access_expires_at,
            session_expires_at,
            created.record.session_id,
            csrf_token,
        )

    async def refresh(
        self,
        refresh_token: str,
        client_type: ClientType,
        device_fingerprint: str,
        correlation_id: UUID,
    ) -> TokenPair:
        now = datetime.now(UTC)
        replacement = secrets.token_urlsafe(48)
        new_jti = uuid4()
        result = await self._repository.rotate_refresh_token(
            token_hash=self._token_hash(refresh_token),
            replacement_hash=self._token_hash(replacement),
            replacement_expires_at=now + timedelta(seconds=REFRESH_FAMILY_SECONDS),
            new_access_jti=new_jti,
            client_type=client_type,
            device_fingerprint_hash=self._fingerprint_hash(device_fingerprint),
            idle_timeout_seconds=IDLE_TIMEOUT_SECONDS,
            now=now,
        )
        if result.revoked is not None:
            if result.status == RotationStatus.ROTATED:
                await self._redis.revoke_access_token(
                    result.revoked.access_jti, ACCESS_TTL_SECONDS
                )
            else:
                await self._apply_revocation(result.revoked, now)
        if result.status == RotationStatus.REUSED:
            if result.revoked is not None:
                await self._repository.audit(
                    "REFRESH_TOKEN_REUSE_DETECTED",
                    "denied",
                    correlation_id,
                    result.revoked.user_id,
                    {"family_revoked": True},
                )
            raise SessionError(
                SessionErrorCode.TOKEN_REUSED,
                "This session may have been stolen and has been ended. Please sign in again.",
                401,
            )
        if result.status == RotationStatus.CLIENT_MISMATCH:
            raise SessionError(
                SessionErrorCode.CLIENT_MISMATCH,
                "This refresh token does not belong to this client or device.",
                401,
            )
        if result.status == RotationStatus.EXPIRED:
            raise SessionError(
                SessionErrorCode.SESSION_EXPIRED,
                "This session has expired. Please sign in again.",
                401,
            )
        if result.status != RotationStatus.ROTATED or result.record is None:
            raise self._token_invalid()
        record = result.record
        access_token, access_expires_at = self._tokens.issue(
            record.user_id,
            record.session_id,
            record.family_id,
            new_jti,
            client_type,
            ("refresh_token",),
            now,
        )
        await self._repository.audit(
            "SESSION_REFRESHED",
            "success",
            correlation_id,
            record.user_id,
            {"client_type": client_type.value},
        )
        csrf_token = secrets.token_urlsafe(32) if client_type == ClientType.WEB else None
        return TokenPair(
            access_token,
            replacement,
            access_expires_at,
            record.expires_at,
            record.session_id,
            csrf_token,
        )

    async def authenticate(self, access_token: str) -> AccessClaims:
        now = datetime.now(UTC)
        claims = self._tokens.verify(access_token, now)
        if await self._redis.access_token_is_revoked(claims.jti):
            raise self._token_invalid()
        if await self._redis.family_is_revoked(claims.family_id):
            raise self._token_invalid()
        revoked_at = await self._redis.user_revoked_at(claims.user_id)
        if revoked_at is not None and claims.issued_at <= revoked_at:
            raise self._token_invalid()
        if not await self._repository.session_is_active(claims.session_id, now):
            raise self._token_invalid()
        return claims

    async def logout(self, claims: AccessClaims, correlation_id: UUID) -> None:
        now = datetime.now(UTC)
        result = await self._repository.revoke_session(
            claims.user_id, claims.session_id, "logout", now
        )
        if result is not None:
            await self._apply_revocation(result, now)
        await self._repository.audit(
            "SESSION_LOGGED_OUT",
            "success",
            correlation_id,
            claims.user_id,
            {"session_id": str(claims.session_id)},
        )

    async def logout_all(self, claims: AccessClaims, correlation_id: UUID) -> int:
        now = datetime.now(UTC)
        results = await self._repository.revoke_all(claims.user_id, "logout_all", now)
        await self._redis.revoke_user(claims.user_id, now)
        for item in results:
            await self._apply_revocation(item, now)
        await self._repository.audit(
            "ALL_SESSIONS_LOGGED_OUT",
            "success",
            correlation_id,
            claims.user_id,
            {"revoked_sessions": len(results)},
        )
        return len(results)

    async def sessions(self, claims: AccessClaims) -> tuple[SessionSummary, ...]:
        values = await self._repository.list_sessions(claims.user_id, datetime.now(UTC))
        return tuple(
            replace(item, current=item.session_id == claims.session_id) for item in values
        )

    async def revoke_selected(
        self, claims: AccessClaims, session_id: UUID, correlation_id: UUID
    ) -> None:
        now = datetime.now(UTC)
        result = await self._repository.revoke_session(
            claims.user_id, session_id, "user_selected", now
        )
        if result is None:
            raise SessionError(
                SessionErrorCode.SESSION_NOT_FOUND,
                "The selected session was not found.",
                404,
            )
        await self._apply_revocation(result, now)
        await self._repository.audit(
            "SESSION_REVOKED",
            "success",
            correlation_id,
            claims.user_id,
            {"session_id": str(session_id)},
        )

    async def _apply_revocation(self, value: RevocationResult, now: datetime) -> None:
        await self._redis.revoke_access_token(value.access_jti, ACCESS_TTL_SECONDS)
        await self._redis.revoke_family(value.family_id, REFRESH_FAMILY_SECONDS)

    def _token_hash(self, value: str) -> str:
        return hmac.new(self._token_pepper, value.encode(), sha256).hexdigest()

    def _fingerprint_hash(self, value: str) -> str:
        return hmac.new(self._fingerprint_pepper, value.encode(), sha256).hexdigest()

    @staticmethod
    def _assurance(workflow: dict[str, object]) -> tuple[str, ...]:
        method = workflow.get("mfa_method") or workflow.get("primary_method") or "unknown"
        assurance = workflow.get("assurance")
        return (str(method), str(assurance)) if assurance else (str(method),)

    @staticmethod
    def _workflow_invalid() -> SessionError:
        return SessionError(
            SessionErrorCode.WORKFLOW_INVALID,
            "This session workflow is invalid or expired.",
            400,
        )

    @staticmethod
    def _token_invalid() -> SessionError:
        return SessionError(
            SessionErrorCode.TOKEN_INVALID,
            "The session token is invalid or expired.",
            401,
        )
