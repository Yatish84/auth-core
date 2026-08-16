from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_core.entity.session import (
    ClientType,
    CreatedSession,
    RevocationResult,
    RotationResult,
    RotationStatus,
    SessionRecord,
    SessionSummary,
)
from auth_core.infrastructure.persistence.models import (
    AuditLog,
    RefreshToken,
    RefreshTokenFamily,
    Session,
    User,
)

MAX_ACTIVE_SESSIONS = 10


class SqlAlchemySessionRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def user_is_active(self, user_id: UUID) -> bool:
        async with self._sessions() as session:
            user = await session.get(User, user_id)
            return bool(user and user.state == "active" and user.anonymized_at is None)

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
    ) -> CreatedSession:
        now = datetime.now(UTC)
        async with self._sessions.begin() as database:
            active_rows = (
                await database.execute(
                    select(RefreshTokenFamily, Session)
                    .join(Session, Session.family_id == RefreshTokenFamily.family_id)
                    .where(
                        RefreshTokenFamily.user_id == user_id,
                        RefreshTokenFamily.revoked_at.is_(None),
                        Session.revoked_at.is_(None),
                        Session.expires_at > now,
                    )
                    .order_by(Session.created_at.asc())
                    .with_for_update()
                )
            ).all()
            evicted: list[RevocationResult] = []
            overflow = max(0, len(active_rows) - MAX_ACTIVE_SESSIONS + 1)
            for family, existing_session in active_rows[:overflow]:
                family.revoked_at = now
                family.revocation_reason = "session_cap"
                existing_session.revoked_at = now
                await database.execute(
                    update(RefreshToken)
                    .where(RefreshToken.family_id == family.family_id)
                    .values(revoked_at=now)
                )
                evicted.append(
                    RevocationResult(user_id, family.family_id, existing_session.access_jti)
                )

            family_id = uuid4()
            session_id = uuid4()
            family = RefreshTokenFamily(
                family_id=family_id,
                user_id=user_id,
                device_fingerprint_hash=device_fingerprint_hash,
                client_id=client_type.value,
                created_at=now,
                absolute_expires_at=family_expires_at,
            )
            database.add(family)
            await database.flush()
            created_session = Session(
                session_id=session_id,
                family_id=family_id,
                user_id=user_id,
                access_jti=access_jti,
                client_id=client_type.value,
                device_fingerprint_hash=device_fingerprint_hash,
                ip_address=ip_address,
                created_at=now,
                last_activity_at=now,
                expires_at=session_expires_at,
            )
            refresh = RefreshToken(
                refresh_token_id=uuid4(),
                family_id=family_id,
                token_hash=refresh_token_hash,
                generation=0,
                issued_at=now,
                expires_at=refresh_expires_at,
            )
            database.add(created_session)
            await database.flush()
            database.add(refresh)
            return CreatedSession(self._record(created_session), tuple(evicted))

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
    ) -> RotationResult:
        async with self._sessions.begin() as database:
            row = (
                await database.execute(
                    select(RefreshToken, RefreshTokenFamily, Session)
                    .join(
                        RefreshTokenFamily,
                        RefreshTokenFamily.family_id == RefreshToken.family_id,
                    )
                    .join(Session, Session.family_id == RefreshTokenFamily.family_id)
                    .where(RefreshToken.token_hash == token_hash)
                    .with_for_update()
                )
            ).one_or_none()
            if row is None:
                return RotationResult(RotationStatus.INVALID)
            token, family, active_session = row
            revoked = RevocationResult(
                active_session.user_id, family.family_id, active_session.access_jti
            )
            if token.used_at is not None:
                await self._revoke_locked(database, family, active_session, now, "token_reuse")
                return RotationResult(RotationStatus.REUSED, revoked=revoked)
            if (
                token.revoked_at is not None
                or family.revoked_at is not None
                or active_session.revoked_at is not None
            ):
                return RotationResult(RotationStatus.INVALID)
            expired = (
                token.expires_at <= now
                or family.absolute_expires_at <= now
                or active_session.expires_at <= now
                or active_session.last_activity_at
                + timedelta(seconds=idle_timeout_seconds)
                <= now
            )
            if expired:
                await self._revoke_locked(database, family, active_session, now, "expired")
                return RotationResult(RotationStatus.EXPIRED, revoked=revoked)
            if (
                family.client_id != client_type.value
                or family.device_fingerprint_hash != device_fingerprint_hash
            ):
                await self._revoke_locked(
                    database, family, active_session, now, "client_mismatch"
                )
                return RotationResult(RotationStatus.CLIENT_MISMATCH, revoked=revoked)

            token.used_at = now
            token.revoked_at = now
            database.add(
                RefreshToken(
                    refresh_token_id=uuid4(),
                    family_id=family.family_id,
                    token_hash=replacement_hash,
                    generation=token.generation + 1,
                    issued_at=now,
                    expires_at=min(replacement_expires_at, family.absolute_expires_at),
                )
            )
            active_session.access_jti = new_access_jti
            active_session.last_activity_at = now
            return RotationResult(
                RotationStatus.ROTATED,
                record=self._record(active_session),
                revoked=revoked,
            )

    async def revoke_session(
        self, user_id: UUID, session_id: UUID, reason: str, now: datetime
    ) -> RevocationResult | None:
        async with self._sessions.begin() as database:
            row = (
                await database.execute(
                    select(Session, RefreshTokenFamily)
                    .join(
                        RefreshTokenFamily,
                        RefreshTokenFamily.family_id == Session.family_id,
                    )
                    .where(Session.session_id == session_id, Session.user_id == user_id)
                    .with_for_update()
                )
            ).one_or_none()
            if row is None:
                return None
            active_session, family = row
            result = RevocationResult(
                active_session.user_id, family.family_id, active_session.access_jti
            )
            await self._revoke_locked(database, family, active_session, now, reason)
            return result

    async def revoke_all(
        self, user_id: UUID, reason: str, now: datetime
    ) -> tuple[RevocationResult, ...]:
        async with self._sessions.begin() as database:
            rows = (
                await database.execute(
                    select(Session, RefreshTokenFamily)
                    .join(
                        RefreshTokenFamily,
                        RefreshTokenFamily.family_id == Session.family_id,
                    )
                    .where(
                        Session.user_id == user_id,
                        Session.revoked_at.is_(None),
                        RefreshTokenFamily.revoked_at.is_(None),
                    )
                    .with_for_update()
                )
            ).all()
            results: list[RevocationResult] = []
            for active_session, family in rows:
                results.append(
                    RevocationResult(
                        active_session.user_id, family.family_id, active_session.access_jti
                    )
                )
                await self._revoke_locked(database, family, active_session, now, reason)
            return tuple(results)

    async def list_sessions(
        self, user_id: UUID, now: datetime
    ) -> tuple[SessionSummary, ...]:
        async with self._sessions() as database:
            rows = (
                await database.scalars(
                    select(Session)
                    .join(
                        RefreshTokenFamily,
                        RefreshTokenFamily.family_id == Session.family_id,
                    )
                    .where(
                        Session.user_id == user_id,
                        Session.revoked_at.is_(None),
                        Session.expires_at > now,
                        RefreshTokenFamily.revoked_at.is_(None),
                        RefreshTokenFamily.absolute_expires_at > now,
                    )
                    .order_by(Session.last_activity_at.desc())
                )
            ).all()
            return tuple(
                SessionSummary(
                    session_id=item.session_id,
                    client_type=ClientType(item.client_id),
                    device_hint=f"{item.device_fingerprint_hash[:8]}…",
                    ip_address=str(item.ip_address) if item.ip_address else None,
                    created_at=item.created_at,
                    last_activity_at=item.last_activity_at,
                    expires_at=item.expires_at,
                    current=False,
                )
                for item in rows
            )

    async def session_is_active(self, session_id: UUID, now: datetime) -> bool:
        async with self._sessions() as database:
            value = await database.scalar(
                select(Session.session_id)
                .join(
                    RefreshTokenFamily,
                    RefreshTokenFamily.family_id == Session.family_id,
                )
                .where(
                    Session.session_id == session_id,
                    Session.revoked_at.is_(None),
                    Session.expires_at > now,
                    RefreshTokenFamily.revoked_at.is_(None),
                    RefreshTokenFamily.absolute_expires_at > now,
                )
            )
            return value is not None

    async def audit(
        self,
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        user_id: UUID,
        metadata: dict[str, str | int | bool],
    ) -> None:
        async with self._sessions.begin() as database:
            database.add(
                AuditLog(
                    actor_user_id=user_id,
                    subject_user_id=user_id,
                    event_type=event_type,
                    outcome=outcome,
                    correlation_id=correlation_id,
                    metadata_json=metadata,
                )
            )

    @staticmethod
    async def _revoke_locked(
        database: AsyncSession,
        family: RefreshTokenFamily,
        active_session: Session,
        now: datetime,
        reason: str,
    ) -> None:
        family.revoked_at = family.revoked_at or now
        family.revocation_reason = family.revocation_reason or reason
        active_session.revoked_at = active_session.revoked_at or now
        await database.execute(
            update(RefreshToken)
            .where(
                RefreshToken.family_id == family.family_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )

    @staticmethod
    def _record(value: Session) -> SessionRecord:
        return SessionRecord(
            session_id=value.session_id,
            family_id=value.family_id,
            user_id=value.user_id,
            access_jti=value.access_jti,
            client_type=ClientType(value.client_id),
            device_fingerprint_hash=value.device_fingerprint_hash,
            ip_address=str(value.ip_address) if value.ip_address else None,
            created_at=value.created_at,
            last_activity_at=value.last_activity_at,
            expires_at=value.expires_at,
            revoked_at=value.revoked_at,
        )
