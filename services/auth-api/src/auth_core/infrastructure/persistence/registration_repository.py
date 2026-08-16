from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_core.entity.registration import DuplicateContactError, PendingContact
from auth_core.entity.user import normalize_email
from auth_core.infrastructure.persistence.models import AuditLog, EphemeralToken, Identity, User


class SqlAlchemyRegistrationRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def get_by_email(self, email: str) -> PendingContact | None:
        async with self._sessions() as session:
            user = await session.scalar(
                select(User).where(
                    User.email == normalize_email(email), User.anonymized_at.is_(None)
                )
            )
            return self._pending_contact(user)

    async def get_by_phone(self, phone_e164: str) -> PendingContact | None:
        async with self._sessions() as session:
            user = await session.scalar(
                select(User).where(
                    User.phone_e164 == phone_e164, User.anonymized_at.is_(None)
                )
            )
            return self._pending_contact(user)

    async def create_email_registration(
        self,
        email: str,
        given_name: str,
        family_name: str,
        password_hash: str,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> UUID:
        try:
            async with self._sessions.begin() as session:
                user = User(
                    email=normalize_email(email),
                    given_name=given_name.strip(),
                    family_name=family_name.strip(),
                )
                session.add(user)
                await session.flush()
                session.add_all(
                    [
                        Identity(
                            user_id=user.user_id,
                            provider="password",
                            provider_subject=normalize_email(email),
                            password_hash=password_hash,
                        ),
                        EphemeralToken(
                            user_id=user.user_id,
                            token_hash=token_hash,
                            purpose="email_verify",
                            expires_at=expires_at,
                        ),
                        self._audit(
                            "USER_REGISTRATION_PENDING",
                            "success",
                            correlation_id,
                            user.user_id,
                            {"method": "email"},
                        ),
                    ]
                )
                await session.flush()
                return user.user_id
        except IntegrityError as error:
            raise DuplicateContactError from error

    async def issue_email_verification(
        self,
        user_id: UUID,
        token_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> None:
        now = datetime.now(UTC)
        async with self._sessions.begin() as session:
            await session.execute(
                update(EphemeralToken)
                .where(
                    EphemeralToken.user_id == user_id,
                    EphemeralToken.purpose == "email_verify",
                    EphemeralToken.consumed_at.is_(None),
                )
                .values(consumed_at=now)
            )
            session.add_all(
                [
                    EphemeralToken(
                        user_id=user_id,
                        token_hash=token_hash,
                        purpose="email_verify",
                        expires_at=expires_at,
                    ),
                    self._audit(
                        "EMAIL_VERIFICATION_REISSUED",
                        "success",
                        correlation_id,
                        user_id,
                        {},
                    ),
                ]
            )

    async def verify_email(self, token_hash: str, now: datetime, correlation_id: UUID) -> bool:
        async with self._sessions.begin() as session:
            token = await session.scalar(
                select(EphemeralToken)
                .where(
                    EphemeralToken.token_hash == token_hash,
                    EphemeralToken.purpose == "email_verify",
                )
                .with_for_update()
            )
            if (
                token is None
                or token.user_id is None
                or token.consumed_at is not None
                or token.expires_at <= now
            ):
                return False
            token.consumed_at = now
            user = await session.get(User, token.user_id, with_for_update=True)
            if user is None or user.state not in {"pending", "active"}:
                return False
            user.state = "active"
            user.version += 1
            await session.execute(
                update(Identity)
                .where(Identity.user_id == user.user_id, Identity.provider == "password")
                .values(verified=True)
            )
            session.add(
                self._audit(
                    "EMAIL_VERIFIED", "success", correlation_id, user.user_id, {}
                )
            )
            return True

    async def create_phone_registration(
        self,
        phone_e164: str,
        given_name: str | None,
        family_name: str | None,
        correlation_id: UUID,
    ) -> UUID:
        try:
            async with self._sessions.begin() as session:
                user = User(
                    phone_e164=phone_e164,
                    given_name=given_name.strip() if given_name else None,
                    family_name=family_name.strip() if family_name else None,
                )
                session.add(user)
                await session.flush()
                session.add_all(
                    [
                        Identity(
                            user_id=user.user_id,
                            provider="phone",
                            provider_subject=phone_e164,
                        ),
                        self._audit(
                            "USER_REGISTRATION_PENDING",
                            "success",
                            correlation_id,
                            user.user_id,
                            {"method": "phone"},
                        ),
                    ]
                )
                await session.flush()
                return user.user_id
        except IntegrityError as error:
            raise DuplicateContactError from error

    async def verify_phone(self, user_id: UUID, correlation_id: UUID) -> bool:
        async with self._sessions.begin() as session:
            user = await session.get(User, user_id, with_for_update=True)
            if user is None or user.state not in {"pending", "active"}:
                return False
            user.state = "active"
            user.version += 1
            identity = await session.scalar(
                select(Identity)
                .where(Identity.user_id == user.user_id, Identity.provider == "phone")
                .with_for_update()
            )
            if identity is None:
                return False
            identity.verified = True
            session.add(
                self._audit("PHONE_VERIFIED", "success", correlation_id, user.user_id, {})
            )
            return True

    @staticmethod
    def _pending_contact(user: User | None) -> PendingContact | None:
        if user is None:
            return None
        return PendingContact(user_id=user.user_id, state=user.state)

    @staticmethod
    def _audit(
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        subject_user_id: UUID,
        metadata: dict[str, str],
    ) -> AuditLog:
        return AuditLog(
            subject_user_id=subject_user_id,
            event_type=event_type,
            outcome=outcome,
            correlation_id=correlation_id,
            metadata_json=metadata,
        )
