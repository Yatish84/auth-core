from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_core.entity.login import DeviceSignals, LoginIdentity, OIDCProfile
from auth_core.entity.registration import DuplicateContactError
from auth_core.entity.user import normalize_email
from auth_core.infrastructure.persistence.models import (
    AuditLog,
    Identity,
    MFADevice,
    TrustedDevice,
    User,
)


class SqlAlchemyLoginRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def password_identity(self, email: str) -> LoginIdentity | None:
        return await self._identity("password", normalize_email(email))

    async def phone_identity(self, phone_e164: str) -> LoginIdentity | None:
        return await self._identity("phone", phone_e164)

    async def oidc_identity(self, provider: str, subject: str) -> LoginIdentity | None:
        return await self._identity(provider, subject)

    async def active_user_by_email(self, email: str) -> LoginIdentity | None:
        async with self._sessions() as session:
            user = await session.scalar(
                select(User).where(
                    User.email == normalize_email(email), User.anonymized_at.is_(None)
                )
            )
            if user is None:
                return None
            return LoginIdentity(
                user.user_id, user.state, None, user.state == "active", user.phone_e164 is not None
            )

    async def provision_oidc(self, profile: OIDCProfile, correlation_id: UUID) -> LoginIdentity:
        try:
            async with self._sessions.begin() as session:
                user = User(
                    email=normalize_email(profile.email),
                    given_name=profile.given_name,
                    family_name=profile.family_name,
                    state="active",
                )
                session.add(user)
                await session.flush()
                session.add_all(
                    [
                        Identity(
                            user_id=user.user_id,
                            provider=profile.provider,
                            provider_subject=profile.subject,
                            verified=True,
                        ),
                        self._audit_model(
                            "OIDC_USER_PROVISIONED",
                            "success",
                            correlation_id,
                            user.user_id,
                            {"provider": profile.provider},
                        ),
                    ]
                )
                await session.flush()
                return LoginIdentity(user.user_id, "active", None, True, False)
        except IntegrityError as error:
            raise DuplicateContactError from error

    async def device_signals(
        self, user_id: UUID, fingerprint_hash: str, ip_address: str | None
    ) -> DeviceSignals:
        async with self._sessions.begin() as session:
            device = await session.scalar(
                select(TrustedDevice)
                .where(
                    TrustedDevice.user_id == user_id,
                    TrustedDevice.fingerprint_hash == fingerprint_hash,
                )
                .with_for_update()
            )
            if device is None:
                session.add(
                    TrustedDevice(
                        user_id=user_id,
                        fingerprint_hash=fingerprint_hash,
                        last_ip_address=ip_address,
                    )
                )
                return DeviceSignals(known=False, trusted=False, ip_changed=False)
            ip_changed = bool(
                ip_address and device.last_ip_address and str(device.last_ip_address) != ip_address
            )
            device.last_ip_address = ip_address
            device.last_seen_at = datetime.now(UTC)
            return DeviceSignals(
                known=True, trusted=device.trust_state == "trusted", ip_changed=ip_changed
            )

    async def fallback_methods(self, user_id: UUID) -> tuple[str, ...]:
        async with self._sessions() as session:
            identities = (
                await session.scalars(
                    select(Identity).where(Identity.user_id == user_id, Identity.verified.is_(True))
                )
            ).all()
            factors = (
                await session.scalars(
                    select(MFADevice).where(
                        MFADevice.user_id == user_id, MFADevice.status == "active"
                    )
                )
            ).all()
        methods = {
            "password"
            if identity.provider == "password"
            else "phone_otp"
            if identity.provider == "phone"
            else identity.provider
            for identity in identities
        }
        methods.update(factor.factor_type for factor in factors)
        return tuple(sorted(methods))

    async def update_password_hash(self, user_id: UUID, password_hash: str) -> None:
        async with self._sessions.begin() as session:
            identity = await session.scalar(
                select(Identity)
                .where(Identity.user_id == user_id, Identity.provider == "password")
                .with_for_update()
            )
            if identity is not None:
                identity.password_hash = password_hash

    async def audit(
        self,
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        subject_user_id: UUID | None,
        metadata: dict[str, str],
    ) -> None:
        async with self._sessions.begin() as session:
            session.add(
                self._audit_model(event_type, outcome, correlation_id, subject_user_id, metadata)
            )

    async def _identity(self, provider: str, subject: str) -> LoginIdentity | None:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(User, Identity)
                    .join(Identity, Identity.user_id == User.user_id)
                    .where(
                        Identity.provider == provider,
                        Identity.provider_subject == subject,
                        User.anonymized_at.is_(None),
                    )
                )
            ).one_or_none()
            if row is None:
                return None
            user, identity = row
            return LoginIdentity(
                user.user_id,
                user.state,
                identity.password_hash,
                identity.verified,
                user.phone_e164 is not None,
            )

    @staticmethod
    def _audit_model(
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        subject_user_id: UUID | None,
        metadata: dict[str, str],
    ) -> AuditLog:
        return AuditLog(
            subject_user_id=subject_user_id,
            event_type=event_type,
            outcome=outcome,
            correlation_id=correlation_id,
            metadata_json=metadata,
        )
