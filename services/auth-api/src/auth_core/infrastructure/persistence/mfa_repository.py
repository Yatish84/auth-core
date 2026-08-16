import hmac
import json
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_core.entity.mfa import MFAFactor, MFAUserProfile, StoredPasskey
from auth_core.infrastructure.persistence.models import (
    AuditLog,
    Identity,
    MFADevice,
    User,
    WebAuthnCredential,
)


class SqlAlchemyMFARepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def user_profile(self, user_id: UUID) -> MFAUserProfile | None:
        async with self._sessions() as session:
            user = await session.get(User, user_id)
            if user is None or user.anonymized_at is not None:
                return None
            identities = (
                await session.scalars(
                    select(Identity).where(
                        Identity.user_id == user_id, Identity.verified.is_(True)
                    )
                )
            ).all()
            has_email_identity = any(
                identity.provider in {"password", "google", "apple", "microsoft"}
                for identity in identities
            )
            has_phone_identity = any(
                identity.provider == "phone" for identity in identities
            )
            return MFAUserProfile(
                user.user_id,
                user.state,
                user.email if has_email_identity else None,
                user.phone_e164 if has_phone_identity else None,
            )

    async def password_hash(self, user_id: UUID) -> str | None:
        async with self._sessions() as session:
            identity = await session.scalar(
                select(Identity).where(
                    Identity.user_id == user_id,
                    Identity.provider == "password",
                    Identity.verified.is_(True),
                )
            )
            return identity.password_hash if identity else None

    async def active_factors(self, user_id: UUID) -> tuple[MFAFactor, ...]:
        async with self._sessions() as session:
            factors = (
                await session.scalars(
                    select(MFADevice).where(
                        MFADevice.user_id == user_id, MFADevice.status == "active"
                    )
                )
            ).all()
            return tuple(self._factor(item) for item in factors)

    async def create_pending_totp(
        self, user_id: UUID, encrypted_secret: bytes, label: str
    ) -> MFAFactor:
        async with self._sessions.begin() as session:
            pending = (
                await session.scalars(
                    select(MFADevice)
                    .where(
                        MFADevice.user_id == user_id,
                        MFADevice.factor_type == "totp",
                        MFADevice.status == "pending",
                    )
                    .with_for_update()
                )
            ).all()
            for factor in pending:
                factor.status = "revoked"
                factor.revoked_at = datetime.now(UTC)
            created = MFADevice(
                user_id=user_id,
                factor_type="totp",
                encrypted_secret=encrypted_secret,
                status="pending",
                label=label,
            )
            session.add(created)
            await session.flush()
            return self._factor(created)

    async def factor(self, user_id: UUID, mfa_id: UUID) -> MFAFactor | None:
        async with self._sessions() as session:
            factor = await session.scalar(
                select(MFADevice).where(
                    MFADevice.user_id == user_id, MFADevice.mfa_id == mfa_id
                )
            )
            return self._factor(factor) if factor else None

    async def activate_totp(
        self, user_id: UUID, mfa_id: UUID, accepted_step: int
    ) -> bool:
        async with self._sessions.begin() as session:
            factor = await session.scalar(
                select(MFADevice)
                .where(
                    MFADevice.user_id == user_id,
                    MFADevice.mfa_id == mfa_id,
                    MFADevice.factor_type == "totp",
                    MFADevice.status == "pending",
                )
                .with_for_update()
            )
            if factor is None:
                return False
            now = datetime.now(UTC)
            factor.status = "active"
            factor.verified_at = now
            factor.last_used_at = now
            factor.last_totp_step = accepted_step
            return True

    async def advance_totp_step(
        self, mfa_id: UUID, previous_step: int | None, accepted_step: int
    ) -> bool:
        condition = (
            MFADevice.last_totp_step.is_(None)
            if previous_step is None
            else MFADevice.last_totp_step == previous_step
        )
        async with self._sessions.begin() as session:
            result = await session.execute(
                update(MFADevice)
                .where(
                    MFADevice.mfa_id == mfa_id,
                    MFADevice.status == "active",
                    condition,
                )
                .values(last_totp_step=accepted_step, last_used_at=datetime.now(UTC))
            )
            return bool(getattr(result, "rowcount", 0))

    async def store_backup_codes(self, user_id: UUID, hashes: tuple[str, ...]) -> None:
        encoded = json.dumps(list(hashes), separators=(",", ":")).encode()
        async with self._sessions.begin() as session:
            factor = await session.scalar(
                select(MFADevice)
                .where(
                    MFADevice.user_id == user_id,
                    MFADevice.factor_type == "backup_codes",
                    MFADevice.status == "active",
                )
                .with_for_update()
            )
            if factor is None:
                session.add(
                    MFADevice(
                        user_id=user_id,
                        factor_type="backup_codes",
                        encrypted_secret=encoded,
                        status="active",
                        label="Recovery codes",
                        verified_at=datetime.now(UTC),
                    )
                )
            else:
                factor.encrypted_secret = encoded
                factor.last_used_at = None

    async def consume_backup_code(self, user_id: UUID, candidate_hash: str) -> bool:
        async with self._sessions.begin() as session:
            factor = await session.scalar(
                select(MFADevice)
                .where(
                    MFADevice.user_id == user_id,
                    MFADevice.factor_type == "backup_codes",
                    MFADevice.status == "active",
                )
                .with_for_update()
            )
            if factor is None or factor.encrypted_secret is None:
                return False
            hashes = [str(value) for value in json.loads(factor.encrypted_secret)]
            match = next(
                (value for value in hashes if hmac.compare_digest(value, candidate_hash)),
                None,
            )
            if match is None:
                return False
            hashes.remove(match)
            factor.encrypted_secret = json.dumps(hashes, separators=(",", ":")).encode()
            factor.last_used_at = datetime.now(UTC)
            if not hashes:
                factor.status = "revoked"
                factor.revoked_at = datetime.now(UTC)
            return True

    async def passkeys(self, user_id: UUID) -> tuple[StoredPasskey, ...]:
        async with self._sessions() as session:
            rows = (
                await session.execute(
                    select(WebAuthnCredential, MFADevice)
                    .join(MFADevice, MFADevice.mfa_id == WebAuthnCredential.mfa_id)
                    .where(
                        MFADevice.user_id == user_id,
                        MFADevice.status == "active",
                    )
                )
            ).all()
            return tuple(self._passkey(credential, factor) for credential, factor in rows)

    async def passkey(self, credential_id: bytes) -> StoredPasskey | None:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(WebAuthnCredential, MFADevice)
                    .join(MFADevice, MFADevice.mfa_id == WebAuthnCredential.mfa_id)
                    .where(
                        WebAuthnCredential.credential_id == credential_id,
                        MFADevice.status == "active",
                    )
                )
            ).one_or_none()
            return self._passkey(*row) if row else None

    async def create_passkey(
        self,
        user_id: UUID,
        label: str,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: tuple[str, ...],
        backup_eligible: bool,
        backup_state: bool,
    ) -> None:
        async with self._sessions.begin() as session:
            factor = MFADevice(
                user_id=user_id,
                factor_type="passkey",
                status="active",
                label=label,
                verified_at=datetime.now(UTC),
            )
            session.add(factor)
            await session.flush()
            session.add(
                WebAuthnCredential(
                    credential_id=credential_id,
                    mfa_id=factor.mfa_id,
                    public_key=public_key,
                    sign_count=sign_count,
                    transports=list(transports),
                    backup_eligible=backup_eligible,
                    backup_state=backup_state,
                )
            )

    async def update_passkey_counter(
        self,
        credential_id: bytes,
        previous_count: int,
        new_count: int,
        backup_state: bool,
    ) -> bool:
        async with self._sessions.begin() as session:
            result = await session.execute(
                update(WebAuthnCredential)
                .where(
                    WebAuthnCredential.credential_id == credential_id,
                    WebAuthnCredential.sign_count == previous_count,
                )
                .values(sign_count=new_count, backup_state=backup_state)
            )
            return bool(getattr(result, "rowcount", 0))

    async def revoke_factor(self, user_id: UUID, mfa_id: UUID) -> bool:
        async with self._sessions.begin() as session:
            factor = await session.scalar(
                select(MFADevice)
                .where(
                    MFADevice.user_id == user_id,
                    MFADevice.mfa_id == mfa_id,
                    MFADevice.status == "active",
                )
                .with_for_update()
            )
            if factor is None:
                return False
            factor.status = "revoked"
            factor.revoked_at = datetime.now(UTC)
            return True

    async def link_oidc_identity(self, user_id: UUID, provider: str, subject: str) -> bool:
        try:
            async with self._sessions.begin() as session:
                session.add(
                    Identity(
                        user_id=user_id,
                        provider=provider,
                        provider_subject=subject,
                        verified=True,
                    )
                )
            return True
        except IntegrityError:
            return False

    async def audit(
        self,
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        user_id: UUID | None,
        metadata: dict[str, str],
    ) -> None:
        async with self._sessions.begin() as session:
            session.add(
                AuditLog(
                    subject_user_id=user_id,
                    event_type=event_type,
                    outcome=outcome,
                    correlation_id=correlation_id,
                    metadata_json=metadata,
                )
            )

    @staticmethod
    def _factor(item: MFADevice) -> MFAFactor:
        return MFAFactor(
            item.mfa_id,
            item.user_id,
            item.factor_type,
            item.status,
            item.label,
            item.encrypted_secret,
            item.last_totp_step,
        )

    @staticmethod
    def _passkey(
        credential: WebAuthnCredential, factor: MFADevice
    ) -> StoredPasskey:
        return StoredPasskey(
            credential.credential_id,
            factor.mfa_id,
            factor.user_id,
            credential.public_key,
            credential.sign_count,
            tuple(credential.transports),
            credential.backup_eligible,
            credential.backup_state,
        )
