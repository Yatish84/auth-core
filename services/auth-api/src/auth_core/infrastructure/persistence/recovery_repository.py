import hmac
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_core.control.ports.recovery import PasswordHasher
from auth_core.entity.recovery import (
    ContactChangeRecord,
    ContactProof,
    ContactType,
    GovernedResetRecord,
    PasswordResetOutcome,
    RecoveryError,
    RecoveryErrorCode,
    RecoveryUser,
    StaffRole,
)
from auth_core.infrastructure.persistence.models import (
    AuditLog,
    ContactChangeRequest,
    EphemeralToken,
    GovernedRequest,
    Identity,
    MFADevice,
    PasswordHistory,
    StaffRoleBinding,
    User,
)
from auth_core.infrastructure.persistence.tenant_context import set_user_context

PASSWORD_HISTORY_LIMIT = 5


class SqlAlchemyRecoveryRepository:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        password_hasher: PasswordHasher,
    ) -> None:
        self._sessions = sessions
        self._password_hasher = password_hasher

    async def eligible_user_by_email(self, email: str) -> RecoveryUser | None:
        async with self._sessions() as database:
            user = await database.scalar(
                select(User).where(User.email == email, User.anonymized_at.is_(None))
            )
            if user is None or user.state not in {"active", "locked"}:
                return None
            password_identity = await database.scalar(
                select(Identity.identity_id).where(
                    Identity.user_id == user.user_id,
                    Identity.provider == "password",
                    Identity.verified.is_(True),
                )
            )
            return self._user(user) if password_identity is not None else None

    async def issue_password_reset(
        self,
        user_id: UUID,
        token_hash: str,
        purpose: str,
        expires_at: datetime,
        correlation_id: UUID,
        actor_user_id: UUID | None = None,
        ticket_reference: str | None = None,
    ) -> None:
        now = datetime.now(UTC)
        async with self._sessions.begin() as database:
            await set_user_context(database, actor_user_id or user_id)
            await database.execute(
                update(EphemeralToken)
                .where(
                    EphemeralToken.user_id == user_id,
                    EphemeralToken.purpose.in_(("password_reset", "support_recovery")),
                    EphemeralToken.consumed_at.is_(None),
                )
                .values(consumed_at=now)
            )
            database.add(
                EphemeralToken(
                    user_id=user_id,
                    token_hash=token_hash,
                    purpose=purpose,
                    metadata_json={"ticket_reference": ticket_reference}
                    if ticket_reference
                    else {},
                    expires_at=expires_at,
                )
            )
            database.add(
                self._audit(
                    "PASSWORD_RESET_REQUESTED"
                    if purpose == "password_reset"
                    else "SUPPORT_RECOVERY_ISSUED",
                    "success",
                    correlation_id,
                    user_id,
                    actor_user_id,
                    {"ticket_reference": ticket_reference} if ticket_reference else {},
                )
            )

    async def consume_password_reset(
        self,
        token_hash: str,
        password: str,
        password_hash: str,
        now: datetime,
        correlation_id: UUID,
    ) -> tuple[PasswordResetOutcome, RecoveryUser | None]:
        async with self._sessions.begin() as database:
            token = await database.scalar(
                select(EphemeralToken)
                .where(
                    EphemeralToken.token_hash == token_hash,
                    EphemeralToken.purpose.in_(("password_reset", "support_recovery")),
                )
                .with_for_update()
            )
            if (
                token is None
                or token.user_id is None
                or token.consumed_at is not None
                or token.expires_at <= now
            ):
                return PasswordResetOutcome.INVALID, None
            user = await database.get(User, token.user_id, with_for_update=True)
            identity = await database.scalar(
                select(Identity)
                .where(Identity.user_id == token.user_id, Identity.provider == "password")
                .with_for_update()
            )
            if (
                user is None
                or identity is None
                or user.state in {"suspended", "disabled", "anonymized"}
            ):
                return PasswordResetOutcome.INVALID, None
            history = (
                await database.scalars(
                    select(PasswordHistory)
                    .where(PasswordHistory.identity_id == identity.identity_id)
                    .order_by(PasswordHistory.created_at.desc())
                    .limit(PASSWORD_HISTORY_LIMIT)
                )
            ).all()
            if any(self._password_hasher.verify(item.password_hash, password) for item in history):
                return PasswordResetOutcome.REUSED, self._user(user)
            token.consumed_at = now
            identity.password_hash = password_hash
            identity.last_used_at = now
            database.add(
                PasswordHistory(identity_id=identity.identity_id, password_hash=password_hash)
            )
            old_history_ids = (
                await database.scalars(
                    select(PasswordHistory.history_id)
                    .where(PasswordHistory.identity_id == identity.identity_id)
                    .order_by(PasswordHistory.created_at.desc())
                    .offset(PASSWORD_HISTORY_LIMIT - 1)
                )
            ).all()
            if old_history_ids:
                await database.execute(
                    delete(PasswordHistory).where(PasswordHistory.history_id.in_(old_history_ids))
                )
            if user.state == "locked":
                user.state = "active"
            user.version += 1
            database.add(
                self._audit(
                    "PASSWORD_RESET_COMPLETED",
                    "success",
                    correlation_id,
                    user.user_id,
                    user.user_id,
                    {"source": token.purpose},
                )
            )
            return PasswordResetOutcome.UPDATED, self._user(user)

    async def create_contact_change(
        self,
        user_id: UUID,
        contact_type: ContactType,
        new_value: str,
        old_code_hash: str,
        new_code_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> ContactChangeRecord | None:
        async with self._sessions.begin() as database:
            await set_user_context(database, user_id)
            user = await database.get(User, user_id, with_for_update=True)
            if user is None or user.state != "active":
                return None
            old_value = user.email if contact_type is ContactType.EMAIL else user.phone_e164
            if not old_value or old_value == new_value:
                return None
            conflict = await database.scalar(
                select(User.user_id).where(
                    (User.email == new_value)
                    if contact_type is ContactType.EMAIL
                    else (User.phone_e164 == new_value),
                    User.user_id != user_id,
                    User.anonymized_at.is_(None),
                )
            )
            if conflict is not None:
                raise RecoveryError(
                    RecoveryErrorCode.CONTACT_CONFLICT,
                    "That contact is already associated with another account.",
                    409,
                )
            await database.execute(
                update(ContactChangeRequest)
                .where(
                    ContactChangeRequest.user_id == user_id,
                    ContactChangeRequest.contact_type == contact_type.value,
                    ContactChangeRequest.state == "pending",
                )
                .values(state="cancelled")
            )
            request = ContactChangeRequest(
                user_id=user_id,
                contact_type=contact_type.value,
                old_value=old_value,
                new_value=new_value,
                old_code_hash=old_code_hash,
                new_code_hash=new_code_hash,
                expires_at=expires_at,
            )
            database.add(request)
            await database.flush()
            database.add(
                self._audit(
                    "CONTACT_CHANGE_STARTED",
                    "success",
                    correlation_id,
                    user_id,
                    user_id,
                    {"contact_type": contact_type.value},
                )
            )
            return self._contact(request)

    async def verify_contact_change(
        self,
        user_id: UUID,
        request_id: UUID,
        proof: ContactProof,
        code_hash: str,
        now: datetime,
        correlation_id: UUID,
    ) -> ContactChangeRecord | None:
        try:
            async with self._sessions.begin() as database:
                await set_user_context(database, user_id)
                request = await database.scalar(
                    select(ContactChangeRequest)
                    .where(
                        ContactChangeRequest.request_id == request_id,
                        ContactChangeRequest.user_id == user_id,
                    )
                    .with_for_update()
                )
                if request is None or request.state != "pending" or request.expires_at <= now:
                    return None
                expected = (
                    request.old_code_hash
                    if proof is ContactProof.OLD
                    else request.new_code_hash
                )
                if not hmac.compare_digest(expected, code_hash):
                    return None
                if proof is ContactProof.OLD:
                    request.old_verified_at = request.old_verified_at or now
                else:
                    request.new_verified_at = request.new_verified_at or now
                if request.old_verified_at is not None and request.new_verified_at is not None:
                    user = await database.get(User, user_id, with_for_update=True)
                    if user is None or user.state != "active":
                        return None
                    if request.contact_type == ContactType.EMAIL.value:
                        user.email = request.new_value
                        await database.execute(
                            update(Identity)
                            .where(
                                Identity.user_id == user_id,
                                Identity.provider == "password",
                            )
                            .values(provider_subject=request.new_value)
                        )
                    else:
                        user.phone_e164 = request.new_value
                        await database.execute(
                            update(Identity)
                            .where(Identity.user_id == user_id, Identity.provider == "phone")
                            .values(provider_subject=request.new_value)
                        )
                    user.version += 1
                    request.state = "applied"
                    request.applied_at = now
                    database.add(
                        self._audit(
                            "CONTACT_CHANGE_COMPLETED",
                            "success",
                            correlation_id,
                            user_id,
                            user_id,
                            {"contact_type": request.contact_type},
                        )
                    )
                return self._contact(request)
        except IntegrityError as error:
            raise RecoveryError(
                RecoveryErrorCode.CONTACT_CONFLICT,
                "That contact is already associated with another account.",
                409,
            ) from error

    async def staff_has_role(self, user_id: UUID, role: StaffRole) -> bool:
        async with self._sessions() as database:
            binding = await database.scalar(
                select(StaffRoleBinding.binding_id).where(
                    StaffRoleBinding.user_id == user_id,
                    StaffRoleBinding.role == role.value,
                    StaffRoleBinding.revoked_at.is_(None),
                )
            )
            return binding is not None

    async def unlock_user(
        self, actor_user_id: UUID, target_user_id: UUID, ticket_reference: str, correlation_id: UUID
    ) -> RecoveryUser | None:
        async with self._sessions.begin() as database:
            await set_user_context(database, actor_user_id)
            user = await database.get(User, target_user_id, with_for_update=True)
            if user is None or user.state not in {"active", "locked"}:
                return None
            user.state = "active"
            user.version += 1
            database.add(
                self._audit(
                    "ACCOUNT_UNLOCKED",
                    "success",
                    correlation_id,
                    target_user_id,
                    actor_user_id,
                    {"ticket_reference": ticket_reference},
                )
            )
            return self._user(user)

    async def suspend_user(
        self,
        actor_user_id: UUID,
        target_user_id: UUID,
        ticket_reference: str,
        reason: str,
        correlation_id: UUID,
    ) -> RecoveryUser | None:
        async with self._sessions.begin() as database:
            await set_user_context(database, actor_user_id)
            user = await database.get(User, target_user_id, with_for_update=True)
            if user is None or user.state in {"disabled", "anonymized"}:
                return None
            user.state = "suspended"
            user.version += 1
            database.add(
                self._audit(
                    "ACCOUNT_SUSPENDED",
                    "success",
                    correlation_id,
                    target_user_id,
                    actor_user_id,
                    {"ticket_reference": ticket_reference, "reason": reason},
                )
            )
            return self._user(user)

    async def initiate_mfa_reset(
        self,
        actor_user_id: UUID,
        target_user_id: UUID,
        ticket_reference: str,
        execute_after: datetime,
        correlation_id: UUID,
    ) -> tuple[GovernedResetRecord, RecoveryUser] | None:
        async with self._sessions.begin() as database:
            await set_user_context(database, actor_user_id)
            user = await database.get(User, target_user_id)
            if user is None or user.state not in {"active", "locked"}:
                return None
            request = GovernedRequest(
                request_type="mfa_reset",
                target_user_id=target_user_id,
                initiator_user_id=actor_user_id,
                execute_after=execute_after,
                target_user_version=user.version,
                ticket_reference=ticket_reference,
            )
            database.add(request)
            await database.flush()
            database.add(
                self._audit(
                    "ADMIN_MFA_RESET_INITIATED",
                    "success",
                    correlation_id,
                    target_user_id,
                    actor_user_id,
                    {"request_id": str(request.governed_request_id)},
                )
            )
            return self._governed(request), self._user(user)

    async def approve_mfa_reset(
        self,
        actor_user_id: UUID,
        request_id: UUID,
        now: datetime,
        correlation_id: UUID,
    ) -> GovernedResetRecord | None:
        async with self._sessions.begin() as database:
            await set_user_context(database, actor_user_id)
            request = await database.scalar(
                select(GovernedRequest)
                .where(
                    GovernedRequest.governed_request_id == request_id,
                    GovernedRequest.request_type == "mfa_reset",
                )
                .with_for_update()
            )
            if request is None or request.state != "pending":
                return None
            if request.initiator_user_id == actor_user_id:
                raise RecoveryError(
                    RecoveryErrorCode.FOUR_EYES_REQUIRED,
                    "A different security supervisor must approve this request.",
                    409,
                )
            user = await database.get(User, request.target_user_id)
            if user is None or user.version != request.target_user_version:
                request.state = "cancelled"
                raise RecoveryError(
                    RecoveryErrorCode.TARGET_CHANGED,
                    "The account changed after this request began. Start a new request.",
                    409,
                )
            request.approver_user_id = actor_user_id
            request.approved_at = now
            request.state = "approved"
            database.add(
                self._audit(
                    "ADMIN_MFA_RESET_APPROVED",
                    "success",
                    correlation_id,
                    request.target_user_id,
                    actor_user_id,
                    {"request_id": str(request_id)},
                )
            )
            return self._governed(request)

    async def get_mfa_reset(self, request_id: UUID) -> GovernedResetRecord | None:
        async with self._sessions() as database:
            request = await database.scalar(
                select(GovernedRequest).where(
                    GovernedRequest.governed_request_id == request_id,
                    GovernedRequest.request_type == "mfa_reset",
                )
            )
            return self._governed(request) if request else None

    async def execute_mfa_reset(
        self,
        actor_user_id: UUID,
        request_id: UUID,
        now: datetime,
        correlation_id: UUID,
    ) -> tuple[GovernedResetRecord, RecoveryUser] | None:
        async with self._sessions.begin() as database:
            await set_user_context(database, actor_user_id)
            request = await database.scalar(
                select(GovernedRequest)
                .where(
                    GovernedRequest.governed_request_id == request_id,
                    GovernedRequest.request_type == "mfa_reset",
                )
                .with_for_update()
            )
            if request is None or request.state != "approved" or request.approver_user_id is None:
                return None
            if request.execute_after > now:
                raise RecoveryError(
                    RecoveryErrorCode.GOVERNED_TOO_EARLY,
                    "The mandatory protection delay has not finished.",
                    409,
                )
            user = await database.get(User, request.target_user_id, with_for_update=True)
            if user is None or user.version != request.target_user_version:
                request.state = "cancelled"
                raise RecoveryError(
                    RecoveryErrorCode.TARGET_CHANGED,
                    "The account changed after approval. Start a new request.",
                    409,
                )
            await database.execute(
                update(MFADevice)
                .where(MFADevice.user_id == user.user_id, MFADevice.status != "revoked")
                .values(status="revoked", revoked_at=now)
            )
            user.version += 1
            request.state = "executed"
            request.executed_at = now
            database.add(
                self._audit(
                    "ADMIN_MFA_RESET_EXECUTED",
                    "success",
                    correlation_id,
                    user.user_id,
                    actor_user_id,
                    {"request_id": str(request_id)},
                )
            )
            return self._governed(request), self._user(user)

    @staticmethod
    def _user(user: User) -> RecoveryUser:
        return RecoveryUser(
            user.user_id, user.email, user.phone_e164, user.state, user.version
        )

    @staticmethod
    def _contact(request: ContactChangeRequest) -> ContactChangeRecord:
        return ContactChangeRecord(
            request.request_id,
            request.user_id,
            ContactType(request.contact_type),
            request.old_value,
            request.new_value,
            request.expires_at,
            request.old_verified_at,
            request.new_verified_at,
            request.applied_at,
        )

    @staticmethod
    def _governed(request: GovernedRequest) -> GovernedResetRecord:
        return GovernedResetRecord(
            request.governed_request_id,
            request.target_user_id,
            request.initiator_user_id,
            request.approver_user_id,
            request.state,
            request.initiated_at,
            request.execute_after,
            request.approved_at,
            request.executed_at,
            request.ticket_reference,
        )

    @staticmethod
    def _audit(
        event_type: str,
        outcome: str,
        correlation_id: UUID,
        subject_user_id: UUID,
        actor_user_id: UUID | None,
        metadata: dict[str, str],
    ) -> AuditLog:
        return AuditLog(
            actor_user_id=actor_user_id,
            subject_user_id=subject_user_id,
            event_type=event_type,
            outcome=outcome,
            correlation_id=correlation_id,
            metadata_json=metadata,
        )
