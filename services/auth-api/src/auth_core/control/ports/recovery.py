from datetime import datetime
from typing import Protocol
from uuid import UUID

from auth_core.entity.recovery import (
    ContactChangeRecord,
    ContactProof,
    ContactType,
    GovernedResetRecord,
    PasswordResetOutcome,
    RecoveryUser,
    StaffRole,
)


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...

    def verify(self, password_hash: str, password: str) -> bool: ...


class BreachPasswordProvider(Protocol):
    async def breach_count(self, password: str) -> int: ...


class RecoveryNotificationProvider(Protocol):
    async def send_password_reset(self, email: str, reset_url: str) -> None: ...

    async def send_password_changed(self, email: str) -> None: ...

    async def send_support_recovery(self, email: str, recovery_url: str) -> None: ...

    async def send_contact_code(self, destination: str, code: str, proof: ContactProof) -> None: ...

    async def send_contact_changed(self, destination: str) -> None: ...

    async def send_mfa_reset_requested(self, destination: str, execute_after: datetime) -> None: ...

    async def send_mfa_reset_completed(self, destination: str) -> None: ...


class RecoveryRateStore(Protocol):
    async def increment_rate_limit(
        self, route: str, subject: str, window_seconds: int
    ) -> int: ...


class GlobalSessionRevoker(Protocol):
    async def revoke_user_access(self, user_id: UUID, reason: str) -> int: ...


class RecoveryRepository(Protocol):
    async def eligible_user_by_email(self, email: str) -> RecoveryUser | None: ...

    async def issue_password_reset(
        self,
        user_id: UUID,
        token_hash: str,
        purpose: str,
        expires_at: datetime,
        correlation_id: UUID,
        actor_user_id: UUID | None = None,
        ticket_reference: str | None = None,
    ) -> None: ...

    async def consume_password_reset(
        self,
        token_hash: str,
        password: str,
        password_hash: str,
        now: datetime,
        correlation_id: UUID,
    ) -> tuple[PasswordResetOutcome, RecoveryUser | None]: ...

    async def create_contact_change(
        self,
        user_id: UUID,
        contact_type: ContactType,
        new_value: str,
        old_code_hash: str,
        new_code_hash: str,
        expires_at: datetime,
        correlation_id: UUID,
    ) -> ContactChangeRecord | None: ...

    async def verify_contact_change(
        self,
        user_id: UUID,
        request_id: UUID,
        proof: ContactProof,
        code_hash: str,
        now: datetime,
        correlation_id: UUID,
    ) -> ContactChangeRecord | None: ...

    async def staff_has_role(self, user_id: UUID, role: StaffRole) -> bool: ...

    async def unlock_user(
        self, actor_user_id: UUID, target_user_id: UUID, ticket_reference: str, correlation_id: UUID
    ) -> RecoveryUser | None: ...

    async def suspend_user(
        self,
        actor_user_id: UUID,
        target_user_id: UUID,
        ticket_reference: str,
        reason: str,
        correlation_id: UUID,
    ) -> RecoveryUser | None: ...

    async def initiate_mfa_reset(
        self,
        actor_user_id: UUID,
        target_user_id: UUID,
        ticket_reference: str,
        execute_after: datetime,
        correlation_id: UUID,
    ) -> tuple[GovernedResetRecord, RecoveryUser] | None: ...

    async def approve_mfa_reset(
        self,
        actor_user_id: UUID,
        request_id: UUID,
        now: datetime,
        correlation_id: UUID,
    ) -> GovernedResetRecord | None: ...

    async def get_mfa_reset(self, request_id: UUID) -> GovernedResetRecord | None: ...

    async def execute_mfa_reset(
        self,
        actor_user_id: UUID,
        request_id: UUID,
        now: datetime,
        correlation_id: UUID,
    ) -> tuple[GovernedResetRecord, RecoveryUser] | None: ...
