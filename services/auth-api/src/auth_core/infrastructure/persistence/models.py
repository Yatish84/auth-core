from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import CITEXT, INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from auth_core.infrastructure.persistence.base import Base, TimestampMixin


def uuid_primary_key() -> Mapped[UUID]:
    return mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending', 'active', 'locked', 'suspended', 'disabled', 'anonymized')",
            name="state_valid",
        ),
        CheckConstraint("version >= 1", name="version_positive"),
        Index(
            "uq_users_email_active",
            "email",
            unique=True,
            postgresql_where=text("anonymized_at IS NULL"),
        ),
        Index(
            "uq_users_phone_active",
            "phone_e164",
            unique=True,
            postgresql_where=text("phone_e164 IS NOT NULL AND anonymized_at IS NULL"),
        ),
    )

    user_id: Mapped[UUID] = uuid_primary_key()
    email: Mapped[str | None] = mapped_column(CITEXT(), nullable=True)
    given_name: Mapped[str | None] = mapped_column(String(120))
    family_name: Mapped[str | None] = mapped_column(String(120))
    phone_e164: Mapped[str | None] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(24), nullable=False, server_default="pending")
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    anonymized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Identity(TimestampMixin, Base):
    __tablename__ = "identities"
    __table_args__ = (
        UniqueConstraint("provider", "provider_subject"),
        CheckConstraint(
            "provider IN ('password', 'google', 'apple', 'phone')", name="provider_valid"
        ),
        CheckConstraint(
            "(provider = 'password' AND password_hash IS NOT NULL) OR "
            "(provider <> 'password' AND password_hash IS NULL)",
            name="password_hash_matches_provider",
        ),
    )

    identity_id: Mapped[UUID] = uuid_primary_key()
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(24), nullable=False)
    provider_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(Text)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PasswordHistory(Base):
    __tablename__ = "password_history"
    __table_args__ = (Index("ix_password_history_identity_created", "identity_id", "created_at"),)

    history_id: Mapped[UUID] = uuid_primary_key()
    identity_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.identities.identity_id", ondelete="CASCADE"), nullable=False
    )
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class MFADevice(TimestampMixin, Base):
    __tablename__ = "mfa_devices"
    __table_args__ = (
        CheckConstraint(
            "factor_type IN ('totp', 'sms', 'email', 'passkey', 'backup_codes')",
            name="factor_type_valid",
        ),
        CheckConstraint(
            "status IN ('pending', 'active', 'revoked')", name="status_valid"
        ),
        CheckConstraint(
            "(factor_type IN ('totp', 'backup_codes') AND encrypted_secret IS NOT NULL) OR "
            "(factor_type NOT IN ('totp', 'backup_codes') AND encrypted_secret IS NULL)",
            name="secret_matches_factor_type",
        ),
    )

    mfa_id: Mapped[UUID] = uuid_primary_key()
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="CASCADE"), nullable=False, index=True
    )
    factor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    encrypted_secret: Mapped[bytes | None] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(String(24), nullable=False, server_default="pending")
    label: Mapped[str | None] = mapped_column(String(120))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebAuthnCredential(TimestampMixin, Base):
    __tablename__ = "webauthn_credentials"

    credential_id: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    mfa_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.mfa_devices.mfa_id", ondelete="CASCADE"), nullable=False, unique=True
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    transports: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default="[]")
    backup_eligible: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    backup_state: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )


class RefreshTokenFamily(Base):
    __tablename__ = "refresh_token_families"
    __table_args__ = (
        CheckConstraint("absolute_expires_at > created_at", name="expiry_after_creation"),
        Index("ix_refresh_families_user_active", "user_id", "revoked_at"),
    )

    family_id: Mapped[UUID] = uuid_primary_key()
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="CASCADE"), nullable=False
    )
    device_fingerprint_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    client_id: Mapped[str] = mapped_column(String(80), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(80))


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        UniqueConstraint("family_id", "generation"),
        CheckConstraint("generation >= 0", name="generation_nonnegative"),
        CheckConstraint("expires_at > issued_at", name="expiry_after_issue"),
    )

    refresh_token_id: Mapped[UUID] = uuid_primary_key()
    family_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.refresh_token_families.family_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"
    __table_args__ = (
        CheckConstraint("state IN ('active', 'suspended', 'closed')", name="state_valid"),
    )

    org_id: Mapped[UUID] = uuid_primary_key()
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(String(24), nullable=False, server_default="active")
    subscription_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        UniqueConstraint("family_id"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        Index("ix_sessions_user_active", "user_id", "revoked_at", "expires_at"),
        Index("ix_sessions_org_active", "org_id", "revoked_at", "expires_at"),
    )

    session_id: Mapped[UUID] = uuid_primary_key()
    family_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.refresh_token_families.family_id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="CASCADE"), nullable=False
    )
    org_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("auth.organizations.org_id", ondelete="SET NULL"), index=True
    )
    access_jti: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), nullable=False, unique=True
    )
    client_id: Mapped[str] = mapped_column(String(80), nullable=False)
    device_fingerprint_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(INET())
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TrustedDevice(Base):
    __tablename__ = "trusted_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "fingerprint_hash"),
        CheckConstraint("trust_state IN ('unknown', 'trusted', 'blocked')", name="state_valid"),
    )

    trusted_device_id: Mapped[UUID] = uuid_primary_key()
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="CASCADE"), nullable=False
    )
    fingerprint_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    trust_state: Mapped[str] = mapped_column(String(24), nullable=False, server_default="unknown")
    last_ip_address: Mapped[str | None] = mapped_column(INET())
    risk_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EphemeralToken(Base):
    __tablename__ = "ephemeral_tokens"
    __table_args__ = (
        CheckConstraint(
            "purpose IN ('email_verify', 'phone_verify', 'password_reset', 'invite')",
            name="purpose_valid",
        ),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        Index("ix_ephemeral_tokens_user_active", "user_id", "purpose", "expires_at"),
    )

    ephemeral_token_id: Mapped[UUID] = uuid_primary_key()
    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    purpose: Mapped[str] = mapped_column(String(40), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default="{}"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Invitation(Base):
    __tablename__ = "invitations"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending', 'accepted', 'expired', 'revoked')", name="state_valid"
        ),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        Index("ix_invitations_org_pending", "org_id", "state", "expires_at"),
    )

    invitation_id: Mapped[UUID] = uuid_primary_key()
    org_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.organizations.org_id", ondelete="CASCADE"), nullable=False, index=True
    )
    invitee_email: Mapped[str] = mapped_column(CITEXT(), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    proposed_roles: Mapped[list[dict[str, str]]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    issued_by_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="RESTRICT"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(24), nullable=False, server_default="pending")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RolePermissionCatalog(TimestampMixin, Base):
    __tablename__ = "role_permission_catalog"
    __table_args__ = (UniqueConstraint("module", "role", "permission", "version"),)

    catalog_id: Mapped[UUID] = uuid_primary_key()
    module: Mapped[str] = mapped_column(String(80), nullable=False)
    role: Mapped[str] = mapped_column(String(80), nullable=False)
    permission: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))


class UserRoleBinding(Base):
    __tablename__ = "user_role_bindings"
    __table_args__ = (
        Index(
            "uq_role_bindings_active",
            "user_id",
            "org_id",
            "catalog_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    binding_id: Mapped[UUID] = uuid_primary_key()
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="CASCADE"), nullable=False
    )
    org_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.organizations.org_id", ondelete="CASCADE"), nullable=False, index=True
    )
    catalog_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.role_permission_catalog.catalog_id", ondelete="RESTRICT"), nullable=False
    )
    granted_by_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="RESTRICT"), nullable=False
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class GovernedRequest(Base):
    __tablename__ = "governed_requests"
    __table_args__ = (
        CheckConstraint("initiator_user_id <> approver_user_id", name="different_actors"),
        CheckConstraint("execute_after >= initiated_at", name="execution_not_early"),
        CheckConstraint(
            "state IN ('pending', 'approved', 'rejected', 'executed', 'expired', 'cancelled')",
            name="state_valid",
        ),
        Index("ix_governed_requests_pending", "state", "execute_after"),
    )

    governed_request_id: Mapped[UUID] = uuid_primary_key()
    org_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("auth.organizations.org_id", ondelete="SET NULL"), index=True
    )
    request_type: Mapped[str] = mapped_column(String(80), nullable=False)
    target_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="CASCADE"), nullable=False
    )
    initiator_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="RESTRICT"), nullable=False
    )
    approver_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="RESTRICT")
    )
    state: Mapped[str] = mapped_column(String(24), nullable=False, server_default="pending")
    initiated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    execute_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ticket_reference: Mapped[str | None] = mapped_column(String(120))
    result_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )


class GDPRRequest(Base):
    __tablename__ = "gdpr_requests"
    __table_args__ = (
        CheckConstraint("request_type IN ('export', 'erasure')", name="type_valid"),
        CheckConstraint(
            "state IN ('requested', 'processing', 'completed', 'failed', 'cancelled')",
            name="state_valid",
        ),
        Index("ix_gdpr_requests_user_state", "user_id", "state"),
    )

    gdpr_request_id: Mapped[UUID] = uuid_primary_key()
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="RESTRICT"), nullable=False
    )
    request_type: Mapped[str] = mapped_column(String(24), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, server_default="requested")
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    artifact_reference: Mapped[str | None] = mapped_column(Text)
    artifact_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(80))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("outcome IN ('success', 'failure', 'denied')", name="outcome_valid"),
        Index("ix_audit_logs_org_cursor", "org_id", "occurred_at", "audit_id"),
        Index("ix_audit_logs_subject_cursor", "subject_user_id", "occurred_at", "audit_id"),
    )

    audit_id: Mapped[UUID] = uuid_primary_key()
    actor_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="SET NULL"), index=True
    )
    subject_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("auth.users.user_id", ondelete="SET NULL"), index=True
    )
    org_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("auth.organizations.org_id", ondelete="SET NULL"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    correlation_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(INET())
    user_agent_hash: Mapped[str | None] = mapped_column(String(128))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default="{}"
    )
    previous_hash: Mapped[str | None] = mapped_column(String(128))
    record_hash: Mapped[str | None] = mapped_column(String(128))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class OutboxEvent(Base):
    __tablename__ = "outbox_events"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending', 'processing', 'published', 'failed')", name="state_valid"
        ),
        Index("ix_outbox_events_available", "state", "available_at"),
    )

    outbox_event_id: Mapped[UUID] = uuid_primary_key()
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(80), nullable=False)
    aggregate_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(String(24), nullable=False, server_default="pending")
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint("actor_id", "route", "key_hash"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        Index("ix_idempotency_expiry", "expires_at"),
    )

    idempotency_record_id: Mapped[UUID] = uuid_primary_key()
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    route: Mapped[str] = mapped_column(String(180), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_reference: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
