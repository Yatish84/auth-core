# Delivered Persistence Foundation

**Milestone:** 2 - Data Foundation

**Status:** Ready for stakeholder review

This document explains the working PostgreSQL and Redis foundation in plain language. It describes storage structures only; registration, login, and customer-facing features are not implemented yet.

## What Was Delivered

The local environment now creates and upgrades the database automatically before the API starts. Alembic records each approved database change, SQLAlchemy supplies the Python mappings, PostgreSQL enforces durable safety rules, and Redis stores only expiring, reconstructible security state.

## PostgreSQL Tables

| Table | Plain-language purpose |
|---|---|
| `users` | Stores a person's account state and basic profile identifiers. |
| `identities` | Records how a user signs in, such as password, Google, Apple, or phone. |
| `password_history` | Stores previous password hashes to prevent unsafe reuse. |
| `mfa_devices` | Records enrolled security factors such as authenticator apps or passkeys. |
| `webauthn_credentials` | Stores passkey public credentials and security counters, never private keys. |
| `refresh_token_families` | Represents the long-lived login lineage for one device. |
| `refresh_tokens` | Stores hashed refresh-token generations for rotation and theft detection. |
| `sessions` | Stores the user's visible active login sessions. |
| `trusted_devices` | Stores bounded device trust and risk history. |
| `ephemeral_tokens` | Stores hashed, expiring email, phone, password-reset, and invitation links. |
| `organizations` | Stores companies or groups that users may access. |
| `invitations` | Stores expiring organization invitations and intended roles. |
| `role_permission_catalog` | Defines approved roles and permissions by version. |
| `user_role_bindings` | Connects users to approved organization roles. |
| `governed_requests` | Stores sensitive actions requiring a different approver and a delay. |
| `gdpr_requests` | Tracks personal-data export and erasure requests. |
| `audit_logs` | Stores append-only security history. |
| `outbox_events` | Reliably queues redacted background work such as notifications. |
| `idempotency_records` | Prevents repeated client requests from performing the same action twice. |

## Database Safety Controls

- Email uniqueness is case-insensitive for active, non-anonymized users.
- Password hashes are allowed only on password identities.
- Token hashes, passkey credential IDs, organization slugs, and request keys are unique where required.
- Token and invitation expiry must occur after issuance.
- A governed request cannot be approved by its initiator or execute before its delay.
- Role assignments must reference an active catalog entry.
- User versions support safe concurrent updates and cannot be less than one.
- Foreign keys prevent orphaned security records.

## Organization Isolation

PostgreSQL row-level security protects organizations, invitations, role bindings, sessions, governed requests, and audit records. After the control layer verifies access, it sets the current user and organization for the transaction. The database then rejects rows belonging to another organization even if application code constructs an unsafe query.

## Audit Protection

The application role can insert and read permitted audit records but cannot update, delete, or truncate them. A PostgreSQL trigger independently rejects mutation attempts, including attempts made outside the ORM.

## Separated Database Roles

| Role | Purpose |
|---|---|
| `auth_migration` | Reserved for controlled schema changes. |
| `auth_app` | Runtime application access with tenant and audit restrictions. |
| `auth_audit_reader` | Read-only access to audit history. |
| `auth_break_glass` | Reserved emergency role with no ordinary application use. |

The local `auth_core` owner supports development. Production credentials and login rights will be provisioned separately in AWS.

## Redis Security Storage

The reusable Redis key service covers OTPs, MFA challenges, WebAuthn challenges, route limits, temporary factor locks, token revocations, organization revocations, and risk state. User IDs, routes, purposes, device fingerprints, and token identifiers are transformed with keyed HMAC values before entering key names. Every temporary security key has an explicit expiration.

## Repository Boundary

Future registration and login controls call repository interfaces rather than raw SQL. The first user repository normalizes email addresses and uses a version number to reject stale concurrent updates. Web and future mobile clients will call the same API workflows and therefore share this storage behavior.

## Automated Evidence

- An empty temporary database upgrades through every Alembic revision.
- Alembic reports no model-to-schema drift.
- The migrated database contains all 19 approved tables.
- Case-insensitive duplicate email insertion is rejected.
- Self-approval of a governed request is rejected.
- Audit update and delete attempts are rejected.
- Cross-organization reads are filtered and writes are rejected.
- Repository email normalization and stale-update protection pass.
- Redis OTP hashes receive the required expiration and opaque key name.
- The complete Docker stack starts only after migrations exit successfully.

## Developer Commands

```bash
make migrate
make migration-check
make test-integration
```

`make up` also runs pending migrations automatically before starting the API.
