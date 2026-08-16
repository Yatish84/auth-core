# PostgreSQL and Redis Schema Specification

**Target:** PostgreSQL 15+ and Redis 7+

**Implementation:** SQLAlchemy 2 async, AsyncPG, Alembic

This document defines the target schema semantics. Alembic migrations, not manually executed copied DDL, will be authoritative during implementation.

## PostgreSQL Namespaces and Extensions

- Application objects use the `auth` schema.
- Prefer `gen_random_uuid()` from `pgcrypto`.
- Use `citext` or an equivalent normalized-email strategy.
- Application, migration, audit-reader, and break-glass database roles remain separate.

## Core Schema

| Table | Key fields |
|---|---|
| `auth.users` | `user_id`, normalized email, names, phone, state, version, timestamps |
| `auth.identities` | `identity_id`, `user_id`, provider, provider subject, password hash, verified, last used |
| `auth.password_history` | `history_id`, `identity_id`, password hash, created time |
| `auth.mfa_devices` | `mfa_id`, `user_id`, type, encrypted secret, status, label, timestamps |
| `auth.webauthn_credentials` | credential ID, `mfa_id`, public key, counter, transports, backup eligibility |
| `auth.refresh_token_families` | family/user/device/client, expiry, revoked time/reason |
| `auth.refresh_tokens` | token hash, family, generation, issued/used/revoked/expiry times |
| `auth.sessions` | session/family/user/org, access JTI, client, device, IP, activity, expiry, revoked time |
| `auth.ephemeral_tokens` | token hash, user, type, expiry, consumed time, metadata |
| `auth.trusted_devices` | user/fingerprint, trust state, last IP, first/last seen, bounded risk metadata |
| `auth.organizations` | workspace type, private owner when personal, org name, lifecycle, subscription metadata, timestamps |
| `auth.invitations` | org, invitee email, token hash, proposed roles, issuer, expiry, acceptance |
| `auth.referrals` | referrer, invitee email, token hash, referred user, invitation/registration/verification state and timestamps |
| `auth.role_permission_catalog` | module, role, permission, version, active state |
| `auth.user_role_bindings` | user, org, module, role, grantor, active/revoked times |
| `auth.staff_role_bindings` | user, approved global support/security role, grantor, active/revoked times |
| `auth.contact_change_requests` | user, old/new contact, hashed proof codes, proof, expiry, and application times |
| `auth.governed_requests` | type, target/version, initiator, approver, approval/execution times, state, execute-after, ticket, result |
| `auth.gdpr_requests` | user, type, state, request/completion, artifact/expiry, failure code |
| `auth.audit_logs` | actor/subject/org, event/outcome, network, correlation, redacted metadata, hash linkage |
| `auth.outbox_events` | type, aggregate, payload, idempotency, availability, attempts, processing state |
| `auth.idempotency_records` | actor, route, key hash, request hash, response reference, expiry |

## Important Constraints

1. Normalized user email is unique for non-anonymized accounts.
2. Federated provider + subject is globally unique.
3. Passkey credential ID and refresh-token hash are globally unique.
4. Refresh generation is unique within its family.
5. Governed approver cannot equal initiator.
6. Execute-after cannot precede initiation.
7. Role binding references an active catalog entry.
8. Audit records reject update/delete through privileges and trigger.
9. Conditional check constraints enforce credential fields appropriate to MFA type.
10. Indexes support active-session, unexpired-token, tenant-membership, outbox, and audit cursor queries.
11. Each non-anonymized user has at most one personal workspace, and personal workspaces require an owner.
12. Each created account can be attributed to at most one referral; referral tokens are hashed, expiring, and never grant portfolio access.
13. Staff authority comes from active database bindings, never from a role supplied in an API request.
14. Contact changes apply only after hashed proof codes for both old and new channels are verified.
15. Governed MFA resets preserve the target account version and cancel safely if the account changes before approval or execution.
16. The application database role can read staff bindings for authorization but cannot insert, update, or delete them.
17. Contact-change rows enforce PostgreSQL row-level isolation by the verified current user.

## Row-Level Security

Tenant-owned tables enable RLS. A transaction sets verified `app.current_org_id` and `app.current_user_id` values after the control layer authorizes membership. Policies restrict rows to the current organization except through dedicated audited administrative roles.

## Token Rotation Transaction

1. Hash incoming refresh token.
2. Lock the matching token/family rows.
3. If the token was already used or revoked, revoke the complete family.
4. Otherwise mark it used and insert the next generation hash.
5. Update session activity and commit atomically.
6. Publish audit/outbox event in the same transaction.

Keeping historical generation hashes is required to distinguish invalid input from reuse of a previously valid token.

## Audit Protection

```sql
REVOKE UPDATE, DELETE, TRUNCATE ON auth.audit_logs FROM auth_app;

CREATE TRIGGER audit_logs_immutable
BEFORE UPDATE OR DELETE ON auth.audit_logs
FOR EACH ROW EXECUTE FUNCTION auth.reject_audit_mutation();
```

Production additionally exports signed audit batches to an AWS retention target such as S3 Object Lock after legal retention requirements are approved.

## Redis Semantics

- All security keys have explicit TTLs except carefully bounded revocation state.
- OTP and challenge writes use cryptographically random identifiers and hashed secrets.
- Rate limits use atomic Lua scripts or equivalent server-side operations.
- Keys never contain plaintext email, phone, token, or unbounded PII; keyed hashes are used where necessary.
- Redis loss may force reauthentication or challenge restart but cannot approve a durable privileged action.

## Migration Policy

- Alembic revisions are immutable after merge.
- CI upgrades an empty database and a representative prior schema.
- Destructive changes use expand/migrate/contract releases.
- Production migrations run with a dedicated role and bounded lock timeout.
- Downgrade scripts are provided only when safe; rollback normally uses forward fixes.
