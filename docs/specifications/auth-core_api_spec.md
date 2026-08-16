# Auth-Core API Contract

**Version:** Draft 2.2

**Base path:** `/api/v1`

**Style:** JSON REST with RFC 7807 problem responses

**Clients:** Next.js web and future React Native / Expo mobile

This human-readable contract defines the intended API surface. During implementation, `packages/contracts/openapi.yaml` becomes the machine-readable source of truth and generates client SDKs.

## Global Conventions

- JSON properties use `snake_case`.
- Identifiers are canonical UUID strings.
- Times use UTC RFC 3339 strings.
- Unknown request properties are rejected on security-sensitive DTOs.
- Responses containing secrets use `Cache-Control: no-store`.
- Endpoints use idempotency keys where duplicate execution could cause harm.

## Standard Headers

| Header | Requirement |
|---|---|
| `Content-Type: application/json` | Required for JSON request bodies. |
| `X-Client-Type: WEB | MOBILE` | Required on authentication/session endpoints. |
| `X-Device-Fingerprint` | Required where documented; a bounded risk signal, not identity proof. |
| `X-CSRF-Token` | Required for state-changing web requests authenticated by cookie. |
| `X-Request-ID` | Optional caller ID; generated when absent and returned in the response. |
| `Idempotency-Key` | Required for invitation, governed-action, and privacy request creation. |

## Authentication and Token Delivery

- Protected endpoints use `Authorization: Bearer <access_token>`.
- Web refresh tokens are delivered only in a `Secure`, `HttpOnly`, `SameSite=Lax` cookie.
- Mobile refresh tokens are returned in the JSON body for immediate secure storage.
- Access tokens are never persisted in browser local storage.
- Web cookie endpoints enforce CSRF; mobile bearer requests do not use cookie authentication.

## Endpoint Inventory

### Public Discovery and Health

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/jwks.json` | Publish active and retiring JWT verification keys. |
| GET | `/health/live` | Process liveness without dependency details. |
| GET | `/health/ready` | Deployment readiness for required dependencies. |

### Registration and Contact Verification

| Method | Path | Use case | Result |
|---|---|---|---|
| POST | `/auth/signup` | UC-301 | Create pending email/password account and send verification. |
| POST | `/auth/signup/phone` | UC-304 | Start phone registration after CAPTCHA/rate limits. |
| POST | `/auth/verify/email` | UC-302 | Consume email-verification token and activate account. |
| POST | `/auth/verify/email/request` | UC-302 | Safely request a replacement verification email. |
| POST | `/auth/verify/phone/request` | UC-304 | Send or resend phone verification OTP. |
| POST | `/auth/verify/phone/confirm` | UC-304 | Confirm phone OTP. |

### Login and Federation

| Method | Path | Use case | Result |
|---|---|---|---|
| POST | `/auth/login` | UC-101, UC-106, UC-401 | Verify password, evaluate risk, return tokens or MFA challenge. |
| POST | `/auth/login/phone/request` | UC-103 | Send rate-limited phone login OTP. |
| POST | `/auth/login/phone/confirm` | UC-103, UC-106 | Verify OTP, evaluate risk, return tokens or challenge. |
| POST | `/auth/sso/{provider}/authorize` | UC-102 | Create OIDC authorization request with PKCE/state/nonce. |
| POST | `/auth/sso/{provider}/callback` | UC-102, UC-303, UC-307 | Verify callback and authenticate, provision, or return collision proof requirement. |
| GET | `/auth/fallback-options` | UC-105 | Return safe fallback factors for a workflow token. |
| POST | `/auth/identities/link` | UC-307 | Link a proven federated identity. |
| DELETE | `/auth/identities/{identity_id}` | UC-307 | Unlink while preserving at least one usable primary factor. |

### MFA and Passkeys

| Method | Path | Use case | Result |
|---|---|---|---|
| GET | `/auth/mfa/methods` | UC-201, UC-202, UC-203 | List methods available for a proven login workflow. |
| POST | `/auth/mfa/challenge` | UC-201, UC-202 | Consume the login workflow and issue one short-lived challenge. |
| POST | `/auth/mfa/verify` | UC-201, UC-202, UC-401 | Verify challenge code and return a session-ready workflow. |
| POST | `/auth/mfa/challenge/resend` | UC-202 | Resend an eligible backup challenge. |
| GET | `/auth/mfa/devices` | UC-204 | List enrolled factors without secrets. |
| POST | `/auth/mfa/totp/setup` | UC-204 | Return temporary secret presentation and enrollment challenge. |
| POST | `/auth/mfa/totp/confirm` | UC-204 | Confirm first code and enable TOTP. |
| POST | `/auth/mfa/passkeys/options` | UC-204 | Create WebAuthn registration options. |
| POST | `/auth/mfa/passkeys/confirm` | UC-204 | Validate attestation and register credential. |
| POST | `/auth/passkeys/options` | UC-104, UC-203 | Create WebAuthn assertion options. |
| POST | `/auth/passkeys/verify` | UC-104, UC-203 | Validate assertion for login or step-up. |
| DELETE | `/auth/mfa/devices/{mfa_id}` | UC-204, UC-509 | Revoke a factor with reauthentication and last-factor rules. |
| POST | `/auth/identities/collision/prove` | UC-307 | Prove the existing password before linking the already-verified social identity. |

### Session and Token Lifecycle

| Method | Path | Use case | Result |
|---|---|---|---|
| POST | `/auth/refresh` | UC-402 | Atomically rotate refresh token and issue new pair. |
| POST | `/auth/logout` | UC-403 | Revoke current family/session and access JTI. |
| POST | `/auth/logout-all` | UC-404 | Revoke every active user family. |
| GET | `/auth/sessions` | UC-509 | List active devices and sessions. |
| DELETE | `/auth/sessions/{session_id}` | UC-509 | Revoke a selected session. |

`UC-405` idle and absolute timeout policy is enforced during access-token verification, refresh, and protected session operations rather than through a separate endpoint. An expired session is denied and cannot be refreshed beyond its family lifetime.

### Recovery and Profile Security

| Method | Path | Use case | Result |
|---|---|---|---|
| POST | `/auth/password/forgot` | UC-501 | Return generic acceptance and conditionally send reset link. |
| POST | `/auth/password/reset` | UC-502 | Consume token, apply password policy/history, revoke sessions. |
| POST | `/auth/contact-change` | UC-510 | Start dual-channel contact change. |
| POST | `/auth/contact-change/verify-old` | UC-510 | Prove existing channel. |
| POST | `/auth/contact-change/verify-new` | UC-510 | Prove new channel and apply change when both proofs exist. |

### Organizations and Authorization

| Method | Path | Use case | Result |
|---|---|---|---|
| POST | `/organizations` | UC-305 | Create organization and owner binding. |
| GET | `/organizations` | UC-306 | List organizations available to current user. |
| POST | `/organizations/{org_id}/invitations` | UC-305 | Invite member with proposed roles. |
| POST | `/organizations/invitations/accept` | UC-305 | Consume invitation and create bindings. |
| POST | `/auth/org/switch` | UC-306 | Verify membership and issue scoped access token. |
| GET | `/organizations/{org_id}/members` | UC-305, UC-506 | List members for authorized administrators. |
| PUT | `/organizations/{org_id}/members/{user_id}/roles` | UC-506 | Replace validated role assignments. |
| DELETE | `/organizations/{org_id}/members/{user_id}` | UC-308 | Offboard member and revoke tenant access. |

### Privacy

| Method | Path | Use case | Result |
|---|---|---|---|
| POST | `/privacy/exports` | UC-601 | Create authenticated export request. |
| GET | `/privacy/requests/{request_id}` | UC-601, UC-602 | Return privacy request status. |
| GET | `/privacy/exports/{request_id}/download` | UC-601 | Return short-lived authorized artifact link or stream. |
| POST | `/privacy/erasures` | UC-602 | Create reauthenticated erasure request. |

### Administrative Governance

All admin endpoints require appropriate role claims, recent strong MFA, tenant checks where applicable, and audit recording.

| Method | Path | Use case | Result |
|---|---|---|---|
| POST | `/admin/users/{user_id}/unlock` | UC-503, UC-507 | Unlock after authorized support verification. |
| POST | `/admin/users/{user_id}/suspend` | UC-504 | Suspend and revoke all sessions. |
| POST | `/admin/users/{user_id}/recovery` | UC-507 | Issue governed single-use recovery path. |
| POST | `/admin/mfa-resets` | UC-508 | Initiate delayed four-eyes reset. |
| POST | `/admin/mfa-resets/{request_id}/approve` | UC-508 | Record distinct L3 approval. |
| GET | `/admin/mfa-resets/{request_id}` | UC-508 | Inspect safe request status. |
| GET | `/admin/audit-logs` | UC-505 | Search authorized, paginated audit history. |
| GET | `/admin/roles` | UC-506 | Read canonical role and permission catalog. |

## Core Request and Response Shapes

### Primary login request

```json
{
  "email": "user@example.com",
  "password": "not-logged-or-returned",
  "device_fingerprint": "client-generated-bounded-risk-signal"
}
```

### Primary login decision

```json
{
  "decision": "mfa_required",
  "risk": "high",
  "workflow_token": "<opaque-five-minute-token>",
  "allowed_methods": ["password", "phone_otp"]
}
```

Primary login returns a workflow decision, not a JWT. Milestone 5 consumes the workflow for MFA and Milestone 6 issues a session only after every required check succeeds.

### MFA completion response

```json
{
  "result": "session_ready",
  "workflow_token": "<opaque-five-minute-token>",
  "backup_codes": []
}
```

Backup codes are populated only when first generated and must be displayed once. MFA completion still returns no access or refresh token; Milestone 6 performs session issuance.

### Token response for mobile

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<opaque-single-use-token>",
  "token_type": "Bearer",
  "expires_in": 900,
  "session_id": "0f523e77-840b-443d-8538-9aa660700b76"
}
```

The web response omits `refresh_token`; the server sets the refresh cookie.

### MFA challenge problem

```json
{
  "type": "https://auth.vittavaan.com/problems/mfa-required",
  "title": "Additional verification required",
  "status": 403,
  "detail": "Complete one of the available verification methods.",
  "instance": "/api/v1/auth/login",
  "code": "AUTH_MFA_REQUIRED",
  "request_id": "3dba8a76-7818-4bc5-8079-f67c67df193c",
  "workflow_token": "<opaque-short-lived-token>",
  "allowed_methods": ["TOTP", "PASSKEY"]
}
```

## Problem Format

Every error uses `application/problem+json` and contains `type`, `title`, `status`, `detail`, `instance`, stable `code`, and `request_id`. Field validation may include a safe `errors` array.

Security responses do not reveal whether an email, phone, identity, reset token, or invitation exists unless the caller is already authorized to know.

## Stable Error Families

| Family | Examples |
|---|---|
| Validation | `REQUEST_INVALID`, `HEADER_REQUIRED` |
| Authentication | `AUTH_INVALID_CREDENTIALS`, `AUTH_MFA_REQUIRED`, `AUTH_REAUTH_REQUIRED` |
| Token | `TOKEN_INVALID`, `TOKEN_EXPIRED`, `TOKEN_REUSE_DETECTED` |
| Authorization | `ACCESS_DENIED`, `ORG_MEMBERSHIP_REQUIRED`, `ROLE_REQUIRED` |
| Rate limiting | `RATE_LIMITED`, with `Retry-After` |
| Workflow | `WORKFLOW_EXPIRED`, `WORKFLOW_ALREADY_COMPLETED`, `COOLDOWN_ACTIVE` |
| Conflict | `IDENTITY_COLLISION`, `EMAIL_ALREADY_REGISTERED` only in authorized contexts |
| Dependency | `SERVICE_TEMPORARILY_UNAVAILABLE` without provider internals |

## Pagination and Filtering

Administrative lists use opaque cursor pagination with bounded page size. Filters are allow-listed, normalized, parameterized, and subject to role restrictions. Audit export is asynchronous for large results.

## Idempotency and Concurrency

- Refresh rotation is atomic; exactly one concurrent use succeeds.
- Token consumption, invitation acceptance, and workflow execution are compare-and-set transitions.
- Idempotency records are scoped to actor, route, and key and never store plaintext secrets.
- Resource conflicts return `409`; stale version updates return a stable concurrency problem.
