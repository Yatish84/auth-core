# Testing Strategy

## Objectives

Testing must prove successful journeys and show that abuse, replay, cross-tenant access, unsafe recovery, dependency failure, and malformed input are rejected safely.

## Test Layers

| Layer | Scope | Examples |
|---|---|---|
| Entity unit | Pure invariants and state machines | User transitions, token family replay, four-eyes actor distinction. |
| Control unit | Use-case orchestration with fakes | Risk step-up, provider timeout, session cap, erasure sequencing. |
| Repository integration | Real PostgreSQL/Redis | Constraints, row locks, RLS, TTLs, atomic rate limits. |
| API contract | FastAPI + generated OpenAPI | DTO validation, RFC 7807, cookies, headers, auth requirements. |
| Provider contract | Sandbox or recorded safe fixtures | OIDC, Turnstile, HIBP, email, SMS, KMS interface. |
| Cross-language | Python issuer + Go verifier | JWKS rotation, claims, revocation, malformed JWT corpus. |
| Browser E2E | Next.js through real API | Registration, login, MFA, recovery, session and admin journeys. |
| Mobile contract | Simulated Expo client semantics | Bearer/refresh delivery, deep-link and retry behavior. |
| Security | Automated abuse and authorization | CSRF, replay, cross-tenant, rate limit, secret leakage. |
| Performance | Critical hot paths | Login load, refresh contention, JWKS cache, verifier latency. |

## Required Security Scenarios

- Generic responses for unknown email/phone and incorrect credentials.
- Concurrent refresh requests: one success, subsequent replay revokes family.
- Expired, wrong-audience, wrong-issuer, unknown-key, and revoked JWTs.
- CSRF missing/mismatch and disallowed browser origins.
- OIDC state/nonce/PKCE failure and email collision without ownership proof.
- OTP expiry, attempt lock, resend limit, and SMS pumping controls.
- WebAuthn wrong origin/RP/challenge and signature-counter anomaly.
- User A accessing User B resources; Organization A accessing Organization B.
- L2 self-approval, wrong L3 role, early execution, and changed target state.
- Audit update/delete attempts at ORM and SQL levels.
- Database, Redis, KMS, OIDC, HIBP, email, and SMS failures.

## Quality Gates

- All tests pass on protected pull requests.
- Changed Python/TypeScript/Go code meets agreed coverage thresholds; security state machines target branch-complete tests.
- OpenAPI generation is clean and generated SDK has no uncommitted drift.
- Lint, type checking, secret scanning, dependency audit, SAST, and container scan pass.
- Critical/high findings block release unless formally risk-accepted with expiry.
- Browser flows pass Chromium, Firefox, and WebKit where supported.
- Accessibility checks include keyboard navigation, labels, contrast, focus, and error announcements.

## Test Data

- Factories generate synthetic users, organizations, credentials, and timestamps.
- No production records, real passwords, private keys, or unredacted provider payloads enter fixtures.
- Time, random source, and provider adapters are injectable for deterministic cases.
- Load tests use isolated accounts and avoid real SMS/email spend.

## Staging Acceptance

Before stakeholder demonstration:

1. Deploy/migration smoke tests pass.
2. Seeded reviewer roles and a documented demo path exist.
3. At least one live email and Google OAuth journey works.
4. SMS restrictions are clearly disclosed and a safe alternate MFA method exists.
5. Monitoring shows request failures without exposing secrets.
6. A rollback rehearsal succeeds.
