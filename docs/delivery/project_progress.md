# Project Progress Tracker

**Last updated:** August 16, 2026

This file is the simple, ongoing record of what has been planned, what is being built, what has been completed, and what is blocking progress. It will be updated as part of every milestone and important pull request.

## How to Read the Status

| Status | Meaning |
|---|---|
| Not started | Work has not begun. |
| In progress | Work is actively being completed. |
| Ready for review | Work is complete locally and needs stakeholder review. |
| Blocked | Progress needs a decision, credential, tool, or external action. |
| Complete | Work has been reviewed and accepted. |

## Overall Milestone Board

| Milestone | Plain-language goal | Status |
|---|---|---|
| 0. Documentation | Agree on what we are building before writing application code. | Complete |
| 1. Project foundation | Create the folders, tools, local services, and automatic checks needed for development. | Complete |
| 2. Data foundation | Create the secure database and temporary storage structures. | Complete |
| 3. Registration | Allow a user to create and verify an account. | Complete |
| 4. Login | Allow safe password, phone, and social sign-in. | Complete |
| 5. Extra security | Add MFA, authenticator codes, backup methods, and passkeys. | Ready for review |
| 6. Sessions | Add secure tokens, refresh, logout, device sessions, and theft detection. | Not started |
| 7. Organizations | Add organizations, invitations, roles, and member removal. | Not started |
| 8. Recovery and administration | Add password recovery and controlled support actions. | Not started |
| 9. Privacy and auditing | Add audit review, data export, and account erasure. | Not started |
| 10. Web experience | Connect all approved website screens to working services. | Not started |
| 11. Public test website | Publish the controlled MVP for stakeholder testing. | Not started |
| 12. AWS production preparation | Harden and move the system to the final AWS environment. | Not started |

## Current Milestone: 5 - MFA, Backup Methods, and Passkeys

### Goal

Add reusable second-factor verification and enrollment so web and future mobile clients can safely complete high-risk login workflows before Milestone 6 creates a session.

### Work Items

| Work item | Simple description | Status |
|---|---|---|
| Challenge workflow | Bind every second-factor attempt to a short-lived proven-login workflow. | Ready for review |
| Authenticator app | Enroll encrypted TOTP secrets and verify replay-safe six-digit codes. | Ready for review |
| Email/SMS backup | Issue hashed, expiring, single-use secondary codes to verified contacts. | Ready for review |
| Backup codes | Generate one-time recovery codes, store only keyed hashes, and consume atomically. | Ready for review |
| Passkeys | Register and verify WebAuthn credentials with origin, RP, challenge, signature, and counter checks. | Ready for review |
| Factor management | Safely list, label, and revoke factors without exposing secrets. | Ready for review |
| Collision ownership | Reuse proven password/MFA workflows before linking a matching social identity. | Ready for review |
| Workflow handoff | Return `session_ready` only after required MFA; continue issuing no JWTs before Milestone 6. | Ready for review |
| Acceptance tests | Prove UC-104 and UC-201 to UC-204 success, replay, expiry, lock, and fallback paths. | Ready for review |
| UI and documentation | Propose missing MFA/passkey states without changing approved frontend screens. | Ready for review |

### Completion Checklist

- [x] TOTP secrets are encrypted and never returned after initial enrollment setup.
- [x] A TOTP time step cannot be accepted twice and three failures lock the factor for 15 minutes.
- [x] Email and SMS challenges are hashed, expiring, attempt-limited, and single-use.
- [x] Backup recovery codes are shown once, stored only as keyed hashes, and consumed once.
- [x] Passkeys enforce the expected RP ID, origin, challenge, user verification, and signature counter.
- [x] WebAuthn and login workflows cannot be replayed.
- [x] Unknown, expired, locked, and provider-failure paths return safe problem responses.
- [x] No factor can be enrolled or removed without a valid proven workflow.
- [x] No access or refresh JWT is issued before Milestone 6.
- [ ] Documentation and UI proposals are reviewed by the project owner.

## Work Log

### August 14, 2026

- Started Milestone 1 on branch `codex/milestone-1-foundation`.
- Added this progress tracker at the owner's request.
- Confirmed that the implementation branch is separate from the documentation review branch.
- Created the monorepo folders for the website, future mobile app, Python API, Go verifier, shared contracts, infrastructure, and scripts.
- Added Docker Compose configuration for PostgreSQL, Redis, Mailpit, FastAPI, Go, and Next.js.
- Added the first health endpoints, status website, OpenAPI contract, tests, lockfiles, and GitHub quality workflow.
- Installed Python 3.12 through `uv`, Go, Node.js 22, pnpm, and Docker Desktop.
- Passed Python linting, strict type checking, and three API tests.
- Passed web linting, type checking, component tests, and the production build.
- Passed Go formatting, tests, and static analysis.
- Passed documentation validation and found no known production web dependency vulnerabilities.
- Repaired the local Docker Desktop installation after macOS correctly rejected a damaged application signature.
- Started the complete environment with one Docker Compose command: website, FastAPI, Go verifier, PostgreSQL, Redis, and Mailpit.
- Confirmed in a real browser that the website displays `Connected` and reports the API, PostgreSQL, and Redis as available.
- Confirmed all service health endpoints respond successfully and found no startup errors in the container logs.
- Re-ran Python, web, Go, documentation, Compose, formatting, type, and production-build checks successfully.
- Marked Milestone 1 ready for stakeholder review; final acceptance remains with the project owner.
- Project owner reviewed the live foundation page and accepted Milestone 1.
- Merged the documentation and Milestone 1 pull requests into `main` after all GitHub checks passed.
- Project owner approved the complete Milestone 2 data-foundation scope.
- Started Milestone 2 on branch `codex/milestone-2-data-foundation`.
- Added SQLAlchemy mappings and Alembic migrations for all 19 approved PostgreSQL tables.
- Added separate migration, application, audit-reader, and emergency database roles.
- Added row-level organization isolation and immutable audit-record enforcement.
- Added opaque, expiring Redis key structures for OTP, challenge, rate-limit, revocation, and risk state.
- Added the user repository boundary with email normalization and optimistic concurrency protection.
- Added four fast API/storage tests and six real PostgreSQL/Redis integration tests.
- Confirmed an empty temporary database upgrades fully and Alembic reports no schema drift.
- Rebuilt the complete Docker stack and confirmed migration completion before a healthy API startup.
- Marked Milestone 2 ready for stakeholder review; final acceptance remains with the project owner.
- Project owner reviewed the database visually and accepted Milestone 2 for GitHub publication.

### August 15, 2026

- Merged Milestone 2 pull request #3 into `main` after all GitHub checks passed.
- Project owner approved the Milestone 3 registration and verification scope.
- Confirmed that existing signup and phone OTP wireframes remain the visual baseline.
- Received permission to recommend UI improvements, while retaining owner approval before any visual implementation.
- Started Milestone 3 on branch `codex/milestone-3-registration`.
- Added shared email/password and phone registration controls behind FastAPI endpoints.
- Added Argon2id password hashing, HIBP k-anonymity checks, local CAPTCHA enforcement, and safe public responses.
- Added hashed 15-minute email verification links with safe resend and single-use database consumption.
- Added hashed three-minute phone OTPs with per-phone rate limits, three-attempt limits, and atomic Redis replay protection.
- Added local Mailpit delivery for verification emails and simulated SMS without requiring paid credentials.
- Added a unique active-phone database constraint and migration `0005_registration_constraints`.
- Added unit, API contract, PostgreSQL, Redis, migration, replay, and provider-failure coverage.
- Documented the delivered workflow and proposed UI improvements without changing approved wireframes.
- Passed 12 fast API tests and 9 real PostgreSQL/Redis integration tests.
- Rebuilt the complete Docker stack and confirmed all services are healthy.
- Completed a live email signup, opened its Mailpit message, activated the account, and proved link replay is rejected.
- Passed Python lint/type checks, web tests/lint/type/build, Go tests/vet, documentation validation, OpenAPI parsing, migration drift checks, Compose validation, and production dependency audit.
- Marked Milestone 3 ready for stakeholder review; final acceptance remains with the project owner.
- Project owner reviewed the plain-language delivery summary and accepted Milestone 3 for GitHub publication.

### August 16, 2026

- Merged Milestone 3 pull request #4 into `main` after all GitHub checks passed.
- Project owner approved the complete Milestone 4 primary-authentication scope.
- Approved a 15-minute temporary login lock after excessive failures.
- Approved Google-first staging while keeping provider-neutral Apple and Microsoft boundaries.
- Confirmed MFA completion remains in Milestone 5 and JWT/session issuance remains in Milestone 6.
- Received permission to document missing login UI proposals without implementing visual changes.
- Started Milestone 4 on branch `codex/milestone-4-primary-auth`.
- Added reusable password and verified-phone login controls for web and future mobile clients.
- Added generic credential failures, constant password-hash work, rate limits, and approved 15-minute temporary locks.
- Added bounded device and IP-change risk decisions that require later MFA for unfamiliar conditions.
- Added short-lived opaque workflow handoffs without issuing access or refresh tokens early.
- Added provider-neutral Google, Apple, and Microsoft OIDC boundaries with local state, nonce, PKCE, issuer, audience, and verified-email checks.
- Added collision protection that refuses to auto-link a social email to an existing account.
- Added the Microsoft provider database constraint through migration `0006_login_identity_providers`.
- Added plain-language delivery documentation and proposed missing login UI states without changing the frontend.
- Passed 25 fast tests and 12 real PostgreSQL/Redis integration tests, including replay and collision checks.
- Confirmed Alembic has no schema drift and marked Milestone 4 ready for stakeholder review.
- Project owner reviewed and approved the complete Milestone 4 delivery for GitHub publication.
- Merged Milestone 4 pull request #5 into `main` after all GitHub checks passed.
- Project owner approved starting Milestone 5 planning and implementation.
- Started Milestone 5 on branch `codex/milestone-5-mfa-passkeys`.
- Confirmed missing MFA and passkey screens will be documented as proposals only and will not be implemented without owner approval.
- Selected verified email or phone as the safe first-login bootstrap path when no authenticator or passkey is enrolled.
- Added reusable MFA controls for email codes, SMS codes, authenticator apps, backup codes, passkeys, factor management, and social-identity ownership proof.
- Added AES-256-GCM encryption for recoverable authenticator secrets and keyed one-way storage for backup codes.
- Added one-time Redis workflows, replay protection, attempt limits, and the approved 15-minute authenticator lock after three failures.
- Added WebAuthn checks for the expected website, origin, challenge, user verification, signature, and credential counter.
- Added migration `0007_mfa_replay_protection` and confirmed the local PostgreSQL schema has no drift.
- Added 12 live MFA/passkey API routes while retaining the Milestone 6 boundary: successful MFA returns `session_ready`, not access or refresh tokens.
- Documented all proposed missing MFA/passkey screens without making frontend visual changes.
- Passed 40 fast API/security tests and 14 real PostgreSQL/Redis integration tests.
- Passed Python lint/type checks, web lint/type/test/build, Go tests/vet, documentation validation, OpenAPI parsing, Compose validation, and Docker health checks.
- Rebuilt the Docker API, confirmed all services are healthy, and verified safe RFC 7807 errors from the live MFA boundary.
- Marked Milestone 5 ready for stakeholder review; final acceptance remains with the project owner.

## Decisions

| Decision | Reason |
|---|---|
| Use one repository for web, backend, future mobile, shared contracts, infrastructure, and documentation. | Keeps related changes synchronized while allowing each service to run separately. |
| Build a small working foundation before authentication features. | Finds setup and communication problems early, before security logic becomes complex. |
| Keep the future mobile application visible in the structure but do not design unapproved screens. | Protects future reuse without creating unauthorized UI work. |
| Track progress in this file. | Gives non-technical and technical stakeholders one clear status record. |

## Current Blockers or Owner Actions

There are no current owner blockers. Local email/SMS delivery, AES-GCM secret encryption, and browser-standard WebAuthn allow development without paid provider credentials.

## Next Planned Milestone

After MFA and passkeys are accepted, Milestone 6 will add access tokens, refresh rotation, cookies, logout, and session management.
