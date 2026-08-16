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
| 5. Extra security | Add MFA, authenticator codes, backup methods, and passkeys. | Complete |
| 6. Sessions | Add secure tokens, refresh, logout, device sessions, and theft detection. | Complete |
| 7. Personal and organization workspaces | Add private portfolios, optional organizations, privacy-safe referrals, roles, and member removal. | Complete |
| 8. Recovery and administration | Add password recovery and controlled support actions. | In progress |
| 9. Privacy and auditing | Add audit review, data export, and account erasure. | Not started |
| 10. Web experience | Connect all approved website screens to working services. | Not started |
| 11. Public test website | Publish the controlled MVP for stakeholder testing. | Not started |
| 12. AWS production preparation | Harden and move the system to the final AWS environment. | Not started |

## Current Milestone: 8 - Recovery and Controlled Administration

### Goal

Help users safely regain account access while ensuring that powerful support actions require verified staff roles, independent approval, waiting periods, user notification, and complete audit evidence.

### Work Items

| Work item | Simple description | Status |
|---|---|---|
| Recovery foundation | Define reusable recovery workflows, safe public responses, expiration, replay protection, and audit evidence. | Ready for review |
| Password-reset request | Send a secure single-use reset link without revealing whether an email belongs to an account. | Ready for review |
| Password-reset execution | Verify the reset link, password policy, breach status, and password history before changing the password. | Ready for review |
| Session response | Revoke active sessions and refresh-token families after a successful password or sensitive contact change. | Ready for review |
| Account unlock | Allow an automatic or authorized support process to release a temporary login lock safely. | Ready for review |
| Account suspension | Let an authorized administrator suspend an account and immediately revoke all active access. | Ready for review |
| Support-assisted recovery | Require a support ticket and verified identity evidence before issuing a single-use recovery link. | Ready for review |
| Governed MFA reset | Require separate L2 initiation and L3 approval, then wait 12 hours and notify the user before execution. | Ready for review |
| Contact change | Verify both the old and new email or phone channel before changing a primary contact. | Ready for review |
| Staff authorization | Enforce approved support and security roles without trusting user-supplied role claims. | Ready for review |
| Tests and documentation | Prove UC-501 to UC-504, UC-507, UC-508, and UC-510 success, abuse, replay, role, and delay paths. | Ready for review |
| UI boundary | Document proposed recovery and administration screens without creating or changing frontend visuals until approved. | Ready for review |

### Completion Checklist

- [x] Password-reset requests return the same safe response for known and unknown accounts.
- [x] Reset and recovery tokens are random, hashed at rest, expiring, rate-limited, and single-use.
- [x] New passwords pass policy, breach, and password-history checks before storage with Argon2id.
- [x] Successful password reset revokes existing sessions and sends a security notification.
- [x] Unlock and suspension actions require an authenticated, authorized staff role and a ticket reference.
- [x] Account suspension immediately blocks login and revokes all active access.
- [x] Support-assisted recovery records verified evidence without storing unnecessary sensitive documents.
- [x] The person approving an MFA reset is different from the person requesting it.
- [x] MFA reset execution cannot occur before the approved 12-hour delay.
- [x] The user is warned through original verified channels before a governed MFA reset executes.
- [x] Primary contact changes require proof through both the old and new channel.
- [x] Replay, expired, wrong-role, self-approval, early-execution, and changed-state paths are rejected safely.
- [x] Recovery behavior is reusable by the web client and future mobile app through the same API contracts.
- [ ] Documentation and any proposed recovery/admin screens are reviewed by the project owner before UI implementation.

## Completed Milestone Archive

When a milestone is accepted, its complete goal, work items, and completion checklist move here before the current milestone changes. The Work Log remains the chronological activity record.

### Milestone 1 - Project Foundation

#### Goal

Prepare the project's basic structure so a developer can run the website, backend, token-checking service, PostgreSQL, Redis, and test email inbox in a consistent way.

#### Work Items

| Work item | Simple description | Final status |
|---|---|---|
| Monorepo folders | Organize the website, backend, future mobile app, shared files, tests, and infrastructure. | Complete |
| Tool versions | Record the required Python, Node.js, Go, and package-manager versions. | Complete |
| Local services | Configure PostgreSQL, Redis, and Mailpit using Docker Compose. | Complete |
| Backend health check | Provide a safe page showing whether the API and its dependencies are running. | Complete |
| Website status page | Show a simple website page that calls the backend health check. | Complete |
| Go service health check | Confirm the future JWT verification component can run independently. | Complete |
| Shared API contract | Document health endpoints in the first machine-readable OpenAPI file. | Complete |
| Automated checks | Configure GitHub to test documentation, Python, web, Go, and containers. | Complete |
| Setup guide | Explain how another developer starts and checks the project. | Complete |
| Local validation | Run the complete connected environment and all available quality checks. | Complete |

#### Completion Checklist

- [x] A new developer can follow the setup guide.
- [x] One command starts all local services.
- [x] The website opens and displays backend availability.
- [x] FastAPI reports application, PostgreSQL, and Redis readiness.
- [x] The Go verifier reports that it is alive and ready.
- [x] Automated tests and quality checks pass.
- [x] No credentials are committed.
- [x] Documentation is updated and reviewed.

### Milestone 2 - Data Foundation

#### Goal

Create the secure, reusable storage layer that future web and mobile registration, login, session, organization, recovery, and audit workflows will share.

#### Work Items

| Work item | Simple description | Final status |
|---|---|---|
| Migration system | Add numbered, repeatable database changes using Alembic. | Complete |
| Durable tables | Create the approved PostgreSQL tables for identities, security, organizations, governance, privacy, and events. | Complete |
| Data safety rules | Enforce uniqueness, valid state, secure relationships, and concurrency rules in PostgreSQL. | Complete |
| Tenant isolation | Prevent one organization from reading or changing another organization's records. | Complete |
| Audit protection | Prevent application-level alteration or deletion of security audit history. | Complete |
| Redis security keys | Add reusable expiring structures for OTPs, challenges, limits, revocations, and risk state. | Complete |
| Repository layer | Add controlled data-access interfaces and PostgreSQL implementations for future workflows. | Complete |
| Integration tests | Test migrations, constraints, audit immutability, Redis expiry, and tenant isolation with real services. | Complete |
| CI and documentation | Run persistence checks automatically and explain the delivered storage model in plain language. | Complete |

#### Completion Checklist

- [x] An empty PostgreSQL database upgrades to the latest schema.
- [x] All approved tables and important constraints exist.
- [x] Cross-organization reads and writes are rejected.
- [x] Audit records reject update and delete attempts.
- [x] Redis security keys use safe identifiers and explicit expiration.
- [x] Repository and migration integration tests pass.
- [x] No plaintext secrets or customer data are committed.
- [x] Documentation is updated and reviewed.

### Milestone 3 - Registration and Verification

#### Goal

Build one secure registration and contact-verification service that the web app and future mobile app can both use.

#### Work Items

| Work item | Simple description | Final status |
|---|---|---|
| Shared API contracts | Define reusable email and phone registration requests and responses for web and mobile. | Complete |
| Email registration | Create a pending account after validation, breach checking, and secure password hashing. | Complete |
| Email verification | Send, resend, expire, and consume single-use verification links. | Complete |
| Phone registration | Create a pending account and verify ownership using a short-lived OTP. | Complete |
| Abuse protection | Enforce CAPTCHA boundaries, rate limits, OTP attempts, and safe duplicate handling. | Complete |
| Provider adapters | Add interchangeable HIBP, CAPTCHA, email, and SMS boundaries with safe local implementations. | Complete |
| Audit evidence | Record redacted registration and verification outcomes without secrets. | Complete |
| Acceptance tests | Prove UC-301, UC-302, and UC-304 success and failure paths using PostgreSQL and Redis. | Complete |
| UI recommendation | Document proposed usability improvements without changing approved wireframes. | Complete |
| Documentation and CI | Update contracts, traceability, diagrams, developer guidance, and automated checks. | Complete |

#### Completion Checklist

- [x] Email registration creates a pending account and never stores plaintext passwords.
- [x] Breached passwords and invalid CAPTCHA proofs are rejected safely.
- [x] Email verification links are hashed, expiring, single-use, and resendable.
- [x] Phone OTPs are hashed, rate-limited, attempt-limited, and short-lived.
- [x] Duplicate and unknown-contact responses do not leak unsafe account details.
- [x] Web and future mobile clients share the same versioned API contract.
- [x] UC-301, UC-302, and UC-304 acceptance tests pass with real PostgreSQL and Redis.
- [x] Documentation and UI recommendations are reviewed.

### Milestone 4 - Primary Authentication and Risk

#### Goal

Verify primary identity safely, evaluate bounded login risk, and return a short-lived workflow decision that later MFA and session milestones can consume.

#### Work Items

| Work item | Simple description | Final status |
|---|---|---|
| Password login | Verify active password identities with anti-enumeration timing protection. | Complete |
| Phone login | Issue and atomically consume short-lived login OTPs. | Complete |
| Temporary lock | Apply the approved 15-minute lock after excessive failures. | Complete |
| Risk decision | Evaluate bounded device, IP-change, and velocity signals without treating them as identity. | Complete |
| Workflow handoff | Return opaque decisions for later MFA or session creation without issuing temporary JWTs. | Complete |
| Social OIDC | Add provider-neutral state, nonce, PKCE, callback, and verified-profile boundaries. | Complete |
| Collision protection | Block unsafe social auto-linking and require a future ownership-proof workflow. | Complete |
| Fallback options | Return safe available methods only for a valid short-lived workflow. | Complete |
| Acceptance tests | Prove UC-101 to UC-103, UC-105, UC-106, UC-303, and collision safety. | Complete |
| UI and documentation | Document missing login states without changing approved wireframes. | Complete |

#### Completion Checklist

- [x] Unknown users and incorrect passwords have safe, generic behavior.
- [x] Five failed password attempts trigger a 15-minute temporary lock.
- [x] Phone login OTPs are hashed, expiring, attempt-limited, and single-use.
- [x] Device and IP signals influence risk but never authenticate a user alone.
- [x] High-risk outcomes require MFA rather than creating a session.
- [x] OIDC state, nonce, PKCE, issuer, audience, and verified-email rules are enforced.
- [x] Matching social email never auto-links to an existing account.
- [x] No access or refresh JWT is issued before Milestone 6.
- [x] Documentation and UI proposals are reviewed by the project owner.

### Milestone 5 - MFA, Backup Methods, and Passkeys

#### Goal

Add reusable second-factor verification and enrollment so web and future mobile clients can safely complete high-risk login workflows before Milestone 6 creates a session.

#### Work Items

| Work item | Simple description | Final status |
|---|---|---|
| Challenge workflow | Bind every second-factor attempt to a short-lived proven-login workflow. | Complete |
| Authenticator app | Enroll encrypted TOTP secrets and verify replay-safe six-digit codes. | Complete |
| Email/SMS backup | Issue hashed, expiring, single-use secondary codes to verified contacts. | Complete |
| Backup codes | Generate one-time recovery codes, store only keyed hashes, and consume atomically. | Complete |
| Passkeys | Register and verify WebAuthn credentials with origin, RP, challenge, signature, and counter checks. | Complete |
| Factor management | Safely list, label, and revoke factors without exposing secrets. | Complete |
| Collision ownership | Reuse proven password/MFA workflows before linking a matching social identity. | Complete |
| Workflow handoff | Return `session_ready` only after required MFA; continue issuing no JWTs before Milestone 6. | Complete |
| Acceptance tests | Prove UC-104 and UC-201 to UC-204 success, replay, expiry, lock, and fallback paths. | Complete |
| UI and documentation | Propose missing MFA/passkey states without changing approved frontend screens. | Complete |

#### Completion Checklist

- [x] TOTP secrets are encrypted and never returned after initial enrollment setup.
- [x] A TOTP time step cannot be accepted twice and three failures lock the factor for 15 minutes.
- [x] Email and SMS challenges are hashed, expiring, attempt-limited, and single-use.
- [x] Backup recovery codes are shown once, stored only as keyed hashes, and consumed once.
- [x] Passkeys enforce the expected RP ID, origin, challenge, user verification, and signature counter.
- [x] WebAuthn and login workflows cannot be replayed.
- [x] Unknown, expired, locked, and provider-failure paths return safe problem responses.
- [x] No factor can be enrolled or removed without a valid proven workflow.
- [x] No access or refresh JWT is issued before Milestone 6.
- [x] Documentation and UI proposals are reviewed by the project owner.

### Milestone 6 - Sessions and Token Security

#### Goal

Create secure signed-in sessions after approved login and MFA workflows, while giving web and future mobile clients safe token refresh, logout, device visibility, and stolen-token protection.

#### Work Items

| Work item | Simple description | Final status |
|---|---|---|
| Session creation | Exchange a one-time `session_ready` workflow for a signed access token and protected refresh token. | Complete |
| Signing and JWKS | Sign access tokens with rotating asymmetric keys and publish public verification keys. | Complete |
| Web/mobile delivery | Use a secure browser cookie for web refresh tokens and a JSON response for mobile secure storage. | Complete |
| Refresh rotation | Replace every used refresh token atomically and reject replayed generations. | Complete |
| Theft response | Revoke the complete token family, record an audit alert, and require a new login after reuse. | Complete |
| Logout and revocation | Support current-device logout, all-device logout, and immediate Redis-backed denial. | Complete |
| Session limits | Enforce 15-minute access and idle limits, a 24-hour session limit, a 30-day family ceiling, and maximum 10 sessions. | Complete |
| Device sessions | List safe active-device details and let an owner revoke a selected session. | Complete |
| Go verification | Validate signatures, expiry, audience, issuer, and revocation in the reusable Go gateway. | Complete |
| Tests and documentation | Prove UC-401 to UC-405 and UC-509 across web/mobile, replay, timeout, and revocation paths. | Complete |

#### Completion Checklist

- [x] A session can be created only from a valid, single-use `session_ready` workflow.
- [x] Access tokens are signed asymmetrically and expire within 15 minutes.
- [x] Refresh tokens are stored only as hashes and rotate atomically after every use.
- [x] Reusing an older refresh token revokes the complete family and records a theft alert.
- [x] Browser refresh tokens use `Secure`, `HttpOnly`, `SameSite=Lax` cookies and CSRF protection.
- [x] Mobile refresh tokens are returned only for secure device storage.
- [x] Current-device, all-device, selected-session, and timeout revocation paths work immediately.
- [x] A user cannot exceed 10 active session families.
- [x] The Go verifier rejects invalid, expired, incorrectly scoped, or revoked access tokens.
- [x] Documentation and proposed session-management screens were reviewed and approved by the project owner.

### Milestone 7 - Personal and Organization Workspaces

#### Goal

Give every user one private workspace for managing their own portfolio, allow optional secure organization collaboration, and let users refer friends without sharing portfolio access or private login activity.

#### Work Items

| Work item | Simple description | Final status |
|---|---|---|
| Workspace foundation | Define one reusable security model for personal and organization portfolio contexts. | Complete |
| Personal workspace | Automatically provide exactly one private, owner-only workspace to every user, including existing users. | Complete |
| Personal referrals | Send expiring referral links and track invited, registered, and verified milestones without exposing login activity. | Complete |
| Future reward boundary | Record attribution now but keep undecided incentives, qualification, and reward calculations outside this milestone. | Complete |
| Organization creation | Let a user optionally create an organization and atomically become its owner. | Complete |
| Role catalog | Use the approved canonical organization roles and permissions instead of free-form permissions. | Complete |
| Invitations | Issue hashed, expiring, single-use organization invitations with proposed roles and safe email delivery. | Complete |
| Invitation acceptance | Verify the invitee, consume the invitation once, and create organization membership safely. | Complete |
| Workspace listing | Return the user's personal workspace and only the organizations where they have active membership. | Complete |
| Member management | List organization members and replace roles only when the acting member has permission. | Complete |
| Context switching | Verify ownership or membership and issue a short-lived token scoped to the selected workspace. | Complete |
| Member offboarding | Revoke organization roles and active organization-scoped access immediately. | Complete |
| Data isolation | Prevent personal and organization portfolio data from crossing workspace boundaries. | Complete |
| Tests and documentation | Prove personal privacy plus UC-305, UC-306, UC-308, UC-309, UC-310, and UC-506 authorization and replay failures. | Complete |

#### Completion Checklist

- [x] Every new and existing user has exactly one private personal workspace.
- [x] Personal workspaces cannot accept invitations, additional members, or organization roles.
- [x] A user's personal workspace cannot be transferred, removed, or entered by another user.
- [x] Referral tokens are random, hashed at rest, expiring, rate-limited, and never grant workspace access.
- [x] A referrer sees only masked invited, registered, verified, expired, or revoked status—not login or portfolio activity.
- [x] Self-referrals and referrals for existing accounts are denied safely.
- [x] Reward qualification and benefits remain disabled until a separate business plan is approved.
- [x] Organization creation and owner membership occur in one database transaction.
- [x] Invitation tokens are random, hashed at rest, expiring, and single-use.
- [x] Invite acceptance cannot grant roles outside the approved catalog.
- [x] Users can list and enter only their personal workspace and organizations where they have active membership.
- [x] Scoped tokens identify the selected workspace, its type, and any verified organization roles.
- [x] Unauthorized role changes, member reads, and removals are denied safely.
- [x] Removing a member revokes bindings and active tenant access immediately.
- [x] A last owner cannot be removed or demoted without a safe ownership transfer.
- [x] PostgreSQL tests prove personal, cross-user, and cross-organization data isolation.
- [x] Documentation and proposed workspace-management needs were reviewed by the project owner; no frontend screens were created or changed.

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
- Project owner reviewed and approved Milestone 5 for GitHub publication.
- Added an exact-value Gitleaks allowlist for two known local-only encryption fixtures after the scanner correctly blocked the first merge attempt.
- Merged Milestone 5 pull request #6 into `main` after all six GitHub checks passed.
- Started Milestone 6 on branch `codex/milestone-6-sessions`.
- Reconciled UC-401 to UC-405 and UC-509 into one web/mobile session-security scope.
- Added a permanent Completed Milestone Archive that preserves the goals, work items, and completion checklists for Milestones 1 through 5.
- Added one-time session creation from approved login/MFA workflows with RS256 access tokens and public JWKS discovery.
- Added web-only secure refresh cookies and double-submit CSRF protection while returning mobile refresh tokens for future Keychain/Keystore storage.
- Added atomic PostgreSQL refresh rotation, keyed token hashes, replay theft detection, complete family revocation, and security audit evidence.
- Added current, global, and selected-session logout plus 15-minute idle, 24-hour session, 30-day family, and 10-session cap enforcement.
- Extended the Go verifier to cache public signing keys and reject invalid signature, issuer, audience, expiry, access JTI, family, and user revocation states.
- Added seven session/JWKS API boundaries and expanded the shared OpenAPI contract to 34 paths.
- Added session architecture documentation and UI recommendations without creating or changing frontend screens.
- Passed 46 fast API/security tests and 18 real PostgreSQL/Redis integration tests.
- Passed Python lint/type checks, web lint/type/test/build, Go tests/vet, documentation validation, OpenAPI parsing, and Compose validation.
- Rebuilt the Docker API and Go verifier and completed a live issue, verify, rotate, old-access denial, replay detection, and family-revocation sequence.
- Marked Milestone 6 ready for stakeholder review; final acceptance remains with the project owner.
- Project owner reviewed and approved the complete Milestone 6 scope.
- Opened pull request #7 and passed all six GitHub quality checks.
- Merged pull request #7 into `main` with merge commit `78d4620e63aea4f9e3755a0a9941a5e91c71168a`.
- Preserved the complete Milestone 6 goal, work items, and completion checklist in the permanent archive.
- Started Milestone 7 planning on branch `codex/milestone-7-organizations`.
- Reconciled the organization scope with UC-305, UC-306, UC-308, and UC-506.
- Project owner clarified that GroX must also serve individuals who manage only their own financial portfolios.
- Expanded Milestone 7 to provide every user a private personal workspace while keeping organization participation optional.
- Project owner approved adding personal user referrals as a separate acquisition use case from organization invitations.
- Added UC-310 referral tracking for invitation, profile-created, and profile-verified status; rewards remain future work.
- Started the Milestone 7 implementation with personal workspace persistence, referral attribution, registration hooks, and shared web/mobile APIs.
- Added migration `0008_workspaces_and_referrals`, including automatic existing-user backfill and canonical owner/member/viewer permissions.
- Added `GET /workspaces`, `POST /organizations`, `POST /referrals`, and `GET /referrals` without changing any frontend screen.
- Connected email registration and verification to referral registration and verification milestones.
- Expanded the shared OpenAPI contract to 37 paths and documented UC-309 and UC-310 across the SRS, schema, methods, diagrams, roadmap, and traceability matrix.
- Passed 51 fast Python tests, 20 real PostgreSQL/Redis tests, web tests and production build, Python lint/type checks, Go tests/vet, documentation validation, Compose validation, OpenAPI parsing, migration downgrade/upgrade, and zero schema drift.
- Added organization invitation, acceptance, member listing, role replacement, workspace switching, and offboarding controls and API boundaries.
- Added owner/member/viewer catalog enforcement, matching-email acceptance, last-owner protection, and PostgreSQL rejection of collaboration records in personal workspaces.
- Added workspace-scoped JWT claims and organization-specific Redis revocation to both the Python issuer and reusable Go verifier.
- Confirmed offboarding invalidates the removed member's organization token while preserving their account, personal workspace, and unrelated sessions.
- Expanded the shared OpenAPI contract to 43 paths and added the delivered workspace architecture guide without creating frontend screens.
- Passed the completed Milestone 7 backend with 55 fast Python tests and 22 real PostgreSQL/Redis tests, including invitation replay, role authorization, personal isolation, scoped-token replacement, last-owner protection, and offboarding revocation paths.
- Project owner approved the complete Milestone 7 delivery and authorized its GitHub pull request and merge.
- Corrected the root README milestone status and added a permanent milestone-by-milestone Quality Assurance Tracker.
- Opened Milestone 7 pull request #8 and passed all six GitHub quality checks.
- Merged pull request #8 into `main` with merge commit `af6061df0eb92b8985384eb09f406ea774807263`.
- Preserved the complete Milestone 7 goal, work items, and completion checklist in the permanent archive.
- Started Milestone 8 recovery and controlled-administration planning on branch `codex/milestone-8-recovery-admin`.
- Added password-reset request and execution with generic responses, three-per-hour limits, keyed token hashes, HIBP checks, Argon2id, recent-password history, replay rejection, session revocation, and security alerts.
- Added recent-MFA contact changes with separate hashed old/new channel proofs and atomic application only after both succeed.
- Added database-backed global staff roles, authorized unlock/suspension, support recovery, and immediate account-wide session revocation.
- Added four-eyes MFA reset initiation, distinct L3 approval, target-version revalidation, mandatory 12-hour delay, execution, notification, and audit evidence.
- Added migration `0009_recovery_governance`, including staff bindings, contact workflows, governed timestamps, and password-history backfill.
- Expanded the shared web/mobile OpenAPI contract from 43 to 55 paths and added the delivered recovery architecture guide without changing frontend screens.
- Passed 68 fast Python tests and 26 real PostgreSQL/Redis tests, including reset replay/history, dual contact proof, staff-role denial, row isolation, self-approval denial, early-execution denial, and MFA revocation.
- Passed Python lint/type checks, web lint/type/test/build, Go tests/vet, documentation validation, OpenAPI parsing, Compose validation, migration downgrade/upgrade, zero schema drift, and a live 202 generic recovery smoke test.
- Marked Milestone 8 ready for project-owner review; no frontend visual was created or changed.

## Decisions

| Decision | Reason |
|---|---|
| Use one repository for web, backend, future mobile, shared contracts, infrastructure, and documentation. | Keeps related changes synchronized while allowing each service to run separately. |
| Build a small working foundation before authentication features. | Finds setup and communication problems early, before security logic becomes complex. |
| Keep the future mobile application visible in the structure but do not design unapproved screens. | Protects future reuse without creating unauthorized UI work. |
| Keep session rules shared while delivering refresh tokens differently to web and mobile clients. | Browsers require protected cookies, while mobile apps require operating-system secure storage. |
| Give every user one private personal workspace and make organizations optional. | Individuals can manage their own portfolios without joining a business, while the same account can later access organization portfolios. |
| Keep personal referrals separate from organization invitations. | Referrals grow the user base but never grant access to another person's or company's portfolio. |
| Track referral attribution now and defer rewards. | The business can measure acquisition while incentive rules, fraud controls, and benefits remain unapproved. |
| Track progress in this file. | Gives non-technical and technical stakeholders one clear status record. |

## Current Blockers or Owner Actions

There are no current owner blockers. Local Mailpit and simulated providers support recovery development without paid credentials. AWS KMS credentials, production messaging providers, and production domains are not needed until later deployment milestones.

## Next Planned Milestone

After recovery and controlled administration are accepted, Milestone 9 will add audit review, privacy export, account erasure, and retention workflows.
