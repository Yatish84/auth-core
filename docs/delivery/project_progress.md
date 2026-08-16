# Project Progress Tracker

**Last updated:** August 15, 2026

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
| 4. Login | Allow safe password, phone, and social sign-in. | Not started |
| 5. Extra security | Add MFA, authenticator codes, backup methods, and passkeys. | Not started |
| 6. Sessions | Add secure tokens, refresh, logout, device sessions, and theft detection. | Not started |
| 7. Organizations | Add organizations, invitations, roles, and member removal. | Not started |
| 8. Recovery and administration | Add password recovery and controlled support actions. | Not started |
| 9. Privacy and auditing | Add audit review, data export, and account erasure. | Not started |
| 10. Web experience | Connect all approved website screens to working services. | Not started |
| 11. Public test website | Publish the controlled MVP for stakeholder testing. | Not started |
| 12. AWS production preparation | Harden and move the system to the final AWS environment. | Not started |

## Current Milestone: 3 - Registration and Verification

### Goal

Build one secure registration and contact-verification service that the web app and future mobile app can both use.

### Work Items

| Work item | Simple description | Status |
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

### Completion Checklist

- [x] Email registration creates a pending account and never stores plaintext passwords.
- [x] Breached passwords and invalid CAPTCHA proofs are rejected safely.
- [x] Email verification links are hashed, expiring, single-use, and resendable.
- [x] Phone OTPs are hashed, rate-limited, attempt-limited, and short-lived.
- [x] Duplicate and unknown-contact responses do not leak unsafe account details.
- [x] Web and future mobile clients share the same versioned API contract.
- [x] UC-301, UC-302, and UC-304 acceptance tests pass with real PostgreSQL and Redis.
- [x] Documentation and UI recommendations are reviewed.

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

## Decisions

| Decision | Reason |
|---|---|
| Use one repository for web, backend, future mobile, shared contracts, infrastructure, and documentation. | Keeps related changes synchronized while allowing each service to run separately. |
| Build a small working foundation before authentication features. | Finds setup and communication problems early, before security logic becomes complex. |
| Keep the future mobile application visible in the structure but do not design unapproved screens. | Protects future reuse without creating unauthorized UI work. |
| Track progress in this file. | Gives non-technical and technical stakeholders one clear status record. |

## Current Blockers or Owner Actions

There are no technical blockers or owner actions for Milestone 3. No paid provider credentials were needed.

## Next Planned Milestone

After registration and verification are accepted, Milestone 4 will implement password, phone OTP, and social sign-in with adaptive risk evaluation.
