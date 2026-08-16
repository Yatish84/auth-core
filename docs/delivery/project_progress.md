# Project Progress Tracker

**Last updated:** August 14, 2026

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
| 3. Registration | Allow a user to create and verify an account. | Not started |
| 4. Login | Allow safe password, phone, and social sign-in. | Not started |
| 5. Extra security | Add MFA, authenticator codes, backup methods, and passkeys. | Not started |
| 6. Sessions | Add secure tokens, refresh, logout, device sessions, and theft detection. | Not started |
| 7. Organizations | Add organizations, invitations, roles, and member removal. | Not started |
| 8. Recovery and administration | Add password recovery and controlled support actions. | Not started |
| 9. Privacy and auditing | Add audit review, data export, and account erasure. | Not started |
| 10. Web experience | Connect all approved website screens to working services. | Not started |
| 11. Public test website | Publish the controlled MVP for stakeholder testing. | Not started |
| 12. AWS production preparation | Harden and move the system to the final AWS environment. | Not started |

## Current Milestone: 2 - Data Foundation

### Goal

Create the secure, reusable storage layer that future web and mobile registration, login, session, organization, recovery, and audit workflows will share.

### Work Items

| Work item | Simple description | Status |
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

### Completion Checklist

- [x] An empty PostgreSQL database upgrades to the latest schema.
- [x] All approved tables and important constraints exist.
- [x] Cross-organization reads and writes are rejected.
- [x] Audit records reject update and delete attempts.
- [x] Redis security keys use safe identifiers and explicit expiration.
- [x] Repository and migration integration tests pass.
- [x] No plaintext secrets or customer data are committed.
- [x] Documentation is updated and reviewed.

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

## Decisions

| Decision | Reason |
|---|---|
| Use one repository for web, backend, future mobile, shared contracts, infrastructure, and documentation. | Keeps related changes synchronized while allowing each service to run separately. |
| Build a small working foundation before authentication features. | Finds setup and communication problems early, before security logic becomes complex. |
| Keep the future mobile application visible in the structure but do not design unapproved screens. | Protects future reuse without creating unauthorized UI work. |
| Track progress in this file. | Gives non-technical and technical stakeholders one clear status record. |

## Current Blockers or Owner Actions

There are no technical blockers or owner actions for Milestone 2. No cloud credentials were needed.

## Next Planned Milestone

After the data foundation is accepted, Milestone 3 will implement account registration and contact verification using the shared storage layer.
