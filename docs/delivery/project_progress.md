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
| 0. Documentation | Agree on what we are building before writing application code. | Ready for review |
| 1. Project foundation | Create the folders, tools, local services, and automatic checks needed for development. | Complete |
| 2. Data foundation | Create the secure database and temporary storage structures. | Not started |
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

## Current Milestone: 1 - Project Foundation

### Goal

Prepare the project's basic structure so a developer can run the website, backend, token-checking service, PostgreSQL, Redis, and test email inbox in a consistent way.

### Work Items

| Work item | Simple description | Status |
|---|---|---|
| Monorepo folders | Organize the website, backend, future mobile app, shared files, tests, and infrastructure. | Ready for review |
| Tool versions | Record the required Python, Node.js, Go, and package-manager versions. | Ready for review |
| Local services | Configure PostgreSQL, Redis, and Mailpit using Docker Compose. | Ready for review |
| Backend health check | Provide a safe page showing whether the API and its dependencies are running. | Ready for review |
| Website status page | Show a simple website page that calls the backend health check. | Ready for review |
| Go service health check | Confirm the future JWT verification component can run independently. | Ready for review |
| Shared API contract | Document health endpoints in the first machine-readable OpenAPI file. | Ready for review |
| Automated checks | Configure GitHub to test documentation, Python, web, Go, and containers. | Ready for review |
| Setup guide | Explain how another developer starts and checks the project. | Ready for review |
| Local validation | Run the complete connected environment and all available quality checks. | Ready for review |

### Completion Checklist

- [x] A new developer can follow the setup guide.
- [x] One command starts all local services.
- [x] The website opens and displays backend availability.
- [x] FastAPI reports application, PostgreSQL, and Redis readiness.
- [x] The Go verifier reports that it is alive and ready.
- [x] Automated tests and quality checks pass.
- [x] No credentials are committed.
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

## Decisions

| Decision | Reason |
|---|---|
| Use one repository for web, backend, future mobile, shared contracts, infrastructure, and documentation. | Keeps related changes synchronized while allowing each service to run separately. |
| Build a small working foundation before authentication features. | Finds setup and communication problems early, before security logic becomes complex. |
| Keep the future mobile application visible in the structure but do not design unapproved screens. | Protects future reuse without creating unauthorized UI work. |
| Track progress in this file. | Gives non-technical and technical stakeholders one clear status record. |

## Current Blockers or Owner Actions

There are no technical blockers or owner actions for Milestone 1. No cloud credentials were needed.

## Next Planned Milestone

After this foundation is accepted, Milestone 2 will create the first secure PostgreSQL and Redis structures using migrations and automated isolation tests.
