# Quality Assurance Tracker

**Last updated:** August 16, 2026

This is the permanent record of tests and quality checks completed during each project milestone. In simple terms, it shows what we checked, why we checked it, and whether it passed.

The [Testing Strategy](./testing_strategy.md) defines the overall testing approach. This tracker records the checks that were actually performed. Detailed day-by-day delivery evidence remains in the [Project Progress Tracker](./project_progress.md).

## Result Key

| Result | Meaning |
|---|---|
| Passed | The check completed successfully. |
| Accepted | The project owner reviewed and approved the milestone. |
| Awaiting review | Technical checks passed; final project-owner acceptance is still pending. |
| Not applicable | The check was not required for that milestone. |

## Milestone Summary

| Milestone | Main QA evidence | Owner status |
|---|---|---|
| 0. Documentation | Specification consistency, links, diagrams, and documentation validation | Accepted |
| 1. Project foundation | Python, web, Go, documentation, Docker, health, and browser checks | Accepted |
| 2. Data foundation | 4 fast tests, 6 database/Redis tests, migrations, schema drift, and Docker checks | Accepted |
| 3. Registration | 12 fast tests, 9 database/Redis tests, live email verification, replay rejection, and full repository checks | Accepted |
| 4. Login | 25 fast tests, 12 database/Redis tests, authentication abuse cases, and migration checks | Accepted |
| 5. Extra security | 40 fast tests, 14 database/Redis tests, MFA/passkey security, Docker health, and full repository checks | Accepted |
| 6. Sessions | 46 fast tests, 18 database/Redis tests, live token rotation/replay, Go verification, and six GitHub checks | Accepted |
| 7. Workspaces | 55 fast tests, 22 database/Redis tests, isolation/revocation scenarios, migrations, and full repository checks | Accepted |
| 8. Recovery and administration | 68 fast tests, 26 database/Redis tests, recovery/governance abuse scenarios, migrations, and full repository checks | Awaiting owner review |

## Milestone 0 - Documentation

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Requirements | Reviewed use cases, methods, API contracts, database design, sequence diagrams, and flowcharts together. | Prevents implementation documents from describing conflicting systems. | Passed |
| Documentation structure | Created a central catalog and organized product, architecture, delivery, operations, specifications, and use-case documents. | Makes the project understandable and traceable for technical and non-technical readers. | Passed |
| Documentation validation | Checked internal document links and required documentation structure. | Finds missing or broken documentation before development begins. | Passed |
| Owner review | Presented the documentation before application implementation. | Confirms the agreed system direction before code is written. | Accepted |

## Milestone 1 - Project Foundation

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Python API | Ran linting, strict type checks, and 3 API tests. | Confirms the initial backend is clean and behaves as expected. | Passed |
| Web application | Ran linting, type checks, component tests, and a production build. | Confirms the web foundation can be safely built. | Passed |
| Go verifier | Ran formatting, tests, and static analysis. | Confirms the reusable token-verification service is valid. | Passed |
| Connected environment | Started Next.js, FastAPI, Go, PostgreSQL, Redis, and Mailpit with Docker and checked service health. | Proves all local components can work together. | Passed |
| Browser smoke test | Opened the website and confirmed the API, PostgreSQL, and Redis showed as connected. | Gives a real user-level confirmation beyond isolated tests. | Passed |
| Security/dependencies | Ran documentation validation and checked production web dependencies for known vulnerabilities. | Detects basic documentation and dependency risks early. | Passed |
| Owner review | Reviewed the live foundation page. | Confirms the first working foundation meets expectations. | Accepted |

## Milestone 2 - Data Foundation

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Fast tests | Ran 4 API and storage tests. | Checks repository behavior quickly without requiring the full environment. | Passed |
| Real storage tests | Ran 6 PostgreSQL and Redis integration tests. | Proves behavior against the same types of data services used by the application. | Passed |
| Database migrations | Upgraded an empty temporary database through every migration. | Confirms a new environment can create the database correctly. | Passed |
| Schema drift | Compared SQLAlchemy models with the migrated database. | Prevents code and database definitions from silently becoming inconsistent. | Passed |
| Docker health | Rebuilt the stack and confirmed migrations completed before a healthy API startup. | Proves startup order and service dependencies work together. | Passed |
| Owner review | Visually inspected the database tables and columns. | Confirms the delivered database structure is understandable and approved. | Accepted |

## Milestone 3 - Registration and Verification

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Fast tests | Ran 12 API tests. | Checks signup, validation, hashing, and public API behavior. | Passed |
| Real storage tests | Ran 9 PostgreSQL and Redis integration tests. | Checks real constraints, OTP state, expiration, and replay behavior. | Passed |
| Live email journey | Created an account, opened the Mailpit verification email, activated the account, and retried the link. | Proves the complete registration journey works and a verification link cannot be reused. | Passed |
| Full repository checks | Ran Python lint/type, web test/lint/type/build, Go test/vet, documentation, OpenAPI, migrations, Compose, and dependency audit checks. | Confirms registration changes did not break another project area. | Passed |
| Owner review | Reviewed the plain-language delivery summary. | Confirms the delivered registration scope is accepted. | Accepted |

## Milestone 4 - Primary Authentication and Risk

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Fast tests | Ran 25 authentication and API tests. | Checks password, phone, social login, lockout, and risk behavior quickly. | Passed |
| Real storage tests | Ran 12 PostgreSQL and Redis integration tests. | Proves rate limits, workflow handoffs, identity collisions, and replay controls use real storage correctly. | Passed |
| Security scenarios | Checked generic failures, temporary locks, OIDC state/nonce/PKCE validation, and social-email collision protection. | Prevents account discovery, brute force, replay, and unsafe account linking. | Passed |
| Database migrations | Confirmed Alembic had no schema drift. | Keeps login identity definitions synchronized with the database. | Passed |
| Owner review | Reviewed and approved the primary-authentication delivery. | Confirms the delivered login scope is accepted. | Accepted |

## Milestone 5 - MFA, Backup Methods, and Passkeys

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Fast tests | Ran 40 API and security tests. | Checks MFA, backup codes, passkeys, factor management, and error behavior. | Passed |
| Real storage tests | Ran 14 PostgreSQL and Redis integration tests. | Proves one-time challenges, replay protection, attempt limits, and persistence behavior. | Passed |
| Passkey security | Checked website, origin, challenge, user verification, signature, credential, and counter rules. | Prevents a passkey assertion from being accepted in the wrong context. | Passed |
| Full repository checks | Ran Python, web, Go, documentation, OpenAPI, Compose, migration, and Docker health checks. | Confirms the security additions work without breaking existing services. | Passed |
| Live API smoke test | Rebuilt the API and confirmed safe RFC 7807 errors from live MFA endpoints. | Verifies the running service reports failures safely and consistently. | Passed |
| GitHub security check | Added a narrow allowlist for known local-only test fixtures after secret scanning correctly blocked the first merge attempt. | Keeps secret scanning strict while documenting the exact safe exception. | Passed |
| Owner review | Reviewed and approved the MFA/passkey delivery. | Confirms the delivered extra-security scope is accepted. | Accepted |

## Milestone 6 - Sessions and Token Security

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Fast tests | Ran 46 API and security tests. | Checks token issuance, refresh, logout, session limits, and revocation. | Passed |
| Real storage tests | Ran 18 PostgreSQL and Redis integration tests. | Proves rotation, replay detection, family revocation, and expiry behavior with real storage. | Passed |
| Cross-language verification | Ran Go tests/vet against JWT signature, issuer, audience, key, token, family, and user revocation rules. | Confirms other Vittavaan services can safely trust tokens issued by Python. | Passed |
| Live theft simulation | Issued and verified tokens, rotated refresh credentials, rejected old access, replayed an old refresh token, and confirmed family revocation. | Proves the system responds correctly when token theft is simulated. | Passed |
| Full repository checks | Ran Python, web, Go, documentation, OpenAPI, and Compose checks. | Confirms session work remains compatible with the full repository. | Passed |
| GitHub CI | Passed all 6 protected pull-request checks before merge. | Provides an independent automated merge gate. | Passed |
| Owner review | Reviewed and approved the complete session scope. | Confirms the delivered session-security scope is accepted. | Accepted |

## Milestone 7 - Personal and Organization Workspaces

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Fast tests | Ran 55 Python API and security tests. | Checks personal workspaces, referrals, organizations, roles, invitations, switching, and removal. | Passed |
| Real storage tests | Ran 22 PostgreSQL and Redis integration tests. | Proves workspace isolation, invitation state, membership, and revocation against real data services. | Passed |
| Authorization abuse | Tested invitation replay, unauthorized roles, cross-user access, cross-organization access, and last-owner protection. | Prevents users from gaining or removing access they are not allowed to control. | Passed |
| Privacy and isolation | Tested personal workspace isolation and confirmed referrals expose no login or portfolio activity. | Protects an individual's private financial workspace and referred users' privacy. | Passed |
| Token/offboarding | Tested scoped-token replacement and immediate organization access revocation while preserving unrelated access. | Ensures removing a member blocks only the intended organization access. | Passed |
| Database migrations | Ran downgrade/upgrade checks and confirmed zero schema drift. | Proves the workspace schema can be deployed consistently and remains aligned with code. | Passed |
| Full repository checks | Ran Python lint/type, web test/lint/type/build, Go test/vet, documentation, OpenAPI parsing, and Compose validation. | Confirms Milestone 7 did not break another service or shared contract. | Passed |
| GitHub CI | Passed all 6 protected pull-request checks before merge. | Provides an independent automated merge gate. | Passed |
| Owner review | Reviewed and approved Milestone 7; no frontend screen was created or changed. | Confirms the backend and documentation are accepted while respecting the UI approval rule. | Accepted |

## Milestone 8 - Recovery and Controlled Administration

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Fast tests | Ran 68 Python API and security tests. | Checks generic recovery responses, password rules, contact proofs, staff authorization, support recovery, suspension, and governed-reset controls. | Passed |
| Real storage tests | Ran 26 PostgreSQL and Redis integration tests. | Proves single-use token state, recent-password history, contact isolation/application, read-only staff bindings, governed locking, and MFA revocation against real services. | Passed |
| Password abuse | Tested unknown accounts, token hashing, token replay, recent-password reuse, breached-password rejection, and session revocation. | Prevents account discovery and reuse of stolen links, passwords, or sessions. | Passed |
| Contact-change security | Tested recent-MFA enforcement and separate old/new proof before applying a contact. | Prevents an attacker controlling only one channel from replacing account contacts. | Passed |
| Staff authorization | Tested database-backed roles, missing-role denial, ticket requirements, suspension revocation, and support recovery. | Prevents request data or organization roles from granting platform-wide staff power. | Passed |
| Four-eyes governance | Tested distinct actors, L2/L3 roles, target-version checks, early-execution denial, 12-hour delay, execution, notification, and factor revocation. | Prevents one support worker from silently removing a user's MFA protection. | Passed |
| Database migrations | Ran empty-database upgrade, downgrade/upgrade rehearsal, 22-table assertion, and zero schema-drift check. | Proves recovery tables can be deployed consistently and rolled back safely in development. | Passed |
| Shared API contract | Parsed 55 shared OpenAPI paths with 56 unique operations and confirmed the live FastAPI exposes the same 55 paths. | Keeps the web client and future mobile app aligned to one reusable service contract. | Passed |
| Full repository checks | Ran Python lint/type, web test/lint/type/build, Go test/vet, documentation, Compose, OpenAPI, and formatting checks. | Confirms Milestone 8 did not break another service or document set. | Passed |
| Live API smoke test | Rebuilt the Docker API, confirmed PostgreSQL/Redis readiness, and received the generic HTTP 202 response for an unknown recovery email. | Proves the running service behaves safely, not just isolated tests. | Passed |
| UI boundary | Confirmed no frontend screen or wireframe was created or changed. | Preserves the project owner's design-approval requirement. | Passed |
| GitHub CI | Passed all 6 protected pull-request checks before merge. | Provides an independent automated merge gate. | Passed |
| Owner review | Reviewed and approved Milestone 8; no frontend screen was created or changed. | Confirms the recovery and administration delivery is accepted while respecting the UI approval rule. | Accepted |

## Milestone 9 - Privacy and Auditing

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Focused privacy tests | Ran 14 control and HTTP tests for audit authorization, encrypted export, tamper rejection, explicit erasure confirmation, session revocation, and ownership-transfer blocking. | Proves the delivered UC-505, UC-601, and UC-602 control and API behavior. | Passed |
| Real database isolation | Ran 4 PostgreSQL tests for audit access, owner-only export storage, erasure, evidence retention, and last-owner blocking. | Proves the complete privacy workflow against real constraints and row-level security. | Passed |
| Database migrations | Created fresh test databases through migrations `0010` to `0012`, with drift and downgrade/re-upgrade rehearsal. | Proves audit, export, erasure-retention, and row-level policies install and reverse safely. | Passed |
| Export encryption | Confirmed the owner's plaintext email is absent from stored artifact bytes and that owner/request binding plus digest verification rejects tampering. | Prevents database readers or modified ciphertext from silently exposing or changing an export. | Passed |
| Idempotency and expiry | Confirmed a repeated key returns the original request and artifacts receive a 24-hour expiry. | Prevents duplicate work and limits the lifetime of downloadable personal data. | Passed |
| Erasure sequencing | Confirmed session revocation occurs before anonymization and explicit confirmation is mandatory. | Prevents continued account use and accidental destructive requests. | Passed |
| PII anonymization | Confirmed names, contacts, identities, MFA factors, and trusted devices are removed while immutable erasure evidence remains. | Satisfies the designed right-to-erasure boundary without destroying lawful evidence. | Passed |
| Organization safety | Confirmed the final active organization owner cannot erase their account before transferring ownership. | Prevents an organization from becoming inaccessible or ownerless. | Passed |
| Backup retention | Confirmed each completed erasure records the configured 30-day backup-purge deadline. | Gives AWS backup lifecycle controls a measurable deadline without mutating immutable snapshots from the app. | Passed |
| Focused code quality | Ran Ruff and MyPy against the new privacy and audit modules. | Catches formatting, unsafe typing, and interface mistakes in the changed scope. | Passed |
| Shared API contract | Parsed the shared OpenAPI contract with 60 paths. | Keeps the website and future mobile app aligned to the same audit, export, and erasure services. | Passed |
| UI boundary | Confirmed no frontend screen or wireframe was created or changed. | Preserves the project owner's design-approval requirement. | Passed |
| CI corrective action | The first PR run found a stale 22-table assertion after the encrypted artifact table became table 23; updated only the expected count and migration head, then passed all 5 persistence tests. | Records the failed check and focused correction instead of hiding it. | Passed |
| GitHub CI | Passed all 6 protected pull-request checks before merge. | Provides an independent automated merge gate. | Passed |
| Owner review | Reviewed and approved complete Milestone 9; no frontend screen was created or changed. | Confirms privacy and auditing are accepted while respecting the UI approval rule. | Accepted |

## Milestone 10 - Web Experience

| QA area | Check performed | Why it matters | Result |
|---|---|---|---|
| Wireframe visual review | Rendered and inspected all 11 pages of the supplied GroX PDF, including each empty, populated, enabled, and error state. | Ensures the plan reflects the actual visual baseline rather than only a written summary. | Passed |
| API journey mapping | Mapped the existing and proposed screens to the 60 shared web/mobile API paths. | Prevents frontend journeys from inventing or duplicating backend behavior. | Passed |
| Security copy review | Identified account-enumerating invalid-login wording and proposed generic replacement copy. | Prevents the website from weakening the backend's generic credential response. | Ready for owner review |
| Recovery-flow review | Identified the wireframed reset OTP conflict with the delivered secure-link reset service and proposed aligned replacement states. | Keeps the website consistent with the implemented single-use recovery security. | Ready for owner review |
| UI boundary | Confirmed no frontend code, screen, wireframe, or visual asset was created or changed. | Preserves the project owner's design-approval requirement. | Passed |
| Owner review | Screen inventory, navigation, recommendations, and staged implementation scope are ready for review. | Frontend visual and code work remains blocked until explicitly approved. | Awaiting review |

## Maintenance Rule

For every milestone, this file must be updated before merge with:

1. Automated test counts and results.
2. Integration, migration, security, and live-flow checks performed.
3. GitHub pull-request check results.
4. Stakeholder acceptance status.
5. Any failed check and the corrective action taken.
