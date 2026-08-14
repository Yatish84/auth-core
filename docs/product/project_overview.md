# Project Overview

## What We Are Building

`auth-core` is the secure front door for the Vittavaan financial platform. It will identify users, protect their accounts, manage their sessions and permissions, and issue trusted access tokens to other Vittavaan services.

The first visible deliverable is a responsive web application that reviewers can open and test. A future React Native / Expo mobile application will use the same backend services and business rules rather than rebuilding authentication.

## The Gatehouse Analogy

Think of Vittavaan as a secured business campus:

- `auth-core` is the gatehouse that checks identity and issues a short-lived access pass.
- Business products such as WealthOS, LoanDesk, BusinessLedger, and Insights are buildings inside the campus.
- Each building trusts a valid pass but does not store passwords or perform MFA itself.
- A pass contains only the organization and permissions required for the current context.

## Desired Outcomes

1. Users can register and verify accounts safely.
2. Users can sign in with supported passwords, OTPs, social providers, and passkeys.
3. Risky activity triggers additional verification instead of silently granting access.
4. Web and mobile clients receive secure, platform-appropriate sessions from the same APIs.
5. Users can manage sessions, devices, organizations, and privacy requests.
6. Administrators can perform governed support actions with complete audit history.
7. Other Vittavaan services can validate access without knowing authentication internals.
8. The MVP can be demonstrated at minimal cost and later migrated to AWS without redesigning the domain.

## Primary Users

| User | Main needs |
|---|---|
| Visitor | Register, verify contact details, or sign in. |
| Customer | Access accounts, complete MFA, recover access, and manage sessions. |
| Organization administrator | Invite members, assign access, and offboard users. |
| Support agent | Assist users through controlled recovery processes. |
| Security supervisor | Approve sensitive actions and investigate audit events. |
| Platform service | Validate JWTs and enforce organization-scoped permissions. |
| Security or compliance reviewer | Trace actions and verify control behavior. |

## MVP Definition

The MVP is a demonstration environment implementing the complete documented capability set in phased milestones. It is intended for stakeholder and controlled tester evaluation, not for real financial activity.

The MVP includes:

- Responsive Vittavaan authentication and account-management website.
- FastAPI authentication service following Entity-Boundary-Control separation.
- PostgreSQL identity and audit store.
- Redis ephemeral state, rate limiting, OTP, and revocation data.
- Go JWT verification service for downstream zero-trust validation.
- Real sandbox integrations where free provider restrictions allow them.
- Automated tests, CI, deployment configuration, and operating documentation.

## Production Destination

The production target is AWS using containerized services, managed PostgreSQL and Redis, KMS-backed cryptography, managed messaging, edge protection, centralized monitoring, backups, and disaster recovery.

The application will use standard PostgreSQL, Redis, HTTP, OpenAPI, OIDC, and container interfaces so the free staging environment does not become a permanent architectural dependency.

## Explicit Boundaries

- The web application is the first client; it is not the owner of authentication rules.
- The future mobile application is planned but is not implemented in the initial web milestone.
- Business modules consume identity claims but remain outside this repository.
- Payment, investment, lending, and accounting features are outside `auth-core`.
- Production compliance certification, penetration testing, and legal review are required separately.

## Measures of Success

- Every use case has a documented API, control, data path, screen or external actor, and acceptance test.
- A reviewer can complete representative authentication and administration journeys from a public staging URL.
- Web and simulated mobile clients pass the same API contract tests.
- Cross-tenant access, token replay, privilege escalation, and audit tampering tests fail closed.
- The same containers and configuration model can be deployed to AWS with provider-adapter changes only.
