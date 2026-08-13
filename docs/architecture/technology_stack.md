# Technology Stack

## Selection Principles

- Use widely supported, portable standards.
- Prefer managed services for production operational risk.
- Keep domain code independent of a hosting vendor.
- Pin versions and commit lockfiles for reproducibility.
- Use mature security libraries rather than custom cryptography.

## Application Stack

| Area | MVP choice | Production choice | Rationale |
|---|---|---|---|
| Web | Next.js, React, TypeScript | Same on S3/CloudFront or Amplify | Responsive SSR/static options and shared TS contracts. |
| Mobile | Reserved Expo/React Native app | Expo/React Native | Reuses generated TypeScript API client and design tokens. |
| API | Python 3.12, FastAPI, Pydantic 2 | Same on ECS Fargate | Async orchestration, typed contracts, rapid secure iteration. |
| JWT verifier | Go 1.24 HTTP middleware/service | Same on ECS Fargate or embedded library | Efficient downstream signature and revocation validation. |
| ORM/migrations | SQLAlchemy 2, AsyncPG, Alembic | Same | Explicit async persistence and controlled schema evolution. |
| Database | PostgreSQL 15+ on Neon | RDS PostgreSQL or Aurora PostgreSQL | ACID, constraints, RLS, standard portability. |
| Ephemeral store | Redis 7-compatible Upstash | ElastiCache Redis | Atomic TTL workflows, rate limits, revocation. |
| Jobs | Transactional outbox worker | SQS/EventBridge + ECS worker | Reliable effects without losing committed work. |

## Security and Integration Libraries

| Capability | Planned approach |
|---|---|
| Passwords | `argon2-cffi` Argon2id with versioned parameters. |
| JWT/JWK | Maintained JOSE library with explicit algorithm allow-list; Go JWK verifier. |
| TOTP | Standards-based TOTP library; secrets envelope-encrypted. |
| Passkeys | Maintained WebAuthn/FIDO2 server library and platform APIs. |
| OIDC | Standards-based client with discovery, PKCE, state, and nonce validation. |
| Breach checks | HIBP Pwned Passwords k-anonymity range endpoint. |
| CAPTCHA | Cloudflare Turnstile. |
| Email | Resend in staging; Amazon SES in production. |
| SMS | Twilio trial in staging; SNS or approved provider in production. |
| Encryption | AES-256-GCM data encryption; AWS KMS envelope/key management in production. |

Exact package versions are selected and locked during the foundation milestone after compatibility and vulnerability review.

## Developer Toolchain

- Python dependency and environment management: `uv`.
- JavaScript workspace and lockfile: pnpm.
- Python quality: Ruff, mypy, pytest, coverage, Bandit, pip-audit.
- Web quality: ESLint, TypeScript, Vitest/Testing Library, Playwright.
- Go quality: formatter, test/race, vet, staticcheck, govulncheck.
- Security: Gitleaks, dependency review, Trivy, SBOM generation.
- Local orchestration: Docker Compose and Make targets.
- CI/CD: GitHub Actions with GitHub OIDC for AWS deployments.

## Observability

- Structured JSON logs with request/correlation IDs and automatic secret redaction.
- OpenTelemetry traces and metrics where supported.
- Security metrics for failures, lockouts, MFA, refresh replay, admin actions, and provider errors.
- MVP logs use platform facilities; AWS uses CloudWatch alarms, dashboards, and retention policies.

## Deferred Decisions

The following require load, compliance, or business evidence before selection: Aurora versus standard RDS PostgreSQL, SNS versus a dedicated messaging provider, exact risk-intelligence provider, production SLOs, multi-region topology, and SIEM integration.
