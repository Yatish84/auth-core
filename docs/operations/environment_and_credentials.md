# Environment, Tools, and Credentials

## Local Tools

| Tool | Required purpose | Current audit |
|---|---|---|
| Git | Source control | Installed |
| Node.js 22 LTS | Next.js and generated clients | Node 20.10 currently installed; upgrade required |
| Corepack + pnpm | JavaScript workspace | Corepack installed; pnpm activation required |
| Python 3.12 | FastAPI target runtime | System Python differs; `uv` will provision pinned runtime |
| `uv` | Python dependencies and lockfile | Installation required |
| Go 1.24 | JWT verifier | Installation required |
| Docker Desktop | Local PostgreSQL, Redis, and services | Installation required |
| Make | Consistent developer commands | Installed |
| OpenSSL | Local development key generation | Installed |
| GitHub CLI | Branch/PR and Actions inspection | Installation required |
| `psql`, `redis-cli` | Optional troubleshooting | Optional when using containers |

## Configuration Categories

The implementation will supply `.env.example` with names and descriptions but no credentials.

### Application

- `APP_ENV`, `APP_BASE_URL`, `API_BASE_URL`
- `LOG_LEVEL`, `CORS_ALLOWED_ORIGINS`, `TRUSTED_HOSTS`
- `COOKIE_DOMAIN`, `COOKIE_SECURE`, `CSRF_SECRET`
- `ACCESS_TOKEN_TTL_SECONDS`, `REFRESH_TOKEN_TTL_SECONDS`, session limits

### Data

- `DATABASE_URL`, connection pool limits, migration URL/role
- `REDIS_URL` or TLS host/user/password fields

### Cryptography

- `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_ACTIVE_KID`
- Development signing key paths or encoded test keys
- `DATA_ENCRYPTION_KEY` only for non-production local/staging provider
- Production AWS KMS key aliases/ARNs

### Providers

- Resend API key, sender address, verified domain
- Twilio account/API credentials, sender number, verified test recipients
- Google/Apple/Microsoft OIDC client IDs/secrets and redirect URIs
- Cloudflare Turnstile site/secret keys
- Optional risk-intelligence provider key
- HIBP Pwned Passwords needs no API key but requires an identifying user agent

### AWS Production

- AWS account and region, deployment role ARN, ECR repositories
- RDS/ElastiCache endpoints through Secrets Manager
- KMS key ARNs, SES identities, SNS configuration
- Route 53 hosted zone, ACM certificates, WAF policy, alert destinations

## Credential Actions Requested From the Owner

Credentials are requested only when their milestone begins. The owner enters secrets directly into approved provider/GitHub/AWS stores; credentials must not be pasted into chat, issues, commits, screenshots, or documentation.

For staging, expected account setup is:

1. Connect GitHub to Render.
2. Create a Neon PostgreSQL project and Upstash Redis database.
3. Verify an email domain in Resend.
4. Create Turnstile widget keys for local and staging hostnames.
5. Configure Google OAuth consent and callbacks.
6. Configure Twilio trial recipients if SMS demonstration is required.
7. Add Apple/Microsoft credentials only when those integrations are ready.

## Secret Management Rules

- `.env`, key files, provider exports, and Terraform state are ignored.
- CI uses GitHub environments with least-privilege secrets and approvals.
- Production workloads use IAM roles and Secrets Manager, not static AWS keys.
- Secrets are rotated after suspected exposure, staff changes, and defined maximum age.
- Logs and problem responses are automatically redacted.
