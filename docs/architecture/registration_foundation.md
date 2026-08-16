# Delivered Registration and Verification Foundation

## In Plain Language

The registration foundation lets a person start an account with either email and password or a mobile phone number. The same versioned API is intended for the website and the future mobile application, so security rules are not duplicated in each client.

This milestone implements the shared backend workflow. It does not replace or materially change the approved frontend wireframes.

## Email Registration

1. The client sends the person's name, email, password, and CAPTCHA proof.
2. The service normalizes the email and applies rate limits.
3. The password must contain 12 to 128 characters and is checked through the HIBP k-anonymity service.
4. Accepted passwords are hashed with Argon2id before PostgreSQL receives them.
5. The account remains pending while a random verification token is stored only as a SHA-256 hash.
6. Mailpit receives the local verification email. The single-use link expires after 15 minutes.
7. Consuming a valid link activates the user and verifies the password identity in one database transaction.

Public duplicate-email responses remain deliberately generic so an attacker cannot use signup to discover who has an account. A pending user may request a replacement verification link; issuing it consumes prior unused links.

## Phone Registration

1. The client sends an international E.164 phone number and CAPTCHA proof.
2. The service permits no more than three OTP requests per minute for the same phone number.
3. A cryptographically random six-digit OTP is stored in Redis only as a keyed HMAC hash for three minutes.
4. Local development simulates SMS delivery through Mailpit; production will use an approved SMS provider.
5. Three incorrect attempts consume the OTP. A correct, unexpired code activates the account and verifies the phone identity.

## Reusable Boundaries

- `RegistrationControl` owns the workflow and is independent of HTTP or a particular client.
- Provider ports isolate CAPTCHA, HIBP, email, SMS, hashing, Redis, and PostgreSQL.
- FastAPI exposes the same JSON contracts to Next.js and future Expo clients.
- Provider adapters can change between local, staging, and AWS production without changing registration rules.

## API Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/auth/signup` | Start email/password registration. |
| `POST` | `/api/v1/auth/verify/email` | Consume an email-verification link. |
| `POST` | `/api/v1/auth/verify/email/request` | Request a replacement verification email safely. |
| `POST` | `/api/v1/auth/signup/phone` | Start phone registration and issue an OTP. |
| `POST` | `/api/v1/auth/verify/phone/request` | Request another phone OTP safely. |
| `POST` | `/api/v1/auth/verify/phone/confirm` | Verify a phone OTP. |

## Local Demonstration

Use CAPTCHA token `local-development-pass` only in local development. Open Mailpit at `http://localhost:8025` to see email links and simulated SMS codes. Local defaults are not production credentials.

## Automated Evidence

- Unit tests cover clean and breached passwords, email verification, phone verification, and rate limiting.
- API tests prove safe acceptance messages and RFC 7807 problem responses.
- PostgreSQL/Redis tests prove Argon2id storage, hashed single-use email tokens, hashed expiring OTPs, and account activation.
- Migration tests prove an empty database upgrades through the registration constraint revision.

