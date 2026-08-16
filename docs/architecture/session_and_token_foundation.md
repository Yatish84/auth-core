# Delivered Session and Token Foundation

## Plain-Language Summary

A successful login now creates a controlled permission slip called a `session_ready` workflow. The workflow can be exchanged exactly once for a signed-in session. This prevents an old login or MFA result from being reused later.

The session returns two different credentials:

- The **access token** is a signed, short-lived pass used for normal API calls. It expires within 15 minutes.
- The **refresh token** is a high-entropy, single-use credential used to obtain the next access token. The database stores only its keyed hash, never the original value.

## Web and Mobile Reuse

Both clients call the same session services and receive the same access-token claims.

| Client | Refresh-token delivery | Protection |
|---|---|---|
| Web | `Secure`, `HttpOnly`, `SameSite=Lax` cookie | JavaScript cannot read it; refresh also requires a matching CSRF header and cookie. |
| Mobile | JSON response | The future app must immediately place it in iOS Keychain or Android Keystore. |

Access tokens are returned to the client but must not be stored in browser local storage.

## Refresh Rotation and Theft Detection

Every successful refresh performs one locked PostgreSQL transaction:

1. Find and lock the presented refresh token, family, and session.
2. Confirm the client type, device fingerprint hash, idle time, and absolute lifetime.
3. Mark the presented token used and revoked.
4. Store only the keyed hash of a new random refresh token.
5. Replace the session's access-token identifier.

If an already-used refresh token appears again, the complete family is revoked, Redis blocks the active access token immediately, an audit alert is written, and the user must sign in again.

## Revocation and Limits

- Current-device logout revokes its family and active access-token identifier.
- Global logout revokes every family and stores a user-wide revocation timestamp.
- A user can inspect safe session metadata and revoke an owned session.
- A maximum of 10 active sessions is enforced; the oldest is revoked when an eleventh is created.
- Access tokens expire in 15 minutes, inactive sessions cannot refresh after 15 minutes, sessions have a 24-hour absolute limit, and refresh families cannot exceed 30 days.

## Signing and Verification

The FastAPI service signs access tokens with RS256 and publishes only the public key at `/.well-known/jwks.json`. The Go verifier caches those public keys, validates signature, issuer, audience, required claims, and expiry, then checks Redis for access-token, family, and user-wide revocation.

Local development generates an in-memory RSA key. Production configuration explicitly rejects this adapter; AWS production will use managed asymmetric keys and rotation.

## Delivered API Boundaries

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/auth/session` | Consume one session-ready workflow and create a session. |
| `POST /api/v1/auth/refresh` | Rotate the refresh token and return a new token pair. |
| `POST /api/v1/auth/logout` | End the current session. |
| `POST /api/v1/auth/logout-all` | End every session for the user. |
| `GET /api/v1/auth/sessions` | List safe active-session metadata. |
| `DELETE /api/v1/auth/sessions/{session_id}` | Revoke one owned session. |
| `GET /.well-known/jwks.json` | Publish public verification keys. |
| `GET :8081/verify` | Validate an access token through the Go gateway. |

## Security Boundaries Retained for Production

- Production signing must use AWS KMS or an equivalent managed asymmetric-key provider.
- Device fingerprints remain bounded risk signals and never prove identity alone.
- Redis revocation is fail-closed: an unavailable revocation check rejects protected access.
- No private signing key, plaintext refresh token, or complete device fingerprint is returned by session-list APIs.

## Validation Evidence

Automated tests cover public-key signing, invalid signatures, browser/mobile delivery, CSRF rejection, real PostgreSQL token rotation, token reuse family revocation, Redis denial, and Go signature/revocation verification.
