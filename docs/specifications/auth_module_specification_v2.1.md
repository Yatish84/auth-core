# Software Requirements Specification (SRS)
## Module: Authentication & User Management Engine (`auth-core`)

**Version:** 2.1.0 (Production-Ready & Audit-Hardened Architecture)  
**Status:** Approved / Requirements Elicitation & Domain Modeling Phase  
**Architecture Style:** Modular Domain Engine / Reusable Library Component  
**Target Environment:** Web (Next.js) & Mobile (React Native / Expo)  

---

## 1. Executive Summary & Purpose

### 1.1 Purpose
The **Authentication & User Management Module (`auth-core`)** serves as the centralized identity provider, security gatekeeper, user session manager, and access control engine for the **Vittavaan** financial operating platform. 

Designed using **Object-Oriented Software Engineering (OOSE)** principles, `auth-core` is architected as an isolated, reusable domain library. It encapsulates all credential management, adaptive multi-factor verification, identity provider federation, token family issuance, multi-tenant organization scoping, role-based access control (RBAC), support-assisted account recovery governance, and GDPR/CCPA regulatory compliance. Core application services (such as *WealthOS*, *LoanDesk*, *BusinessLedger*, and *Insights*) consume `auth-core` via standardized interfaces without needing internal knowledge of underlying security mechanisms or third-party identity providers.

### 1.2 Key Objectives
* **Modular Versatility:** Function as an extensible authentication library capable of plugging into both Web and Mobile client applications seamlessly.
* **Pluggable Identity Architecture:** Support multiple authentication factors (Email/Password, Social SSO, Mobile Phone OTP, Hardware Passkeys/WebAuthn) with zero changes required to downstream business modules when adding future identity mechanisms.
* **Adaptive Risk-Based Security:** Enforce dynamic step-up multi-factor authentication (MFA) based on real-time risk assessment (IP anomalies, unrecognized device fingerprints, geographic displacement).
* **Hardened Support Governance (4-Eyes Principle):** Provide secure, audited administrative interfaces requiring dual-agent approval and mandatory delay windows for high-risk helpdesk actions (e.g., MFA resets) to prevent social engineering and SIM-swap account takeovers.
* **Bank-Grade Compliance & Zero-Trust:** Enforce mandatory MFA, immutable append-only audit logging, zero-trust token family rotation with concurrent session caps, strict password storage policies (Argon2id + HaveIBeenPwned k-anonymity checks), and fine-grained multi-module RBAC.

---

## 2. Technology Stack & Architectural Justification

| Component / Layer | Selected Technology | Functional Role & Rationale |
| :--- | :--- | :--- |
| **API Gateway & Core Auth Logic** | **Python (FastAPI)** | Manages high-level identity orchestration, OAuth2/OIDC token pipelines, password hashing, administrative support tools, GDPR workflows, and third-party integrations. Provides native async handling and rapid schema validation via Pydantic. |
| **High-Throughput Verification** | **Go (Golang)** | Intercepts high-frequency requests, validates incoming JWT signatures statelessly in memory (<1ms latency), checks real-time Redis revocation bloom filters, evaluates device fingerprint hashes, and enforces high-performance rate limiting. |
| **Relational Identity Store** | **PostgreSQL** | Stores core user records, role bindings, tenant mappings, identity linkage maps, and hashed tokens with strict ACID compliance and row-level security (RLS). |
| **Caching & Ephemeral State** | **Redis** | Manages ephemeral state, temporary OTP codes, failed login attempt counters, device fingerprint caches, JWT revocation blacklists, and rate-limiting counters. |
| **Secrets Management** | **AWS KMS / HashiCorp Vault** | Handles asymmetric key pairs (RS256/EdDSA) for JWT signing with automated 90-day key rotation and envelope encryption for stored TOTP secret keys. |
| **Web Frontend Integration** | **Next.js (TypeScript)** | Consumes `auth-core` APIs; handles session state using `httpOnly`, `Secure`, `SameSite=Lax` browser cookies with anti-CSRF tokens to prevent Cross-Site Scripting (XSS) and accommodate OAuth redirects. |
| **Mobile Integration** | **React Native / Expo** | Consumes `auth-core` APIs; securely persists tokens in device-level secure enclaves (iOS Keychain / Android Keystore). |

---

## 3. Actor Profiles & System Roles

In accordance with OOSE methodology, **Actors** represent external entities (human users or automated systems) that interact with the `auth-core` module boundary.

```
+-------------------------------------------------------------------------------+
|                                ACTOR MATRIX                                   |
+--------------------------+----------------------------------------------------+
| Actor Name               | Description & Responsibilities                     |
+--------------------------+----------------------------------------------------+
| Unauthenticated Visitor  | End-user accessing public routes; seeks to register|
|                          | an account or initiate primary login.              |
+--------------------------+----------------------------------------------------+
| Authenticated User       | User with valid credentials who must complete MFA   |
|                          | or already possesses active session tokens.        |
+--------------------------+----------------------------------------------------+
| Organization Admin       | Admin managing business tenant settings, member    |
|                          | onboarding, offboarding, and module permissions.   |
+--------------------------+----------------------------------------------------+
| Customer Support Agent   | Level 2 helpdesk staff member authorized to initiate|
|                          | identity verification and account unlocking.       |
+--------------------------+----------------------------------------------------+
| Security Supervisor      | Level 3 security officer required for 4-eyes dual  |
|                          | approval on high-risk operations (e.g., MFA reset).|
+--------------------------+----------------------------------------------------+
| System Administrator     | Elevated user capable of auditing logs, revoking   |
|                          | user sessions, or disabling compromised accounts.  |
+--------------------------+----------------------------------------------------+
| Identity Provider (IdP)  | Third-party OAuth2/OIDC providers (Google, Apple,  |
|                          | Microsoft) supplying identity assertions.          |
+--------------------------+----------------------------------------------------+
| Telephony Gateway        | SMS/Voice provider (e.g., Twilio) responsible for  |
|                          | delivering multi-factor codes and login OTPs.      |
+--------------------------+----------------------------------------------------+
| Risk Assessment Engine   | Internal background service evaluating device      |
|                          | fingerprints, IP reputation, and anomalous patterns|
+--------------------------+----------------------------------------------------+
| Security Auditor (System)| Automated background service monitoring audit logs |
|                          | and triggering security throttles/alerts.          |
+--------------------------+----------------------------------------------------+
```

---

## 4. Comprehensive Use Case Catalog

This catalog outlines all functional paths supported by the `auth-core` engine across primary authentication, adaptive secondary verification, registration, session management, tenancy, administrative governance, support escalation, and privacy regulations.

```
                                +-----------------------------------+
                                |     UC CATALOG OVERVIEW MAP       |
                                +-----------------------------------+
                                                  |
       +--------------------+---------------------+---------------------+--------------------+
       |                    |                     |                     |                    |
+------v-------+    +-------v------+      +-------v------+      +-------v------+     +-------v------+
| 4.1 Primary  |    | 4.2 Secondary|      | 4.3 Registr. |      | 4.4 Session  |     | 4.5 Recovery |
| Auth Flows   |    | Verification |      | & Onboarding |      | & Lifecycle  |     | & Governance |
+--------------+    +--------------+      +--------------+      +--------------+     +--------------+
                                                                                          |
                                                                                   +------v-------+
                                                                                   | 4.6 GDPR     |
                                                                                   | & Compliance |
                                                                                   +--------------+
```

### 4.1 Primary Authentication Flows
* **UC-101: Password Authenticate:** User supplies Email and Password. Engine checks k-anonymity breach list and verifies hash via Argon2id.
* **UC-102: Social SSO Authenticate:** User authenticates via Google, Apple, or Microsoft OAuth2/OIDC provider; engine verifies JWT payload and links or creates local identity (`UC-307`).
* **UC-103: Mobile Phone OTP Authenticate:** User requests login code via SMS (protected by CAPTCHA/SMS pumping rate limit); enters 6-digit code validated against hashed Redis temporary store.
* **UC-104: Passkey / Biometric Authenticate:** User completes WebAuthn / FIDO2 challenge using device hardware (TouchID/FaceID/YubiKey).
* **UC-105: Fallback Authentication Trigger:** System detects login failure or user selects alternative registered auth method when primary option is unavailable.
* **UC-106: Adaptive Risk Evaluation:** System evaluates IP location, device fingerprint, and login velocity upon primary authentication to determine if step-up challenge is required.

### 4.2 Secondary Verification & Mandatory MFA
* **UC-201: TOTP Authenticate:** User inputs 6-digit code from authenticator app (Google Authenticator, 1Password) validated against stored shared secret.
* **UC-202: SMS/Email Secondary OTP:** User requests backup 2FA code via SMS or Email if authenticator app is unavailable.
* **UC-203: Passkey Secondary Step-up:** User completes biometric challenge during elevated financial actions or high-risk logins.
* **UC-204: MFA Setup & Enrollment:** User generates secret key, scans QR code, or registers WebAuthn public key to activate factor.

### 4.3 Registration, Onboarding & Multi-Tenancy
* **UC-301: Self-Service Email Registration:** User submits profile details and password (protected by CAPTCHA); account is initialized in `PENDING_VERIFICATION` state with an `EmailVerificationToken`.
* **UC-302: Email Address Verification:** User clicks time-bound cryptographically signed link sent to email to activate account.
* **UC-303: Social SSO Auto-Provisioning:** System extracts verified profile details from SSO provider and auto-creates account with linked external identity (protected by CAPTCHA/bot-defense).
* **UC-304: Phone-Based Quick Registration:** User registers using phone number and SMS code, subsequently adding secondary details.
* **UC-305: Organization Creation & Member Invitation:** Admin creates an `Organization` (e.g., for *BusinessLedger*) and issues an `Invitation` token to team members with assigned module roles.
* **UC-306: Organization Context Switch:** Authenticated user with multiple `UserRoleBinding` records swaps active enterprise tenant scope without re-authenticating, issuing a new scoped JWT.
* **UC-307: Identity Link / Unlink & SSO Collision Resolution:** User links social provider or resolves collision between social SSO email and existing local account. Explicit rule: If an SSO email matches an existing local account, auto-linking is blocked until the user proves ownership by re-authenticating with their existing primary password/MFA credential. Prevents factor unlinking if only one factor remains.
* **UC-308: Organization Member Offboarding:** Organization Admin removes a member; system immediately revokes all assigned `UserRoleBinding` instances for that tenant and revokes all active tenant-scoped session tokens.

### 4.4 Session Management & Token Lifecycle
* **UC-401: Dual-Client Token Issue:** Issues short-lived Access JWT (15-min max lifetime) and long-lived Refresh Token bound to a `RefreshTokenFamily`. Enforces a maximum concurrent session cap (max 10 active families per user); oldest active session family is automatically revoked upon overflow.
* **UC-402: Token Refresh & Automatic Family Rotation:** Client presents valid refresh token and device fingerprint; engine verifies fingerprint, invalidates current refresh token, issues a new token pair in the family, and invalidates the entire family if token reuse is detected.
* **UC-403: Explicit Logout (Single Device):** Invalidates current session refresh token and pushes JWT ID (`jti`) to Redis revocation bloom filter.
* **UC-404: Global Logout (All Devices):** Revokes all active `RefreshTokenFamily` records for a user and pushes revocation timestamp to Redis.
* **UC-405: Idle & Absolute Session Timeout:** Automatically expires access tokens after 15 minutes of inactivity or 24 hours absolute age.

### 4.5 Account Recovery, Helpdesk & Governance
* **UC-501: Forgotten Password Request:** Generates secure, single-use `PasswordResetToken` sent via email without disclosing account existence (rate-limited to max 3 requests/hour per email).
* **UC-502: Password Reset Execution:** User validates reset token and submits new password meeting complexity criteria (enforcing password history policy).
* **UC-503: Account Lockout Release:** Admin or automated system unlocks account following excessive failed login attempts.
* **UC-504: Admin Account Suspend/Disable:** Administrator immediately revokes all active sessions and sets account status to `SUSPENDED`.
* **UC-505: Audit Trail Query:** Security auditors view immutable log entries for compliance and threat analysis.
* **UC-506: Role & Permission Assignment:** Assigns granular module permissions from `RolePermissionCatalog` to users.
* **UC-507: Support-Assisted Account Recovery:** Customer Support Agent performs out-of-band identity verification, unlocks user account, and issues a secure single-use recovery link.
* **UC-508: Admin MFA Reset (4-Eyes Governed):** L2 Support Agent initiates MFA reset; requires L3 Security Supervisor co-approval. Triggers 12-hour delayed execution window and sends out-of-band notification to user's original channels before resetting device.
* **UC-509: Self-Service Active Session Management:** User views all active logged-in devices (`TrustedDevice`, IP, Last Seen) and selectively revokes specific sessions.
* **UC-510: Primary Contact (Email/Phone) Change:** User updates email/phone; system requires dual-channel verification (code sent to both old and new channel) before applying change.

### 4.6 GDPR & Privacy Compliance
* **UC-601: GDPR Data Export (Right of Access):** User requests a machine-readable export (JSON) of all stored personal profile, session, and identity metadata.
* **UC-602: GDPR Account Erasure (Right to be Forgotten):** User requests account deletion; system anonymizes core identity data while retaining cryptographically hashed audit trails. Backup retention policy: Pre-anonymization backup data is isolated and purged automatically within 30 days via rolling snapshot expiration cycles.

---

## 5. Domain Object Models (Entity - Boundary - Control Classification)

In accordance with Object-Oriented Software Engineering (OOSE) analysis practices, system objects are categorized into three stereotypes: **Entity Objects**, **Boundary Objects**, and **Control Objects**.

```
      ┌────────────────┐                ┌────────────────┐                ┌────────────────┐
      │ Boundary Object│ ──────────────> │ Control Object │ ──────────────> │  Entity Object │
      └────────────────┘                └────────────────┘                └────────────────┘
     (User Interfaces &                  (Business Logic &               (Persistent Business
     System Interfaces)                    Orchestration)                  Concepts & Data)
```

---

### 5.1 Entity Objects («entity»)

#### 5.1.1 Object: `User`
Represents core user identities holding demographic profile data and account status.
* **Properties:**
  * `userID: UUID`
  * `email: String`
  * `firstName: String`
  * `lastName: String`
  * `phoneNumber: String` (Optional)
  * `accountState: Enum` (`PENDING_VERIFICATION`, `ACTIVE`, `SUSPENDED`, `LOCKED`, `ANONYMIZED_GDPR`)
  * `createdAt: Timestamp`
  * `updatedAt: Timestamp`
* **Methods:**
  * `createAccount()`: Initializes a new user entity.
  * `verifyEmail()`: Transitions account state to `ACTIVE`.
  * `suspendAccount(reason: String)`: Blocks access and revokes active sessions.
  * `unlockAccount(agentID: UUID, ticketRef: String)`: Releases account lock following support agent verification.
  * `updateContactDetails(newEmail: String, newPhone: String)`: Updates primary contact info following dual verification.
  * `anonymizeForGDPR()`: Replaces PII fields with irreversible cryptographic hashes.

#### 5.1.2 Object: `AuthenticationIdentity`
Encapsulates credentials linked to a `User`. A single user may own multiple identities.
* **Properties:**
  * `identityID: UUID`
  * `userID: UUID` (Foreign Key)
  * `providerType: Enum` (`PASSWORD`, `GOOGLE`, `APPLE`, `MICROSOFT`, `PHONE_OTP`)
  * `providerKey: String` (Argon2id password hash or external OAuth subject ID)
  * `passwordHistory: List<String>` (Hashed previous passwords to prevent reuse)
  * `isVerified: Boolean`
  * `lastUsedAt: Timestamp`
* **Methods:**
  * `verifyCredential(inputSecret: String): Boolean`: Validates password hash or OTP code.
  * `linkProvider(providerType: Enum, providerKey: String)`: Binds social account to user.
  * `unlinkProvider(providerType: Enum)`: Detaches social provider (enforcing last-factor guard).

#### 5.1.3 Object: `MFADevice`
Stores second-factor authentication devices and secrets required for mandatory MFA enforcement.
* **Properties:**
  * `mfaID: UUID`
  * `userID: UUID` (Foreign Key)
  * `mfaType: Enum` (`TOTP_APP`, `SMS_OTP`, `PASSKEY_WEBAUTHN`)
  * `secretKey: String` (Encrypted via AWS KMS / Vault envelope encryption)
  * `credentialID: String` (WebAuthn credential identifier; Nullable for TOTP)
  * `publicKey: String` (WebAuthn public key payload; Nullable for TOTP)
  * `signCounter: Integer` (WebAuthn signature counter for clone detection)
  * `transports: List<String>`
  * `isEnabled: Boolean`
  * `backupCodes: List<String>` (Hashed emergency recovery codes)
* **Methods:**
  * `generateTOTPSecret()`: Creates new TOTP secret key and QR code URL.
  * `registerPasskey(credentialID: String, publicKey: String)`: Stores FIDO2 WebAuthn public key bindings.
  * `validateCode(inputCode: String): Boolean`: Verifies TOTP or SMS code.
  * `verifyPasskeySignature(signature: String, clientDataJSON: String, authenticatorData: String): Boolean`: Validates WebAuthn assertion and updates `signCounter`.
  * `revokeDevice(agentID: UUID, reason: String)`: Deactivates factor following helpdesk recovery verification.

#### 5.1.4 Object: `RefreshTokenFamily`
Tracks long-lived refresh token rotation lineage to detect token reuse/theft attacks.
* **Properties:**
  * `familyID: UUID`
  * `userID: UUID` (Foreign Key)
  * `currentRefreshTokenHash: String`
  * `generation: Integer`
  * `isRevoked: Boolean`
  * `createdAt: Timestamp`
  * `expiresAt: Timestamp` (Max absolute lifetime: 30 days)
* **Methods:**
  * `rotateToken(incomingHash: String): TokenPair`: Generates new child token and increments generation.
  * `revokeFamily()`: Revokes all tokens in family upon detecting reuse of an older generation hash.

#### 5.1.5 Object: `AuthSession`
Tracks active logged-in session state, client context, and device bindings.
* **Properties:**
  * `sessionID: UUID`
  * `userID: UUID` (Foreign Key)
  * `familyID: UUID` (Foreign Key -> `RefreshTokenFamily`)
  * `clientType: Enum` (`WEB`, `MOBILE`)
  * `deviceFingerprintHash: String` (SHA-256 hash)
  * `ipAddress: String`
  * `userAgent: String`
  * `isRevoked: Boolean`
  * `expiresAt: Timestamp`
* **Methods:**
  * `issueTokens(): TokenPair`: Generates Access JWT and Refresh Token pair.
  * `revoke()`: Marks session as terminated and pushes `jti` to Redis.

#### 5.1.6 Object: `PasswordResetToken` & `EmailVerificationToken`
Ephemeral tokens for asynchronous account workflows.
* **Properties:**
  * `tokenID: UUID`
  * `userID: UUID` (Foreign Key)
  * `tokenHash: String` (SHA-256)
  * `tokenType: Enum` (`PASSWORD_RESET`, `EMAIL_VERIFICATION`, `CONTACT_CHANGE`)
  * `isConsumed: Boolean`
  * `expiresAt: Timestamp` (15-minute expiration)
* **Methods:**
  * `validateAndConsume(inputToken: String): Boolean`

#### 5.1.7 Object: `Organization` & `Invitation`
Multi-tenant business structures (*BusinessLedger*).
* **Properties:**
  * `orgID: UUID`, `orgName: String`, `taxIdentifier: String`, `subscriptionTier: String`
  * `invitationID: UUID`, `inviteEmail: String`, `role: String`, `invitationTokenHash: String`, `isAccepted: Boolean`
* **Methods:**
  * `createOrganization()`, `issueInvitation()`, `acceptInvitation()`

#### 5.1.8 Object: `TrustedDevice`
Tracks historical browser and hardware signatures for risk scoring.
* **Properties:**
  * `deviceID: UUID`, `userID: UUID`, `fingerprintHash: String`, `lastIpAddress: String`, `trustScore: Float`, `lastSeenAt: Timestamp`
* **Methods:**
  * `updateTrustMetrics(ip: String, fingerprint: String)`

#### 5.1.9 Object: `RolePermissionCatalog` & `UserRoleBinding`
Canonical RBAC permissions registry across Vittavaan modules.
* **Properties:**
  * `bindingID: UUID`, `userID: UUID`, `orgID: UUID` (Nullable), `module: Enum`, `role: String` (`OWNER`, `LOAN_UNDERWRITER`, `WEALTH_READ_ONLY`, `SUPPORT_AGENT_L2`, `SECURITY_SUPERVISOR_L3`)
* **Methods:**
  * `assignRole()`, `revokeRole()`

#### 5.1.10 Object: `GDPRRequest`
Tracks regulatory privacy requests.
* **Properties:**
  * `requestID: UUID`, `userID: UUID`, `requestType: Enum` (`EXPORT`, `ERASURE`), `status: Enum` (`PENDING`, `PROCESSING`, `COMPLETED`), `requestedAt: Timestamp`

#### 5.1.11 Object: `AuditLog`
An immutable security log capturing platform events.
* **Properties:**
  * `logID: UUID`, `userID: UUID` (Nullable), `actorID: UUID`, `eventType: String`, `ipAddress: String`, `metadata: JSON`, `timestamp: Timestamp`
* **Methods:**
  * `recordEvent(eventType: String, actorID: UUID, metadata: Object)`

---

### 5.2 Boundary Objects («boundary»)

#### 5.2.1 Object: `AuthRESTController`
Public API HTTP gateway for web and mobile clients.
* **Methods:** `handleSignUp()`, `handleLogin()`, `handleMFAVerification()`, `handleTokenRefresh()`, `handleLogout()`, `handleSwitchOrganization()`, `handleSelfRevokeSession()`, `handleInitiateGDPR()`

#### 5.2.2 Object: `AdminPortalRESTController`
Internal administrative gateway receiving privileged support requests.
* **Methods:** `handleSupportUnlockAccount()`, `handleInitiateSupportMFAReset()`, `handleApproveSupportMFAReset()`, `handleAdminSuspendUser()`, `handleOffboardOrgMember()`, `handleQueryAuditLogs()`

#### 5.2.3 Object: `JWKSRESTController`
Public key discovery boundary for downstream microservices.
* **Properties:** `routePrefix: String` (`/.well-known/jwks.json`), `rotationCadence: String` (`90 days`)
* **Methods:** `getPublicKeys(): JSON`

#### 5.2.4 Object: `WebCookieAdapter` & `MobileTokenAdapter`
* Handles `httpOnly`, `Secure`, `SameSite=Lax` cookies with anti-CSRF headers, and secure enclave formatting for mobile.

#### 5.2.5 External Integration Adapters
* `GoogleSSOAdapter`, `AppleSSOAdapter`, `SMSGatewayAdapter` (Twilio), `HaveIBeenPwnedAdapter` (k-anonymity breached password API).

---

### 5.3 Control Objects («control»)

#### 5.3.1 Object: `RegistrationControl`
Coordinates account onboarding, password breach checks via `HaveIBeenPwnedAdapter`, CAPTCHA verification, and emits `EmailVerificationToken`.

#### 5.3.2 Object: `LoginControl` & `RiskAssessmentControl`
Coordinates primary credentials, evaluates `TrustedDevice` history, determines risk rating, enforces concurrent session caps (max 10 active families), and enforces step-up MFA.

#### 5.3.3 Object: `TokenRefreshControl`
Coordinates token family extension, device fingerprint validation, and revokes the entire `RefreshTokenFamily` if reuse of an older generation token is detected.

#### 5.3.4 Object: `SupportAdminControl` (4-Eyes Governed)
* **`initiateSupportMFAReset(agentID: UUID, targetUserID: UUID, ticketRef: String)`**: Creates pending reset request and notifies user out-of-band.
* **`approveSupportMFAReset(supervisorID: UUID, requestID: UUID)`**: Enforces dual approval from `SECURITY_SUPERVISOR_L3`, checks 12-hour cooldown delay, revokes `MFADevice`, terminates active sessions, and logs audit event.

#### 5.3.5 Object: `OrganizationControl`
Manages multi-tenant organization creation, invitation acceptance, member offboarding (`UC-308`), and issues tenant-scoped JWTs during `UC-306 (Organization Context Switch)`.

#### 5.3.6 Object: `GDPRComplianceControl`
Executes data export compilation (`UC-601`) and data anonymization (`UC-602`), enforcing the 30-day backup snapshot purging rule.

#### 5.3.7 Object: `AuditQueryControl` & `RoleAssignmentControl`
Backs administrative auditing (`UC-505`) and role assignments (`UC-506`).

---

## 6. Security, Compliance & Non-Functional Requirements

1. **Zero Password Exposure & Breach Checks:** Passwords must be hashed using **Argon2id**. All new passwords must pass a k-anonymity API lookup (`HaveIBeenPwnedAdapter`) to reject known breached passwords.
2. **Stateless JWT Validation with Real-Time Revocation:** Go validates JWT signatures statelessly in <1ms. To support immediate session revocation (`UC-403`, `UC-404`), Go checks a Redis Bloom Filter containing revoked `jti` identifiers and global user revocation timestamps. Public keys are served via `JWKSRESTController` with an automated 90-day key rotation cycle.
3. **Dual-Agent Governance (4-Eyes Principle):** MFA resets (`UC-508`) require approval from two distinct staff members (`SUPPORT_AGENT_L2` and `SECURITY_SUPERVISOR_L3`), enforce a 12-hour delayed execution window, and dispatch mandatory alerts to the user's registered contact channels.
4. **Rate Limiting & Anti-Fraud Throttling:**
   * Login endpoints: Max 5 failed attempts/min per IP/email.
   * OTP SMS endpoints: Max 3 requests/min per phone number; CAPTCHA required on registration (`UC-301`), SSO provisioning (`UC-303`), and OTP endpoints to prevent SMS pumping fraud.
   * TOTP verification: Max 3 failed attempts before 15-minute lock on factor.
   * Password Reset Requests (`UC-501`): Max 3 requests/hour per email to prevent spamming.
5. **Session & Cookie Security:** Web sessions use `httpOnly`, `Secure`, `SameSite=Lax` cookies with double-submit anti-CSRF tokens. Token max access lifetime = 15 mins; max refresh family lifetime = 30 days. Maximum concurrent active sessions per user = 10 (oldest session family revoked on overflow).
6. **Immutable Audit Storage:** `AuditLog` entries must be written to an append-only, Write-Once-Read-Many (WORM) storage target or database role without `UPDATE` or `DELETE` grants.

---

## 7. Standardization & Phase 2 DTO Schemas

### 7.1 JWT Claim Structure
Access JWTs issued by `auth-core` contain the following standard claims:
```json
{
  "iss": "https://auth.vittavaan.com",
  "sub": "usr_9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "aud": "vittavaan-platform",
  "jti": "jwt_8f3a1b02-4c5d-6e7f-8a9b-0c1d2e3f4a5b",
  "iat": 1785734400,
  "exp": 1785735300,
  "client_type": "WEB",
  "active_org_id": "org_11223344-5566-7788-9900-aabbccddeeff",
  "roles": {
    "WEALTH_OS": "WEALTH_READ_ONLY",
    "LOAN_DESK": "LOAN_UNDERWRITER",
    "BUSINESS_LEDGER": "LEDGER_ACCOUNTANT"
  }
}
```

### 7.2 Standardized API Error DTO (RFC 7807)
All API boundary endpoints return errors adhering to RFC 7807 Problem Details:
```json
{
  "type": "https://auth.vittavaan.com/errors/mfa-step-up-required",
  "title": "Step-Up Authentication Required",
  "status": 403,
  "detail": "Login attempt detected from unrecognized device. Secondary MFA challenge required.",
  "instance": "/api/v1/auth/login",
  "code": "AUTH_MFA_STEP_UP_REQUIRED",
  "mfa_challenge_token": "mfa_tok_7a8b9c1d2e3f4a5b6c"
}
```

---

## 8. Next Architectural Phase

With **Phase 1: Requirements Elicitation & Domain Modeling (EBC)** updated to version 2.1.0, the project advances to **Phase 2: Object-Oriented Design (OOD)**. Phase 2 will define:
* System sequence diagrams for primary, adaptive risk, token family rotation, and 4-eyes support recovery pipelines.
* Complete OpenAPI 3.0 specification schemas for REST boundaries (`AuthRESTController`, `AdminPortalRESTController`, `JWKSRESTController`).
* Relational database DDL scripts (PostgreSQL tables, indexes, and RLS policies).
