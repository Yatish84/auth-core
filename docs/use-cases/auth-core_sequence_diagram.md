# System Sequence Diagrams Specification (`auth-core`)

**Module:** Authentication & User Management Engine (`auth-core`)  
**Version:** 2.1.0  
**Architecture Style:** Object-Oriented Software Engineering (OOSE) - Entity-Boundary-Control (EBC) Pattern  
**Target Environment:** Web (Next.js) & Mobile (React Native / Expo)  

---

## 1. Overview & Architectural Coverage

This document contains the complete dynamic interaction models for the `auth-core` module. In accordance with Object-Oriented Software Engineering (OOSE) principles, sequence diagrams capture the dynamic message exchanges between **Boundary Objects («boundary»)**, **Control Objects («control»)**, and **Entity Objects («entity»)** across time.

To maintain a clean, maintainable architecture, sequence diagrams are organized by **Primary Collaboration Patterns**. Each pattern models a core workflow or high-risk exception loop. Every use case defined in the primary specification (`auth_module_specification_v2.1.md`) maps directly to one of these 8 sequence diagram patterns.

### Architectural Use Case Coverage Matrix

| Sequence Diagram Pattern | Primary Use Case Modeled | Covered Equivalent / Derived Use Cases |
| :--- | :--- | :--- |
| **1. Adaptive Risk Login + Step-Up MFA** | `UC-101` (Password Authenticate)<br>`UC-106` (Adaptive Risk)<br>`UC-201` (TOTP Authenticate) | `UC-103` (Mobile Phone OTP Authenticate)<br>`UC-104` (Passkey / Biometric Authenticate)<br>`UC-202` (SMS/Email Secondary OTP)<br>`UC-203` (Passkey Secondary Step-up)<br>`UC-204` (MFA Setup & Enrollment) |
| **2. Token Family Rotation & Reuse Detection** | `UC-402` (Token Refresh & Rotation) | `UC-401` (Dual-Client Token Issue)<br>`UC-403` (Explicit Single Device Logout)<br>`UC-404` (Global Multi-Device Logout)<br>`UC-405` (Idle & Absolute Session Timeout) |
| **3. 4-Eyes Governed Admin MFA Reset** | `UC-508` (Admin MFA Reset - 4-Eyes) | `UC-503` (Account Lockout Release)<br>`UC-504` (Admin Account Suspend/Disable)<br>`UC-507` (Support-Assisted Account Recovery) |
| **4. Self-Service Registration & Breach Check** | `UC-301` (Self-Service Email Reg)<br>`UC-302` (Email Address Verification) | `UC-304` (Phone-Based Quick Registration)<br>`UC-501` (Forgotten Password Request)<br>`UC-502` (Password Reset Execution) |
| **5. SSO Login & Account Collision Prevention** | `UC-102` (Social SSO Authenticate)<br>`UC-303` (SSO Auto-Provisioning)<br>`UC-307` (SSO Collision Resolution) | All third-party OIDC/OAuth provider integrations (Google, Apple, Microsoft) & social provider identity linking/unlinking |
| **6. Multi-Tenant Context Switching** | `UC-306` (Organization Context Switch) | `UC-305` (Organization Creation & Member Invite)<br>`UC-506` (Role & Permission Assignment)<br>`UC-509` (Self-Service Active Session Management) |
| **7. Organization Member Offboarding** | `UC-308` (Org Member Offboarding) | Admin-driven workspace access revocation, role binding deletion, and real-time tenant session termination |
| **8. GDPR Account Erasure & Anonymization** | `UC-602` (GDPR Account Erasure) | `UC-601` (GDPR Data Export / Right of Access) |

---

## 2. Mermaid Sequence Diagrams

---

### Sequence Diagram 1: Adaptive Risk-Based Login + Mandatory MFA (`UC-101`, `UC-106`, `UC-201`)

```mermaid
sequenceDiagram
    autonumber
    actor Visitor as Unauthenticated Visitor
    participant Boundary as AuthRESTController
    participant LoginCtrl as LoginControl
    participant RiskCtrl as RiskAssessmentControl
    participant AuthIdent as AuthenticationIdentity
    participant Device as TrustedDevice
    participant MFACtrl as MFAVerificationControl
    participant MFADev as MFADevice
    participant Session as AuthSession
    participant Audit as AuditLog

    Visitor->>Boundary: POST /api/v1/auth/login (email, password, fingerprint)
    Boundary->>LoginCtrl: authenticateUser(credentials)
    LoginCtrl->>AuthIdent: verifyCredential(password)
    AuthIdent-->>LoginCtrl: True (Argon2id Valid)
    
    LoginCtrl->>RiskCtrl: evaluateRisk(ip, fingerprint)
    RiskCtrl->>Device: checkDeviceTrust(fingerprint)
    Device-->>RiskCtrl: Unrecognized Device (Score < 0.5)
    RiskCtrl-->>LoginCtrl: Risk Level: HIGH
    
    LoginCtrl->>MFACtrl: issueMFAChallengeToken(userID)
    MFACtrl-->>LoginCtrl: mfa_challenge_token (5-min exp)
    LoginCtrl-->>Boundary: Exception: AUTH_MFA_STEP_UP_REQUIRED
    Boundary-->>Visitor: HTTP 403 Forbidden (RFC 7807 + mfa_challenge_token)

    Visitor->>Boundary: POST /api/v1/auth/mfa/verify (mfa_challenge_token, code)
    Boundary->>MFACtrl: verifyMFACode(token, code)
    MFACtrl->>MFADev: validateCode(code)
    MFADev-->>MFACtrl: True
    
    MFACtrl->>Session: issueTokens(userID)
    Note over Session: Enforces Max Concurrent Session Cap (<= 10)
    Session-->>MFACtrl: TokenPair (Access JWT + Refresh Token)
    
    MFACtrl->>Audit: recordEvent("AUTH_LOGIN_SUCCESS")
    MFACtrl-->>Boundary: TokenPair
    Boundary-->>Visitor: HTTP 200 OK (httpOnly Cookie or Mobile JSON)
```

---

### Sequence Diagram 2: Token Family Rotation & Reuse Theft Detection (`UC-402`)

```mermaid
sequenceDiagram
    autonumber
    actor Client as Client App (Web / Mobile)
    participant Boundary as AuthRESTController
    participant RefreshCtrl as TokenRefreshControl
    participant Family as RefreshTokenFamily
    participant Redis as RedisRevocationFilter
    participant Audit as AuditLog

    Client->>Boundary: POST /api/v1/auth/refresh (RefreshToken + Fingerprint)
    Boundary->>RefreshCtrl: processTokenRefresh(token, fingerprint)
    RefreshCtrl->>Family: rotateToken(incomingHash)
    
    alt Legitimate Token Rotation (Current Generation Match)
        Family-->>RefreshCtrl: Returns New TokenPair & Increments Generation
        RefreshCtrl-->>Boundary: New TokenPair
        Boundary-->>Client: HTTP 200 OK (New Access JWT + Rotated Refresh Token)
    else Reuse / Theft Attack Detected (Older Generation Token Presented)
        Family-->>RefreshCtrl: Exception: REUSE_DETECTED
        RefreshCtrl->>Family: revokeFamily()
        RefreshCtrl->>Redis: pushToRevocationFilter(familyID)
        RefreshCtrl->>Audit: recordEvent("AUTH_TOKEN_REUSE_THEFT_ALERT")
        RefreshCtrl-->>Boundary: Exception: AUTH_TOKEN_STOLEN
        Boundary-->>Client: HTTP 401 Unauthorized ("Invalid or Stolen Token Family")
    end
```

---

### Sequence Diagram 3: 4-Eyes Governed Admin MFA Reset (`UC-508`)

```mermaid
sequenceDiagram
    autonumber
    actor L2Agent as Customer Support L2
    actor L3Supervisor as Security Supervisor L3
    participant AdminBoundary as AdminPortalRESTController
    participant AdminCtrl as SupportAdminControl
    participant MFADev as MFADevice
    participant Session as AuthSession
    participant SMS as SMSGatewayAdapter
    participant Audit as AuditLog

    L2Agent->>AdminBoundary: POST /api/v1/admin/mfa-reset/initiate (targetUserID, ticketRef)
    AdminBoundary->>AdminCtrl: initiateSupportReset(agentID, targetUserID, ticketRef)
    AdminCtrl->>SMS: sendSMSCode(userPhone, "MFA Reset Requested by Support")
    AdminCtrl-->>AdminBoundary: Request Created (Status: PENDING_APPROVAL)
    AdminBoundary-->>L2Agent: HTTP 202 Accepted (Pending L3 Approval)

    L3Supervisor->>AdminBoundary: POST /api/v1/admin/mfa-resets/{id}/approve
    AdminBoundary->>AdminCtrl: approveSupportReset(supervisorID, requestID)
    AdminCtrl->>Audit: recordEvent("ADMIN_MFA_RESET_APPROVED")
    AdminCtrl-->>AdminBoundary: Approved; execution remains delayed
    Note over AdminCtrl: Mandatory 12-hour protection delay elapses
    L3Supervisor->>AdminBoundary: POST /api/v1/admin/mfa-resets/{id}/execute
    AdminBoundary->>AdminCtrl: executeSupportReset(supervisorID, requestID)
    Note over AdminCtrl: Revalidate roles, distinct actors, target version, state, and delay
    AdminCtrl->>MFADev: revokeDevice(targetUserID)
    AdminCtrl->>Session: revokeAllSessions(targetUserID)
    AdminCtrl->>Audit: recordEvent("ADMIN_MFA_RESET_EXECUTED")
    AdminCtrl-->>AdminBoundary: Reset Complete
    AdminBoundary-->>L3Supervisor: HTTP 200 OK (MFA Reset Finalized)
```

---

### Sequence Diagram 4: Self-Service Registration & k-Anonymity Breach Check (`UC-301`, `UC-302`)

```mermaid
sequenceDiagram
    autonumber
    actor Visitor as Unauthenticated Visitor
    participant Boundary as AuthRESTController
    participant RegCtrl as RegistrationControl
    participant HIBP as HaveIBeenPwnedAdapter
    participant User as User Entity
    participant AuthIdent as AuthenticationIdentity
    participant Token as EmailVerificationToken
    participant Audit as AuditLog

    Visitor->>Boundary: POST /api/v1/auth/signup (email, password, profile)
    Boundary->>RegCtrl: executeRegistration(dto)
    RegCtrl->>HIBP: checkPasswordBreach(5-char SHA1 prefix)
    HIBP-->>RegCtrl: Return Match Count

    alt Password Found in Data Breach (Count > 0)
        RegCtrl-->>Boundary: Exception: AUTH_PASSWORD_BREACHED
        Boundary-->>Visitor: HTTP 400 Bad Request ("Password found in public data breach")
    else Password Clean (Count == 0)
        RegCtrl->>User: createAccount(email, profile)
        User-->>RegCtrl: userID (Status: PENDING_VERIFICATION)
        RegCtrl->>AuthIdent: createIdentity(userID, Argon2id Hash)
        RegCtrl->>Token: generateToken(userID)
        Token-->>RegCtrl: verificationToken
        Note over RegCtrl: Dispatches Email with Signed Verification Link
        RegCtrl->>Audit: recordEvent("USER_REGISTERED_SUCCESS")
        RegCtrl-->>Boundary: Success
        Boundary-->>Visitor: HTTP 201 Created ("Verification email dispatched")
    end
```

---

### Sequence Diagram 5: Social SSO Login, Auto-Provisioning & Account Collision Prevention (`UC-102`, `UC-303`, `UC-307`)

```mermaid
sequenceDiagram
    autonumber
    actor Visitor as Unauthenticated Visitor
    participant Boundary as AuthRESTController
    participant LoginCtrl as LoginControl
    participant SSOAdapter as GoogleSSOAdapter
    participant AuthIdent as AuthenticationIdentity
    participant User as User Entity
    participant Session as AuthSession
    participant Audit as AuditLog

    Visitor->>Boundary: POST /api/v1/auth/sso/google (id_token)
    Boundary->>LoginCtrl: authenticateSSO(id_token)
    LoginCtrl->>SSOAdapter: verifyIDToken(id_token)
    SSOAdapter-->>LoginCtrl: Claims (email, google_sub)

    LoginCtrl->>AuthIdent: findByIdentityKey(google_sub)

    alt Existing SSO Identity Linked
        AuthIdent-->>LoginCtrl: Identity Found
        LoginCtrl->>Session: issueTokens(userID)
        Session-->>LoginCtrl: TokenPair
        LoginCtrl-->>Boundary: TokenPair
        Boundary-->>Visitor: HTTP 200 OK + Session Tokens
    else No SSO Link, Local Account Exists with Same Email (UC-307 Collision)
        AuthIdent-->>LoginCtrl: Null
        LoginCtrl->>User: findByEmail(email)
        User-->>LoginCtrl: User Found (Local Password Identity Active)
        LoginCtrl-->>Boundary: Exception: AUTH_SSO_COLLISION
        Boundary-->>Visitor: HTTP 409 Conflict ("Account exists. Re-authenticate with password to link SSO")
    else Completely New User (UC-303 Auto-Provisioning)
        AuthIdent-->>LoginCtrl: Null
        LoginCtrl->>User: findByEmail(email)
        User-->>LoginCtrl: Null
        LoginCtrl->>User: createAccount(email, profile)
        LoginCtrl->>AuthIdent: linkProvider(userID, GOOGLE, google_sub)
        LoginCtrl->>Session: issueTokens(userID)
        LoginCtrl->>Audit: recordEvent("SSO_AUTO_PROVISION_SUCCESS")
        LoginCtrl-->>Boundary: TokenPair
        Boundary-->>Visitor: HTTP 201 Created + Session Tokens
    end
```

---

### Sequence Diagram 6: Multi-Tenant Organization Context Switching (`UC-306`)

```mermaid
sequenceDiagram
    autonumber
    actor User as Authenticated User
    participant Boundary as AuthRESTController
    participant OrgCtrl as OrganizationControl
    participant RBAC as UserRoleBinding
    participant Session as AuthSession
    participant Audit as AuditLog

    User->>Boundary: POST /api/v1/auth/org/switch (targetOrgID)
    Note over Boundary: Request authenticated via current Access JWT
    Boundary->>OrgCtrl: switchContext(userID, targetOrgID)
    OrgCtrl->>RBAC: verifyUserRoleInOrg(userID, targetOrgID)

    alt User is NOT a Member of Target Org
        RBAC-->>OrgCtrl: Null / Empty Roles
        OrgCtrl-->>Boundary: Exception: ORG_ACCESS_DENIED
        Boundary-->>User: HTTP 403 Forbidden ("User is not a member of target organization")
    else User is a Valid Member of Target Org
        RBAC-->>OrgCtrl: Role Claims (e.g., BUSINESS_LEDGER: LEDGER_ACCOUNTANT)
        OrgCtrl->>Session: issueScopedJWT(userID, targetOrgID, roleClaims)
        Session-->>OrgCtrl: New Scoped Access JWT
        OrgCtrl->>Audit: recordEvent("ORG_CONTEXT_SWITCH_SUCCESS")
        OrgCtrl-->>Boundary: New Access JWT
        Boundary-->>User: HTTP 200 OK (New Scoped Access JWT)
    end
```

---

### Sequence Diagram 7: Organization Member Offboarding (`UC-308`)

```mermaid
sequenceDiagram
    autonumber
    actor OrgAdmin as Organization Admin
    participant AdminBoundary as AdminPortalRESTController
    participant OrgCtrl as OrganizationControl
    participant RBAC as UserRoleBinding
    participant Session as AuthSession
    participant Redis as RedisRevocationFilter
    participant Audit as AuditLog

    OrgAdmin->>AdminBoundary: DELETE /api/v1/admin/org/members/{userID}
    AdminBoundary->>OrgCtrl: offboardMember(adminID, targetUserID, orgID)
    OrgCtrl->>RBAC: verifyAdminRights(adminID, orgID)
    RBAC-->>OrgCtrl: True (Role: OWNER / ADMIN)

    OrgCtrl->>RBAC: deleteRoleBindings(targetUserID, orgID)
    OrgCtrl->>Session: revokeOrgSessions(targetUserID, orgID)
    OrgCtrl->>Redis: pushOrgRevocationTimestamp(targetUserID, orgID)
    OrgCtrl->>Audit: recordEvent("ORG_MEMBER_OFFBOARDED")
    
    OrgCtrl-->>AdminBoundary: Offboard Success
    AdminBoundary-->>OrgAdmin: HTTP 204 No Content
```

---

### Sequence Diagram 8: GDPR Account Erasure / Right to be Forgotten (`UC-602`)

```mermaid
sequenceDiagram
    autonumber
    actor User as Authenticated User
    participant Boundary as AuthRESTController
    participant GDPRCtrl as GDPRComplianceControl
    participant UserEntity as User Entity
    participant Session as AuthSession
    participant Backup as BackupScheduler
    participant Audit as AuditLog

    User->>Boundary: POST /api/v1/auth/gdpr/delete (confirmationPassword)
    Boundary->>GDPRCtrl: executeGDPRErasure(userID, confirmationPassword)
    Note over GDPRCtrl: Verifies primary user password before destructive deletion
    
    GDPRCtrl->>UserEntity: anonymizeForGDPR(userID)
    Note over UserEntity: Replaces PII (name, email, phone) with SHA-256 Hashes
    UserEntity-->>GDPRCtrl: Anonymized
    
    GDPRCtrl->>Session: terminateAllSessions(userID)
    GDPRCtrl->>Backup: schedule30DayBackupPurge(userID)
    GDPRCtrl->>Audit: recordAnonymizedEvent("GDPR_ACCOUNT_ERASED")
    
    GDPRCtrl-->>Boundary: Erasure Executed
    Boundary-->>User: HTTP 200 OK ("Account PII anonymized - backups purge in 30 days")
```

---

### Sequence Diagram 9: Password Recovery and Session Revocation (`UC-501`, `UC-502`)

```mermaid
sequenceDiagram
    actor User
    participant Web as Web/Mobile Client
    participant API as AuthRESTController
    participant Recovery as RecoveryControl
    participant DB as PostgreSQL
    participant Notify as NotificationAdapter
    participant Redis as Redis Revocation

    User->>Web: Submit email
    Web->>API: POST /auth/password/forgot
    API->>Recovery: requestPasswordReset(email)
    Recovery->>DB: Conditionally create hashed single-use token
    Recovery-->>Notify: Dispatch reset link when eligible
    API-->>Web: Generic 202 Accepted
    User->>Web: Open link and submit new password
    Web->>API: POST /auth/password/reset
    API->>Recovery: resetPassword(token, password)
    Recovery->>DB: Atomically consume token, check history, update Argon2id hash
    Recovery->>DB: Revoke all token families and sessions
    Recovery->>Redis: Set global user revocation timestamp
    Recovery-->>Notify: Send password-changed alert
    API-->>Web: 200 Password updated
```

### Sequence Diagram 10: MFA Enrollment (`UC-204`)

```mermaid
sequenceDiagram
    actor User
    participant Client
    participant API as AuthRESTController
    participant MFA as MFAControl
    participant Cipher as SecretCipher
    participant DB as PostgreSQL

    User->>Client: Choose TOTP enrollment
    Client->>API: POST /auth/mfa/totp/setup
    API->>MFA: setupTOTP(user, recentAuth)
    MFA->>Cipher: Encrypt generated secret
    MFA->>DB: Store disabled pending factor
    API-->>Client: QR payload + short-lived setup token
    User->>Client: Enter first authenticator code
    Client->>API: POST /auth/mfa/totp/confirm
    API->>MFA: confirmTOTP(setupToken, code)
    MFA->>DB: Lock pending factor and validate code
    MFA->>DB: Enable factor and store hashed backup codes
    API-->>Client: Enabled + one-time backup codes
```

### Sequence Diagram 11: Session Inspection and Selective Revocation (`UC-509`)

```mermaid
sequenceDiagram
    actor User
    participant Client
    participant API as AuthRESTController
    participant Session as SessionControl
    participant DB as PostgreSQL
    participant Redis as Redis Revocation

    Client->>API: GET /auth/sessions
    API->>Session: listSessions(currentUser)
    Session->>DB: Query safe active session metadata
    API-->>Client: Devices, last seen and current-session marker
    User->>Client: Revoke selected device
    Client->>API: DELETE /auth/sessions/{id}
    API->>Session: revokeOwnedSession(user, id)
    Session->>DB: Revoke session and family
    Session->>Redis: Revoke active JTI/family context
    API-->>Client: 204 No Content
```

### Sequence Diagram 12: Contact Change With Dual Verification (`UC-510`)

```mermaid
sequenceDiagram
    actor User
    participant Client
    participant API as AuthRESTController
    participant Recovery as RecoveryControl
    participant DB as PostgreSQL
    participant Notify as Email/SMS Adapters

    Client->>API: POST /auth/contact-change
    API->>Recovery: startContactChange(old, new, recentAuth)
    Recovery->>DB: Store pending workflow
    Recovery->>Notify: Send proof to old and new channels
    Client->>API: POST /auth/contact-change/verify-old
    Recovery->>DB: Record old-channel proof
    Client->>API: POST /auth/contact-change/verify-new
    Recovery->>DB: Atomically record proof and apply change if both valid
    Recovery->>Notify: Send security confirmation
    API-->>Client: Updated contact details
```

### Sequence Diagram 13: Personal Workspace Provisioning (`UC-309`)

```mermaid
sequenceDiagram
    actor User
    participant Client as Web/Mobile Client
    participant API as WorkspaceRouter
    participant Control as WorkspaceControl
    participant DB as PostgreSQL

    User->>Client: Complete profile registration
    Client->>API: GET /api/v1/workspaces
    API->>Control: listWorkspaces(authenticatedUser)
    Control->>DB: Ensure exactly one personal workspace
    DB-->>Control: Personal workspace plus active organizations
    Control-->>API: Authorized workspace summaries
    API-->>Client: Private personal portfolio and optional organizations
    Note over Control,DB: Personal workspace cannot accept members, roles, or invitations
```

### Sequence Diagram 14: Personal Referral Attribution (`UC-310`)

```mermaid
sequenceDiagram
    actor Referrer
    actor Friend
    participant Client as Web/Mobile Client
    participant API as WorkspaceRouter
    participant Referral as ReferralControl
    participant DB as PostgreSQL
    participant Notify as Email Provider
    participant Registration as RegistrationControl

    Referrer->>Client: Enter friend's email
    Client->>API: POST /api/v1/referrals
    API->>Referral: invite(referrer, email)
    Referral->>Referral: Deny self/existing user and enforce daily limit
    Referral->>DB: Store only hashed expiring token
    Referral->>Notify: Send opaque referral link
    API-->>Client: Masked invited status
    Friend->>Registration: Register with referral token
    Registration->>DB: Create independent user and private workspace
    Registration->>DB: Atomically claim matching referral
    Friend->>Registration: Verify profile email
    Registration->>DB: Mark referral verified
    Referrer->>API: GET /api/v1/referrals
    API-->>Referrer: Masked milestone status only
    Note over API,DB: No login time, session state, profile detail, or portfolio access is shared
```
