# Auth-Core Functional Flowcharts

## Authentication Decision Flow

```mermaid
flowchart TD
    START([Authentication request]) --> VALIDATE[Validate headers, CAPTCHA and rate limits]
    VALIDATE --> METHOD{Authentication method}
    METHOD -->|Password| PASSWORD[Verify Argon2id credential]
    METHOD -->|Phone OTP| OTP[Verify hashed unexpired OTP]
    METHOD -->|OIDC| OIDC[Verify state, nonce, PKCE and provider claims]
    METHOD -->|Passkey| PASSKEY[Verify challenge, origin, RP and signature]
    PASSWORD --> PRIMARY{Primary proof valid?}
    OTP --> PRIMARY
    OIDC --> COLLISION{Existing identity or safe provisioning?}
    PASSKEY --> PRIMARY
    COLLISION -->|Unsafe email collision| PROOF[Require existing-account proof]
    COLLISION -->|Safe| PRIMARY
    PRIMARY -->|No| FAIL[Generic failure + audit + rate counter]
    PRIMARY -->|Yes| STATE{Account active?}
    STATE -->|No| BLOCK[Safe account-state response]
    STATE -->|Yes| RISK[Evaluate bounded risk signals]
    RISK --> MFA{Step-up required?}
    MFA -->|Yes| CHALLENGE[Issue short-lived MFA workflow]
    MFA -->|No| SESSION[Issue token family and session]
    CHALLENGE --> VERIFY[Verify TOTP, OTP or passkey]
    VERIFY -->|Invalid| MFAFAIL[Attempt count / factor lock]
    VERIFY -->|Valid| SESSION
    SESSION --> CLIENT{Client type}
    CLIENT -->|Web| COOKIE[HttpOnly refresh cookie + access token]
    CLIENT -->|Mobile| SECURE[Token response for secure device storage]
```

## Refresh Rotation and Theft Detection

```mermaid
flowchart TD
    R([Refresh request]) --> HASH[Hash presented token]
    HASH --> LOCK[Lock token family and generation]
    LOCK --> FOUND{Known generation?}
    FOUND -->|No| INVALID[Generic invalid token]
    FOUND -->|Yes| USED{Already used or revoked?}
    USED -->|Yes| REVOKE[Revoke complete family]
    REVOKE --> ALERT[Audit theft signal and update revocation]
    ALERT --> DENY[401 TOKEN_REUSE_DETECTED]
    USED -->|No| DEVICE{Device binding valid?}
    DEVICE -->|No| REVOKE
    DEVICE -->|Yes| ROTATE[Mark used and insert next hash atomically]
    ROTATE --> ISSUE[Issue new access and refresh tokens]
```

## Organization Context and Offboarding

```mermaid
flowchart TD
    ACTOR([Authenticated actor]) --> ACTION{Action}
    ACTION -->|Switch| MEMBER[Verify active target membership]
    MEMBER -->|No| DENY[403 ACCESS_DENIED]
    MEMBER -->|Yes| ROLES[Load active catalog-backed roles]
    ROLES --> JWT[Issue new organization-scoped access token]
    ACTION -->|Offboard| ADMIN[Verify admin rights and target rules]
    ADMIN -->|No| DENY
    ADMIN -->|Yes| TX[Revoke role bindings in transaction]
    TX --> REV[Set user/org revocation timestamp]
    REV --> SESSIONS[Revoke organization-scoped sessions]
    SESSIONS --> AUDIT[Append audit and notification event]
```

## Four-Eyes MFA Reset

```mermaid
stateDiagram-v2
    [*] --> PendingApproval: L2 initiates + user notified
    PendingApproval --> ApprovedWaiting: distinct L3 approves
    PendingApproval --> Rejected: rejected or expires
    ApprovedWaiting --> Executable: 12-hour execute-after reached
    Executable --> Completed: worker revalidates and resets
    Executable --> Failed: policy or state changed
    Completed --> [*]
    Rejected --> [*]
    Failed --> [*]
```

## GDPR Erasure

```mermaid
flowchart TD
    REQUEST([Erasure request]) --> REAUTH[Require recent strong reauthentication]
    REAUTH --> WARN[Record informed confirmation]
    WARN --> PENDING[Create durable request]
    PENDING --> REVOKE[Disable access and revoke sessions]
    REVOKE --> ANON[Anonymize identity and profile PII]
    ANON --> LINKS[Remove provider links and encrypted factor secrets]
    LINKS --> AUDIT[Preserve privacy-safe lawful audit evidence]
    AUDIT --> COMPLETE[Record completion and backup-expiry policy]
```

## Error Outlet Rules

- Invalid credentials and password-reset requests do not disclose account existence.
- Dependency outages return retryable generic errors and do not bypass checks.
- Replayed workflow tokens are rejected idempotently.
- Authorization failure never falls back to client-supplied roles.
- Every security-significant result writes a redacted outcome event.
