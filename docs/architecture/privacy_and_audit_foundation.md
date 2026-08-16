# Delivered Privacy and Audit Foundation

## In Plain Language

Milestone 9 begins by letting specifically authorized security supervisors review security history without exposing passwords, tokens, contact details, or other unnecessary private information. Ordinary users and other staff roles cannot use this cross-user audit view.

This service is shared by the website and future mobile application. No frontend screen or wireframe was created or changed.

## Delivered Audit Flow

```mermaid
flowchart LR
    CLIENT["Approved web or future mobile client"] --> TOKEN["Verify access token"]
    TOKEN --> MFA{"Recent MFA present?"}
    MFA -- No --> DENY["Return safe forbidden response"]
    MFA -- Yes --> ROLE{"Active SECURITY_SUPERVISOR_L3 role?"}
    ROLE -- No --> DENY
    ROLE -- Yes --> QUERY["Apply approved filters and cursor pagination"]
    QUERY --> RLS["PostgreSQL independently enforces staff access"]
    RLS --> REDACT["Redact sensitive metadata and bound returned values"]
    REDACT --> RESULT["Return at most 100 records plus next cursor"]
    RESULT --> EVIDENCE["Record AUDIT_LOGS_QUERIED in immutable audit history"]
```

## Security Rules

| Rule | Delivered behavior |
|---|---|
| Strong verification | The caller must have a recent MFA assurance method. |
| Staff authority | The role comes from `staff_role_bindings`, never from request data or organization membership. |
| Least privilege | Cross-user audit search is limited to active `SECURITY_SUPERVISOR_L3` staff. |
| Database enforcement | PostgreSQL row-level security independently checks the same role. |
| Safe filtering | Search supports subject, event, outcome, time range, and an opaque cursor. |
| Bounded results | Each response contains 1 to 100 records. |
| Privacy redaction | Metadata keys related to credentials, tokens, codes, contact details, evidence, and network identifiers are replaced with `[REDACTED]`. |
| Tamper resistance | Application roles cannot update, delete, or truncate audit records; a database trigger rejects mutation. |
| Audit of access | Every successful audit search creates an `AUDIT_LOGS_QUERIED` record. |

## Remaining Milestone 9 Work

- Privacy and audit screens only after project-owner design approval.

## Delivered Data Export Flow

```mermaid
flowchart LR
    USER["Authenticated user with recent MFA"] --> REQUEST["POST privacy export with idempotency key"]
    REQUEST --> REUSE{"Matching request already exists?"}
    REUSE -- Yes --> STATUS["Return the original safe status"]
    REUSE -- No --> COLLECT["Collect only the owner's approved profile, identity, MFA, session, device, and workspace-role metadata"]
    COLLECT --> EXCLUDE["Exclude password hashes, MFA secrets, refresh tokens, and signing material"]
    EXCLUDE --> ENCRYPT["Encrypt JSON with AES-256-GCM and owner/request binding"]
    ENCRYPT --> STORE["Store ciphertext and digest for 24 hours"]
    STORE --> DOWNLOAD["Owner reauthenticates and downloads verified JSON"]
```

The MVP stores encrypted artifacts in PostgreSQL. The same `PrivacyRepository` and cipher boundaries can use AWS S3 plus KMS in production without changing the web or future mobile API.

## Delivered Account Erasure Flow

```mermaid
flowchart LR
    USER["Authenticated user with recent MFA"] --> CONFIRM["Submit ERASE_MY_ACCOUNT plus idempotency key"]
    CONFIRM --> OWNER{"Last owner of an organization?"}
    OWNER -- Yes --> TRANSFER["Stop and require ownership transfer"]
    OWNER -- No --> REVOKE["Revoke all sessions and token families"]
    REVOKE --> ERASE["Delete credentials, MFA secrets, devices, contact workflows, and export artifacts"]
    ERASE --> ANON["Remove profile PII and close/anonymize the personal workspace"]
    ANON --> AUDIT["Preserve pseudonymous immutable audit evidence"]
    AUDIT --> RETAIN["Record configured backup-purge deadline"]
```

The retained user UUID is a pseudonymous technical reference, not a usable account. Email, phone, names, login identities, factors, devices, sessions, referrals owned by the user, and export artifacts are removed or irreversibly anonymized. This allows lawful audit evidence to remain immutable without preserving an active identity.
