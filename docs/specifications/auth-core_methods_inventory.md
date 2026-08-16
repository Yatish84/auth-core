# Planned Methods and Operations Inventory

**Architecture:** Entity-Boundary-Control

**Status:** Design inventory; signatures may be refined without changing the documented API behavior.

## Entity Operations

| Entity | Operation | Inputs | Output / invariant |
|---|---|---|---|
| `User` | `create` | normalized contact, profile | Pending user with validated state. |
| `User` | `verify_email` | verified time | Valid pending-to-active transition. |
| `User` | `lock`, `unlock`, `suspend` | reason and actor context | Controlled account-state transition. |
| `User` | `change_contacts` | proven new values | Applies only after required proofs. |
| `User` | `anonymize` | pseudonymization service | Removes/replaces PII irreversibly. |
| `Identity` | `create_password` | Argon2id hash | Verified password identity. |
| `Identity` | `link_federated` | provider and subject | Unique external identity binding. |
| `Identity` | `unlink` | factor inventory | Refuses removal of last usable primary factor. |
| `PasswordPolicy` | `evaluate` | candidate and history | Violations or accepted password. |
| `MFADevice` | `enable`, `disable` | proof or governed actor | Factor lifecycle transition. |
| `TOTPDevice` | `verify` | code and clock window | Constant-time outcome without secret exposure. |
| `PasskeyCredential` | `verify_assertion` | WebAuthn assertion | Verified signature and safe counter update. |
| `TokenFamily` | `rotate` | presented generation hash | New generation or replay/theft result. |
| `TokenFamily` | `revoke` | reason and time | Entire lineage becomes unusable. |
| `Session` | `touch`, `revoke` | activity or reason | Enforces idle/absolute lifetime. |
| `TrustedDevice` | `record_success` | bounded signals | Updated risk history. |
| `Invitation` | `accept` | token proof and user | Single acceptance before expiry. |
| `Workspace` | `validate_access` | user and workspace | Personal ownership or active organization membership only. |
| `Referral` | `claim`, `mark_verified` | token/email/user proof | Single attribution without access rights or login visibility. |
| `RoleBinding` | `assign`, `revoke` | org/module/role | Catalog-backed tenant permission. |
| `GovernedRequest` | `initiate` | actor, target, execute-after | Pending action with initiator. |
| `GovernedRequest` | `approve` | distinct supervisor | Approval without early execution. |
| `GovernedRequest` | `execute` | current time and policy | Revalidates all conditions. |
| `GDPRRequest` | `start`, `complete`, `fail` | request context | Valid privacy workflow state. |
| `AuditEvent` | `create` | safe actor/action/outcome data | Immutable event payload. |

## Control Operations

| Control | Operations | Responsibilities |
|---|---|---|
| `RegistrationControl` | `register_email`, `register_phone`, `verify_email`, `verify_phone` | CAPTCHA, breach policy, uniqueness, identities, tokens, notifications, audit. |
| `LoginControl` | `login_password`, `request_phone_otp`, `login_phone`, `login_federated`, `fallback_options` | Anti-enumeration, credentials, state, risk, MFA decision, session issuance. |
| `IdentityControl` | `start_link`, `complete_link`, `unlink` | Reauthentication, OIDC proof, collision protection, last-factor guard. |
| `RiskAssessmentControl` | `evaluate` | Device history, IP/velocity/provider signals, bounded decision explanation. |
| `MFAControl` | `issue_challenge`, `verify_code`, `resend`, `setup_totp`, `register_passkey`, `remove_factor` | Challenge state, factor policy, attempt limits, assurance. |
| `SessionControl` | `issue`, `list`, `revoke`, `revoke_all`, `enforce_cap` | Token family, session metadata, revocation, audit. |
| `TokenRefreshControl` | `rotate` | Atomic generation lookup, device binding, replay response, new token pair. |
| `RecoveryControl` | `request_password_reset`, `reset_password`, `change_contact`, `support_recovery` | Generic responses, single-use tokens, reauthentication, session revocation. |
| `OrganizationControl` | `create`, `invite`, `accept_invitation`, `switch_context`, `offboard` | Membership, role policy, scoped tokens, tenant revocation. |
| `WorkspaceControl` | `ensure_personal`, `list`, `switch_context` | Exactly one private personal context plus authorized organizations. |
| `ReferralControl` | `invite`, `list_status` | Rate limits, token hashing, safe delivery, masked status, no reward calculation. |
| `RoleControl` | `list_catalog`, `replace_member_roles` | Admin authorization and catalog validation. |
| `SupportAdminControl` | `unlock`, `suspend`, `initiate_mfa_reset`, `approve_mfa_reset`, `execute_mfa_reset` | Staff roles, four-eyes rule, cooldown, notifications, session termination. |
| `AuditQueryControl` | `search`, `export` | Filter authorization, pagination, redaction, audit of audit access. |
| `GDPRControl` | `request_export`, `build_export`, `request_erasure`, `execute_erasure` | Reauthentication, data collection, artifact protection, anonymization. |
| `KeyControl` | `publish_jwks`, `rotate_signing_key` | Key lifecycle and overlap windows. |

## Boundary Operations

| Boundary / Port | Planned operations |
|---|---|
| `AuthRouter` | Registration, verification, login, federation, MFA, refresh, logout, recovery. |
| `OrganizationRouter` | Organization, invitation, membership, role, and context endpoints. |
| `WorkspaceRouter` | Personal/organization workspace listing and personal referral endpoints. |
| `AdminRouter` | Support, governed reset, suspension, and audit endpoints. |
| `PrivacyRouter` | Export, erasure, status, and download endpoints. |
| `JWKSRouter` | Public key discovery. |
| `UserRepository` | `get_by_id`, `get_by_email`, `add`, `save`, state-safe lookups. |
| `IdentityRepository` | Provider/subject and user identity operations. |
| `FactorRepository` | MFA and passkey operations without exposing secret plaintext. |
| `SessionRepository` | Family/generation/session locking, listing, revocation, cap queries. |
| `OrganizationRepository` | Organizations, invitations, membership, and role bindings. |
| `WorkspaceRepository` | Personal ownership, authorized workspace listing, and referral attribution. |
| `GovernanceRepository` | Governed request locking and state transitions. |
| `AuditRepository` | Append and authorized cursor search only. |
| `OutboxRepository` | Append, claim, retry, complete, dead-letter. |
| `RedisSecurityStore` | Challenges, OTPs, locks, rate limits, risk cache, revocation timestamps. |
| `PasswordHasher` | `hash`, `verify`, `needs_rehash`. |
| `SecretCipher` | `encrypt`, `decrypt`, `rotate_envelope`. |
| `TokenSigner` | `sign_access`, `public_jwks`, `rotate`. |
| `OIDCProvider` | `authorization_request`, `verify_callback`. |
| `BreachPasswordProvider` | `breach_count` using k-anonymity range query. |
| `CaptchaProvider` | `verify` with hostname/action checks. |
| `EmailProvider`, `SMSProvider` | Template-based notification delivery. |
| `RiskProvider` | Optional IP reputation/geolocation signals with timeout policy. |
| `ArtifactStore` | Encrypt, store, authorize, and expire privacy exports. |
| `Clock`, `RandomSource` | Injectable deterministic test seams. |

## Worker Operations

| Handler | Responsibility |
|---|---|
| `NotificationHandler` | Render approved templates and deliver idempotently. |
| `GovernedActionHandler` | Revalidate and execute matured approved actions. |
| `PrivacyExportHandler` | Generate encrypted JSON export and expiry metadata. |
| `ErasureHandler` | Execute resumable anonymization and completion audit. |
| `CleanupHandler` | Expire workflow state and enforce retention policies. |
| `KeyRotationHandler` | Coordinate signing-key publication, activation, and retirement. |

## Method Design Rules

- Async boundaries; pure synchronous entity logic where possible.
- Typed DTOs and enums; no unstructured dictionaries across layers.
- Explicit actor, organization, clock, and correlation context.
- No method accepts or returns plaintext secrets beyond the shortest necessary scope.
- Security failures return stable domain errors; provider details stay internal.
- Every mutation defines transaction, idempotency, audit, and retry behavior.
