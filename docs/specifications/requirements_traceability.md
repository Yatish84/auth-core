# Requirements Traceability Matrix

This matrix ensures every source use case receives a boundary, control, persistent or ephemeral state, user experience, and acceptance test.

| Use cases | Capability group | Primary API / boundary | Main control | Main state | UI / actor | Acceptance focus |
|---|---|---|---|---|---|---|
| UC-101, UC-106 | Password login and risk | `/auth/login` | `LoginControl`, `RiskAssessmentControl` | identities, trusted devices, rate keys | Login, MFA prompt | Generic failure, risk step-up, lockout |
| UC-102, UC-303, UC-307 | OIDC and identity linking | `/auth/sso/*`, `/auth/identities/*` | `LoginControl`, `IdentityControl` | identities, users, OIDC workflow | Social login, collision proof | State/nonce/PKCE, no unsafe auto-link |
| UC-103, UC-105 | Phone OTP and fallback | `/auth/login/phone/*`, fallback | `LoginControl` | OTP/rate keys, identities | Phone entry, OTP, fallback chooser | Expiry, attempts, pumping controls |
| UC-104 | Passkey login | `/auth/passkeys/*` | `MFAControl` | credentials, challenge keys | Passkey prompt | Origin/RP/challenge/signature checks |
| UC-201, UC-202, UC-203, UC-204 | MFA and enrollment | `/auth/mfa/*` | `MFAControl` | devices, encrypted secrets, challenges | Verify/setup/manage factors | Attempt lock, backup, last-factor guard |
| UC-301, UC-302 | Email registration | `/auth/signup`, `/auth/verify/email`, `/auth/verify/email/request` | `RegistrationControl` | users, identities, ephemeral tokens | Signup, verification status | CAPTCHA, HIBP, single-use activation and safe resend |
| UC-304 | Phone registration | `/auth/signup/phone`, verify phone | `RegistrationControl` | users, phone identity, OTP keys | Phone signup and OTP | E.164, rate limit, uniqueness |
| UC-305 | Organizations/invitations | `/organizations*` | `OrganizationControl` | orgs, invitations, bindings | Org create/invite/accept | Authorization, expiry, idempotency |
| UC-306 | Context switching | `/auth/workspace/switch` | `WorkspaceControl`, `SessionControl` | bindings, sessions, org revocation | Workspace switcher | Membership, scoped claims, prior-JTI denial |
| UC-308 | Offboarding | member DELETE | `OrganizationControl` | bindings, sessions, org revocation | Member administration | Immediate tenant denial only |
| UC-309 | Personal workspace | `/workspaces` | `WorkspaceControl` | organizations with personal owner | Workspace switcher | Exactly one owner-only workspace; cross-user denial |
| UC-310 | Personal referrals | `/referrals`, signup referral token | `ReferralControl`, `RegistrationControl` | referrals | Referral status | Hashing, expiry, attribution, privacy, self-referral denial |
| UC-401, UC-402, UC-403, UC-404, UC-405 | Token/session lifecycle | refresh/logout/session APIs | `SessionControl`, `TokenRefreshControl` | families, generations, sessions, revocation keys | Session management | Replay theft, cap, idle/absolute expiry |
| UC-501, UC-502 | Password recovery | `/auth/password/*` | `RecoveryControl` | ephemeral tokens, history | Forgot/reset screens | Anti-enumeration, single use, revoke all |
| UC-503, UC-504 | Unlock/suspend | `/admin/users/*` | `SupportAdminControl` | users, sessions, audit | Admin user detail | Role/MFA checks and revocation |
| UC-505 | Audit query | `/admin/audit-logs` | `AuditQueryControl` | audit logs | Audit search | Immutable data, filter authorization |
| UC-506 | Roles | member roles and `/admin/roles` | `RoleControl` | catalog, bindings | Role editor | No arbitrary role injection |
| UC-507 | Support recovery | admin recovery API | `RecoveryControl` | governed/ephemeral tokens | Support case | Ticket, notification, single use |
| UC-508 | MFA reset | `/admin/mfa-resets*` | `SupportAdminControl` | governed requests, outbox | Initiate/approve/status | Distinct actors, 12-hour delay |
| UC-509 | Active sessions | `/auth/sessions*` | `SessionControl` | sessions, families | Device/session list | Self-only list, selected revocation |
| UC-510 | Contact change | `/auth/contact-change*` | `RecoveryControl` | workflow state/tokens | Dual verification screens | Old + new proof, atomic change |
| UC-601 | Data export | `/privacy/exports*` | `GDPRControl` | GDPR requests, artifacts | Privacy request/status/download | Reauth, encrypted expiring artifact |
| UC-602 | Erasure | `/privacy/erasures` | `GDPRControl` | all PII, audit, jobs | Erasure warning/status | Reauth, anonymization, retention |

## Traceability Rules

- Pull requests cite the affected use-case IDs.
- Automated test names include the use-case ID where practical.
- Contract changes update API, sequence, method, schema, and screen documents together.
- A use case is not complete while any matrix column is undefined.
