# Screen and Experience Inventory

## Design Governance

The supplied wireframes are the approved visual baseline. Material changes or new wireframes will not be created without first explaining the gap, the proposed experience, and the reason, then receiving stakeholder permission.

Implementation-only states such as responsive spacing, keyboard focus, loading indicators, disabled controls, and safe technical failures may be completed in the existing visual language when they do not change the intended journey.

## Existing Wireframe Coverage

The current 11-page PDF covers desktop web variants for:

- Mobile-number entry and validation.
- OTP verification, resend, populated, and error states.
- Email/password sign-up and validation states.
- Email/password login and invalid-credential state.
- Forgot-password request.
- Password-reset OTP verification.
- New-password entry and validation.

## Required Screens Not Yet Represented

These are documentation requirements, not approved designs.

| Experience | Related use cases | Why required | Approval status |
|---|---|---|---|
| Email verification sent/completed/expired | UC-302 | User needs clear asynchronous status and resend path. | Design permission required |
| MFA method chooser and TOTP verification | UC-105, UC-201, UC-202 | Risk step-up may offer multiple factors. | Design permission required |
| TOTP setup, QR, confirmation, backup codes | UC-204 | Mandatory MFA enrollment needs a guided secure flow. | Design permission required |
| Passkey enrollment and sign-in states | UC-104, UC-203, UC-204 | Browser prompts alone do not explain setup, fallback, or failure. | Design permission required |
| Social identity collision and linking proof | UC-307 | Unsafe auto-linking must be replaced by explicit proof. | Design permission required |
| Active sessions and devices | UC-509 | Users must inspect and revoke sessions. | Design permission required |
| Organization creation, invitation, switcher, members | UC-305, UC-306, UC-308 | Multi-tenant workflows require management interfaces. | Design permission required |
| Role editor | UC-506 | Organization admins need safe catalog-based assignment. | Design permission required |
| Contact-change dual verification | UC-510 | Both old and new channels need visible status. | Design permission required |
| Privacy export/erasure request and status | UC-601, UC-602 | High-impact privacy actions require warnings and progress. | Design permission required |
| Support user search/detail/recovery | UC-503, UC-504, UC-507 | Authorized staff need controlled case context. | Design permission required |
| Four-eyes reset initiation/approval/status | UC-508 | Distinct actors and cooldown must be understandable. | Design permission required |
| Audit search and event detail | UC-505 | Security reviewers need filterable, redacted evidence. | Design permission required |
| Protected reviewer dashboard | Demo navigation | Testers need a safe landing page to exercise features. | Design permission required |

## Universal States

Every approved screen implementation will consider:

- Initial, focused, populated, loading, success, empty, and recoverable error states.
- Rate-limit and temporary-unavailable responses.
- Expired or already-used workflow links.
- Keyboard-only operation, visible focus, screen-reader labels, and reduced motion.
- Responsive desktop, tablet, and mobile-web layouts.
- Safe copy that avoids account enumeration or sensitive detail leakage.

## Future Mobile Design

The Expo application will preserve journey and visual tokens but use native navigation, secure storage, platform passkeys, deep links, and phone-sized layouts. Mobile wireframes will be reviewed separately before creation; desktop screens will not simply be shrunk without usability review.
