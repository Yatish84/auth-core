# MFA and Passkey UI Recommendations

**Status:** Proposal for stakeholder review; no frontend screen has been designed or implemented from this document.

## Design Principle

Make strong security understandable and reassuring. The same journey should feel natural on desktop web, mobile web, and the future Expo application without copying backend security rules into each client.

## Recommended Experience

| Area | Recommendation | Why it helps |
|---|---|---|
| Method chooser | Show the recommended method first, with masked email/phone destinations and concise alternatives. | Reduces uncertainty without exposing private contact details. |
| Authenticator setup | Show a QR representation, manual key, copy action, and a confirmation-code step. | Supports both camera scanning and same-device setup. |
| Backup codes | Show once with copy, print, and confirmation that the user stored them safely. | Makes the emergency path usable while preserving one-time disclosure. |
| Passkey enrollment | Explain the device prompt before opening Face ID, Touch ID, Windows Hello, or security-key UI. | Users understand that biometrics remain on their device. |
| Passkey cancellation | Return to the same page with retry and alternative-method actions. | Browser cancellation should not look like an account failure. |
| Temporary lock | Explain the 15-minute wait and offer another enrolled method when safe. | Prevents repeated failures and reduces support requests. |
| Factor management | Show human labels, factor type, and remove action; require another strong factor before removing the last one. | Keeps security settings understandable and prevents lockout. |
| Accessibility | Announce code errors, preserve keyboard focus, support code paste, and avoid countdown-only instructions. | Supports keyboard, screen-reader, and cognitive accessibility needs. |

## Missing Wireframes Requiring Permission

Before frontend implementation, prepare reviewable desktop and phone wireframes for:

1. MFA method chooser.
2. Authenticator setup, manual-key fallback, and confirmation.
3. Backup-code one-time display and saved confirmation.
4. Email/SMS code entry, expiry, resend countdown, and temporary lock.
5. Passkey explanation, browser prompt handoff, success, cancellation, and unsupported-device fallback.
6. Factor-management list, rename, remove, and last-strong-factor warning.
7. Social-account collision proof and successful linking.

No proposed wireframe or visual change will be implemented until the project owner reviews and explicitly approves it.
