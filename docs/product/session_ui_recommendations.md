# Session UI Recommendations

**Status:** Proposal only — no frontend screens have been created or changed.

## Missing States Worth Designing

| Proposed experience | Plain-language purpose |
|---|---|
| Active sessions page | Show signed-in devices, approximate IP, last activity, expiry, and which session is current. |
| Revoke confirmation | Explain that removing a device signs it out immediately. |
| Sign out everywhere | Confirm the user intends to end all web and mobile sessions. |
| Session expired message | Explain that the security time limit ended and offer a clear sign-in action. |
| Stolen-token warning | Explain that suspicious token reuse ended the session as a precaution. |
| Maximum-device notice | Explain that signing in on a new device removed the oldest of ten sessions. |

## Recommended Presentation

- Use familiar device labels such as “Web browser” and “Mobile app”; never display complete fingerprints.
- Mark the current session clearly and place destructive actions behind confirmation.
- Use neutral language for normal expiry and stronger guidance for detected refresh-token reuse.
- Keep the same information hierarchy for web and future mobile screens.

Visual wireframes or frontend implementation require project-owner approval before work begins.
