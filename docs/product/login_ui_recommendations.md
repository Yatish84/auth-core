# Login UI Recommendations

**Status:** Proposal for stakeholder review; no frontend design or implementation has been changed.

## Design Principle

Keep the approved GroX visual direction while making login clear, reassuring, accessible, and reusable across desktop web, mobile web, and the future Expo application.

## Recommended Improvements

| Area | Recommendation | Why it helps |
|---|---|---|
| Login choices | Lead with the most familiar method and place phone and social options under a clear divider. | Reduces visual competition and decision effort. |
| Password entry | Add show/hide, Caps Lock notice, clear focus, and a visible forgot-password link. | Prevents common entry mistakes. |
| Temporary lock | Show the wait time and safe recovery choices without confirming account existence. | Explains why retries are blocked without leaking private data. |
| Phone OTP | Support full-code paste, automatic advance, numeric keyboard, and resend countdown. | Improves desktop and smartphone usability. |
| Social login | Use provider-standard button labels and return users to a clear retry screen after cancellation. | Matches user expectations and provider rules. |
| Risk step-up | Explain that an extra check protects the account because the device or network looks different. | Makes MFA feel protective rather than arbitrary. |
| Fallback | Show only methods returned for the short-lived workflow and mask contact details. | Avoids exposing account information. |
| Accessibility | Preserve keyboard order, visible focus, screen-reader announcements, and adequate contrast. | Supports assistive technology and financial-platform accessibility. |

## Missing States Requiring Approval

Before frontend implementation, prepare reviewable wireframes for:

1. Invalid credentials with a generic message.
2. Temporary 15-minute login lock.
3. Phone OTP sent, invalid, expired, and resend countdown states.
4. Social-provider cancellation or temporary failure.
5. New-device or changed-network MFA explanation.
6. Social-email collision requiring existing-account proof.
7. Safe fallback-method chooser.

Each proposal should show desktop and phone-sized layouts. No proposed screen will be implemented until the project owner reviews and approves it.
