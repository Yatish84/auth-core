# Registration UI Recommendations

**Status:** Proposal for stakeholder review; no frontend design or implementation has been changed.

## Design Principle

Keep the approved GroX visual identity and journeys while improving clarity, accessibility, mobile readiness, and confidence during high-trust financial account creation.

## Recommended Improvements

| Current baseline | Recommendation | Why it helps |
|---|---|---|
| Large illustration and comparatively small form area | Give the form more width and reduce or hide the illustration on smaller screens. | Improves readability and reduces unnecessary scrolling. |
| Multi-step journey without persistent orientation | Add a simple `Account details -> Verification -> Complete` progress indicator. | Users understand where they are and what remains. |
| Password feedback concentrated around submission | Show requirements while typing, add show/hide, and preserve safe validation state. | Reduces failed submissions without weakening security. |
| OTP boxes treated as separate inputs | Support automatic advance, backspace, full-code paste, and mobile numeric keyboard. | Makes verification faster on desktop and mobile. |
| Resend action without visible timing | Show a resend countdown and clearly explain expiration and attempt limits. | Prevents repeated clicks and surprise rate limits. |
| Limited asynchronous states | Add approved sent, completed, expired, already-used, and temporarily unavailable states. | Makes verification links and provider delays understandable. |
| Desktop-first composition | Use responsive content priority rather than shrinking the desktop canvas. | Produces a usable future mobile-web experience and informs Expo design. |
| General validation presentation | Add visible focus, screen-reader announcements, field associations, and sufficient contrast. | Supports keyboard and assistive-technology users. |

## Missing Design States Requiring Approval

Before frontend implementation, prepare reviewable wireframes for:

1. Email verification sent.
2. Email verification completed.
3. Email verification expired or already used, with resend action.
4. Temporary email/SMS provider failure and retry.

The proposal should show desktop and phone-sized layouts. No new wireframe will be treated as approved until the project owner reviews it.

