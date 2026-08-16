# Workspace, Organization, and Referral Foundation

## Plain-Language Purpose

Every GroX user receives a private personal portfolio space. A user may also create or join business workspaces without opening another account. Personal referrals introduce new independent users, while organization invitations grant controlled access to a specific business workspace.

These are deliberately separate:

- A personal referral creates attribution only. It never shares a portfolio.
- An organization invitation grants a catalog-approved role only after the invited person signs in with the matching email and accepts the single-use invitation.

## Delivered Capabilities

| Capability | Behavior |
|---|---|
| Personal workspace | Created automatically for new users and backfilled for existing users. Exactly one is allowed per owner. |
| Organization creation | Creates the workspace and complete owner permission bindings in one transaction. |
| Workspace listing | Returns the caller's personal workspace and only organizations with active membership. |
| Personal referrals | Tracks invited, registered, and verified milestones with masked status and no login visibility. |
| Organization invitations | Uses a hashed seven-day token, approved `MEMBER` or `VIEWER` role, matching-email proof, and single acceptance. |
| Member directory | Available only to organization owners; email is masked in client responses. |
| Role replacement | Replaces all active bindings with `OWNER`, `MEMBER`, or `VIEWER` catalog entries. |
| Context switching | Revalidates ownership or membership and replaces the access token with a 15-minute workspace-scoped token. |
| Offboarding | Revokes role bindings and organization-scoped access immediately while preserving the person's account and unrelated workspaces. |

## Security Rules

1. Personal workspaces cannot contain invitations or role bindings; PostgreSQL triggers reject both.
2. Personal ownership cannot be transferred through the public API.
3. Client-supplied permissions are never trusted. Roles map only to active catalog records.
4. The final organization owner cannot be removed or demoted until another owner exists.
5. Invitation and referral bearer tokens are stored only as keyed HMAC hashes.
6. A workspace switch revokes the previous access-token ID before issuing the replacement.
7. Refreshing a session returns to an unscoped state, requiring workspace access to be checked again.
8. Offboarding records a user-and-organization revocation timestamp in Redis and revokes active scoped token IDs.
9. PostgreSQL row-level security separates personal owners and organization members.
10. Referral status never contains session activity, last-login information, profile details, or portfolio information.

## Shared Web and Mobile APIs

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/workspaces` | List authorized personal and organization contexts. |
| POST | `/api/v1/organizations` | Create an optional organization. |
| POST | `/api/v1/organizations/{workspace_id}/invitations` | Invite a teammate with an approved role. |
| POST | `/api/v1/organizations/invitations/accept` | Accept a matching single-use invitation. |
| GET | `/api/v1/organizations/{workspace_id}/members` | List safe member details. |
| PUT | `/api/v1/organizations/{workspace_id}/members/{user_id}/roles` | Replace a member's role. |
| DELETE | `/api/v1/organizations/{workspace_id}/members/{user_id}` | Remove organization access. |
| POST | `/api/v1/auth/workspace/switch` | Obtain a short-lived token for a verified workspace. |
| POST | `/api/v1/referrals` | Refer a prospective independent user. |
| GET | `/api/v1/referrals` | View masked referral milestones. |

The future mobile app uses the same operations and rules. Only token storage, navigation, and screen layout differ by client platform.

## Deferred Business Decisions

Referral rewards, qualification thresholds, incentive expiry, tax treatment, campaign limits, and reward-ledger accounting are intentionally not implemented. They require a separately approved business and fraud-control plan.

No frontend screen was created or changed in this milestone increment. Proposed workspace and referral experiences remain subject to owner approval before visual implementation.
