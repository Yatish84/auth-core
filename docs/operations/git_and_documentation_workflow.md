# Git and Documentation Workflow

## Branching

- `main` is protected and always releasable.
- Work uses short-lived `codex/<milestone-or-feature>` branches.
- Direct pushes to `main` are disabled after repository protections are configured.
- Each branch addresses one coherent review scope.

## Commits

Use Conventional Commit-style messages:

- `docs: complete authentication architecture`
- `feat(auth): add password registration control`
- `fix(tokens): revoke family on generation replay`
- `test(org): cover cross-tenant role access`

Commits must not contain credentials, generated caches, local databases, build artifacts, or unrelated formatting churn.

## Pull Requests

Each pull request includes:

- Purpose and affected use-case IDs.
- Architecture/API/schema/security impact.
- Tests run and demonstration evidence.
- Migration and rollback notes.
- New environment variables or provider actions.
- Documentation and wireframe approval status.

Draft PRs are opened early for substantial milestones. Required checks and reviewer approval precede squash merge.

## Documentation Governance

- Repository Markdown is canonical.
- The README provides a stakeholder overview and links into `docs/README.md`.
- Mermaid source stays version-controlled beside explanatory text.
- Machine-readable OpenAPI is generated/validated in CI.
- A GitHub Pages/MkDocs site may publish repository docs; a Wiki contains only curated navigation or synchronized summaries to avoid drift.
- Material design changes require stakeholder permission before a wireframe is created.

## Planned GitHub Protections

- Protected `main` with pull-request reviews.
- Required CI checks and resolved review conversations.
- Secret scanning, dependency alerts, and Dependabot/Renovate policy.
- CODEOWNERS for security-critical paths.
- Signed commits or vigilant mode where practical.
- GitHub OIDC rather than long-lived AWS deployment credentials.

## Publishing Sequence for This Documentation Set

1. Complete and validate documents locally.
2. Present changed files, structure, findings, and validation results to the owner.
3. Make requested revisions locally.
4. Obtain explicit approval to publish.
5. Create documentation branch, commit intentionally, push, and open a draft or ready PR as approved.

No commit or push occurs before step 4.
