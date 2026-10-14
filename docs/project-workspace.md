# Project Workspace milestone

## Information architecture

- Login opens `#/dashboard`. Global navigation: dashboard, projects, new project, account.
- Project routes: `#/projects/{id}/overview`, `findings`, `history`, `rescan`, `settings`.
- Historical results use `findings?review={id}&view={view}` and a historical-result notice. Overview always uses the latest review.
- Findings reuse `ReviewResultWorkspace`, saved per-finding AI guidance, technical details, PDF actions, and the five-state progress snapshot. Navigation does not request AI generation.
- Account shows the authenticated user's name/email and logout. No sharing, teams, workflow, or new AI features.

## Backend-owned dashboard

`GET /api/workspace` returns only the authenticated user's projects, latest saved risk/progress summaries, review counts, and aggregate project counts.

- `blockedProjectCount` / `reviewRequiredProjectCount` use the latest persisted risk assessment, not the legacy security score.
- `analyzedProjectCount` means projects with at least one review; it is not an undocumented recent-time window.
- Missing reviews or legacy reviews without risk snapshots are unassessed, never implicitly READY.
- `findingCount` on project review history sums the saved deterministic priority counts. Semantic candidates remain separate.
- Latest ordering is `createdAt DESC, id DESC`. Counts/latest reviews are queried in batches, not by loading every project's review collection.
- No schema change or migration is required. Historical snapshots are not recalculated.

## Ownership and legacy data

Previously, ownerless projects/reviews were allowed by several access checks, and the global review history query included orphan/ownerless records. This was a legacy compatibility exception, not an ownership guarantee.

`ProjectOwnership.requireOwner` now rejects unauthenticated access and projects without the current owner. Review detail, AI/PDF, project dashboard/history/comparison, status mutation, rescan, and deletion are covered by API isolation tests. Global history is restricted to owned projects.

Ownerless records remain in the database but are hidden and forbidden to ordinary authenticated users. No claim-on-read, automatic assignment, or deletion is performed. A future administrative migration must verify actual ownership before assigning these records.

Legacy unscoped persistence helpers remain for internal scan construction/test compatibility, not for HTTP controller access. New HTTP endpoints must use the authenticated owner-aware services.

## Project identity and rescanning

Existing behavior is retained: within one user, an extracted ZIP project name or normalized GitHub repository URL resolves to an existing project. The new-project screen explains this behavior. It does not merge projects across users.

Explicit project rescans always target the selected project ID, including a renamed ZIP. GitHub rescans show the saved URL. Failed scans preserve the previous snapshot. Unknown comparison coverage is not resolution; AI candidate disappearance is not deterministic resolution.

Deleting a review refreshes latest/history from the backend; an empty project is retained. Project deletion requires confirmation and existing backend ownership checks.

## Verification

- `gradle test`: ownership, ownerless data preservation, workspace counts, latest snapshots, empty/legacy projects, existing analysis regressions.
- `cd frontend && npm test && npm run build`.
- Browser scripts: `workspace.cjs`, `result-workspace.cjs`, `review-progress.cjs`, `zip-upload.cjs` under `frontend/tests/browser`; use `PLAYWRIGHT_MODULE` when Playwright is provided outside this repository. Viewports: 1440, 390, 320.
- Workspace browser coverage includes failed fetch/retry, empty project, confirmation/cancel deletion, account navigation, logout/login, stale previous-user response suppression, and forbidden project navigation.
- Actual local PostgreSQL/browser verification used an isolated server with template AI, SCA/threat-intelligence external lookups disabled, and Hibernate `validate`. Signup/login, ZIP, dashboard, findings, renamed ZIP rescan, stored comparison/history, and User B denial passed. One resolved and one remaining finding were round-tripped. Temporary accounts/projects were removed; pre-existing row fingerprints were unchanged. No paid AI requests.

## Boundaries

- Workspace/project histories are not paginated yet; a large-account milestone should add server-side pagination and bounded summary projections.
- Existing JWT/localStorage/session-expiry behavior is unchanged. Revocation and refresh-token design are separate authentication work.
- Same-name ZIP auto-association is existing behavior; users should use explicit project rescans when identity matters.
- Real GitHub cloning and external intelligence/AI calls were not repeated in this milestone's live browser test; existing automated regressions and stored/mock result paths were used.
