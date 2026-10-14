# Result experience

This frontend-only update separates the deployment decision, required actions,
review questions, recommendations, guidance, and technical records. It does not
change stored assessments, API contracts, authentication, or analysis policies.

## Presentation contract

- `BLOCKED`: 배포 전 수정 필요
- `REVIEW_REQUIRED`: 확인 후 배포 판단 필요
- `READY_WITH_WARNINGS`: 배포 가능하지만 수정 권장
- `READY`: 현재 분석 범위에서는 배포 가능

The summary uses the server's risk assessment, never the legacy numerical score.
The score remains available as a rule-engine reference in Technical Information.
Legacy results without a risk snapshot show an unassessed state, not zero risk.

The required-action and recommendation lists use existing `RiskFinding.priority`.
The direct-verification count displays the server's `REVIEW_REQUIRED` count.
Independent semantic candidates are shown separately, never added to that count.
Supporting evidence attached to an existing finding is not counted again.
Canonical dependency findings remain authoritative; original rule observations
are accessible separately in technical records.

Problem cards show plain-language actions first. Closed details expose locations,
reasoning, masked evidence, severity, confidence, false-positive risk, advisory
identifiers, threat information, and model provenance. Missing metadata is never
assigned an invented default. Fixed dependency versions are reported fixes, not
guarantees of compatibility or freedom from all vulnerabilities. Semantic titles
use question-oriented labels for the server's candidate type; original model
titles, reason and verification steps remain unchanged in technical details.
Type-based manual checks are shown first without asserting a confirmed diagnosis.

AI-enhanced but disabled, failed, unsupported-context, empty-completed, and legacy
states stay distinguishable. No candidate does not mean the project is safe.
Stored remediation remains matched by finding identity. Guidance shows one
finding at a time instead of six separate generation tabs. See `ai-ux-roles.md`.
Navigating the UI does not invoke AI generation.

## Verification

- `npm test` in `frontend`: component rendering and presentation invariants.
- `npm run build` in `frontend`: type checking and production bundle.
- `node tests/browser/result-workspace.cjs` in `frontend`: mock-only Playwright
  verification against the Vite server (default `http://localhost:5173`).
  Install Playwright in the test environment or set `PLAYWRIGHT_MODULE` to its
  module path. `FRONTEND_URL` can select another local Vite URL.
- Browser coverage includes login/logout, ZIP/GitHub submission, history detail,
  all six views, severity filtering, technical disclosure, status updates, PDF
  download dispatch, explicit AI PDF cost confirmation, stored guidance,
  backend-driven summary, disabled AI, empty AI, and legacy
  snapshots at 1440, 390, and 320 pixel widths. All API requests are intercepted;
  no real credentials, database writes, or external AI calls are used.
- Screenshots are written only to `/private/tmp/securedeploy-result-*.png`.
- Run the backend test suite with template mode and external smoke flags disabled.

## Limits

Phase 5 now supplies saved `riskSummary` and `comparisonAvailable` in history.
History uses that summary without inferring deployment readiness from the legacy
score; older entries without it remain unassessed. Open a result for full details.
Backend and AI explanations can still contain technical language. Type-based
manual checks supplement the original advice without inventing a diagnosis.
The core problem lists paginate at six items; legacy technical lists can still
be long. Rescanning and progress are documented separately in
`phase5-security-progress.md`; presentation does not introduce a new security policy.
