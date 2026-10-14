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
The check-needed count displays the sum of the server's `REVIEW_REQUIRED` count
and independent semantic candidates, with the two counts explicitly broken out.
This is a navigation workload count, not a change to the assessment or finding
count. Supporting evidence attached to an existing finding is not counted again.
Canonical dependency findings remain authoritative; original rule observations
are accessible separately in technical records.

Problem cards show reported actions and locations first. Closed details expose
reasoning, masked evidence, severity, confidence, false-positive risk, advisory
identifiers, threat information, and model provenance. Missing metadata is never
assigned an invented default. Fixed dependency versions are reported fixes, not
guarantees of compatibility or freedom from all vulnerabilities. Semantic titles
use question-oriented labels for the server's candidate type; original model
titles remain in technical details, with reason and verification steps unchanged.

AI-enhanced but disabled, failed, unsupported-context, empty-completed, and legacy
states stay distinguishable. No candidate does not mean the project is safe.
Stored remediation remains matched by finding identity. Existing manual AI tools
are available under Guidance; navigating the UI does not invoke them.

## Verification

- `npm test` in `frontend`: component rendering and presentation invariants.
- `npm run build` in `frontend`: type checking and production bundle.
- `node tests/browser/result-workspace.cjs` in `frontend`: mock-only Playwright
  verification against the Vite server (default `http://localhost:5173`).
  Install Playwright in the test environment or set `PLAYWRIGHT_MODULE` to its
  module path. `FRONTEND_URL` can select another local Vite URL.
- Browser coverage includes login/logout, ZIP/GitHub submission, history detail,
  all six views, severity filtering, technical disclosure, status updates, PDF
  download dispatch, AI summary/error display, disabled AI, empty AI, and legacy
  snapshots at 1440, 390, and 320 pixel widths. All API requests are intercepted;
  no real credentials, database writes, or external AI calls are used.
- Screenshots are written only to `/private/tmp/securedeploy-result-*.png`.
- Run the backend test suite with template mode and external smoke flags disabled.

## Limits

Phase 5 now supplies saved `riskSummary` and `comparisonAvailable` in history.
History uses that summary without inferring deployment readiness from the legacy
score; older entries without it remain unassessed. Open a result for full details.
Backend and AI explanations can still contain technical language; the UI groups
and labels the supplied facts but does not invent a plain-language diagnosis.
The core problem lists paginate at six items; legacy technical lists and optional
AI tools can still be long. Rescanning and progress are documented separately in
`phase5-security-progress.md`; presentation does not introduce a new security policy.
