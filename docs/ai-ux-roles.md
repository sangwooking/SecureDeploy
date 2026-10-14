# AI review and remediation experience

## Roles and decision authority

- AI-enhanced analysis remains an explicit scan-time choice. Semantic candidates
  are shown as additional items to verify before deployment, not vulnerabilities
  confirmed by AI. Empty, failed, disabled and unsupported-context states remain
  distinct. STANDARD does not acquire an AI generation call through navigation.
- AI solution guidance uses the saved Phase 4A remediation snapshot. One panel
  selects an exact `findingId`; it never joins advice by a shared rule name.
- AI detail explains one finding: what it means, possible impact, what to check,
  what to change, saved examples and verification followed by a same-project rescan.
  Template, generated, unavailable and missing results keep their provenance.

Project Security Summary reads `prioritizedDeploymentAssessment` and
`prioritySummary` directly from the backend snapshot. Finding order follows backend
priority, not severity or an AI-generated ranking. AI candidate counts are shown
separately. No score, priority, confidence or deployment decision is recalculated.

Review-required and low-confidence/high-false-positive explanations start with
verification, not an assertion that an exploit exists. Semantic manual checks use
owned test accounts/data and an authorized test environment. Original AI opinions
and source locations remain available inside Technical Information. Masked evidence
is rendered as text; the client never attempts to restore credential values.

## UI consolidation and preserved call paths

| Previous UI | Current surface |
| --- | --- |
| Per-vulnerability AI review | One finding's AI detail / saved remediation |
| AI summary | Backend-driven Project Security Summary |
| AI remediation | Saved AI solution guidance |
| Old AI audit | Scan-time Semantic Review candidates |
| AI priorities | Backend priority and stored reason only |
| AI roadmap | Verify, fix, test and rescan guidance |
| AI comparison generation | Saved Phase 5 progress comparison |

No backend code, DTO, persistence, migration, rule or risk policy changed.
The analysis facade still saves the review, completes remediation, semantic review,
and progress snapshots in the existing order. History reads the same snapshots.
Provider fallback, structured output validation, evidence validation and masking
remain in those existing backend paths.

Legacy `/ai-review`, `/ai-summary`, `/ai-remediation`, `/ai-audit`, `/ai-priorities`,
`/ai-roadmap` and comparison insight APIs remain compatible, but the result UI no
longer requests them. Their frontend API exports are retained for compatibility.

Both PDF endpoints remain available. The legacy `/report/ai` implementation calls
`AiReviewService.generateReview` and can incur a new external request. Its button
requires explicit confirmation of this before calling the endpoint. It is not an
export of the saved Phase 4A remediation/semantic snapshot. Basic PDF is unchanged.

## Validation

- `gradle test --rerun-tasks` with `AI_PROVIDER=template` and external smoke flags
  disabled: existing backend regression suite, no real OpenAI calls.
- `npm test`: includes strong/uncertain secret language, manual semantic checks,
  incomplete SCA, honest generation provenance, exact identity and escaped output.
- `npm run build`: TypeScript and Vite build.
- `tests/browser/result-workspace.cjs`: mocked login/history, ZIP/GitHub modes,
  disclosures, selector isolation, no legacy AI requests, unchanged assessment,
  empty/disabled/legacy results, status management, PDF dispatch/cost confirmation.
- `tests/browser/review-progress.cjs` and `zip-upload.cjs`: existing workflow tests.
- Browser viewports: 1440, 390 and 320 pixels. All API requests are intercepted;
  screenshots remain in `/private/tmp`, not Git. No real account or DB writes.

## Limits

- Plain-language type-based checks are general guidance, not new analysis or a
  translation of every possible model statement. Unknown types use cautious
  generic checks; original model text remains accessible for detailed review.
- Saved model guidance and code examples still require developer validation.
- Historical reviews without snapshots show basic guidance, not invented AI output.
- No new AI generation, remediation regeneration or saved-snapshot PDF export was
  implemented. Legacy paid generation APIs still exist for compatible clients.
- This milestone helps users act on existing evidence without adding a competing
  deployment judgment or a second source of security priorities.
