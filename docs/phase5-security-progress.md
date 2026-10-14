# Phase 5: Re-scan / Security Progress

## Product contract

Analysis -> understand -> fix -> re-scan -> inspect improvement. Stored risk-based
deployment assessments lead the before/after view; the legacy score is only a
reference. A newly observed issue is not proof that the user's edit caused it.
No scoring formula, detector, false-positive policy, threat-intelligence policy,
or semantic candidate promotion policy is changed by comparison.

## Existing model and re-scan

User -> Project -> independent Review snapshots is retained. Result details now
include sourceType, repositoryUrl and createdAt. The existing project-scoped
POST endpoints create new reviews and verify ownership and source type. GitHub
re-scans must target the registered repository (optional .git suffix and case
differences allowed); each invocation clones fresh. ZIP re-scans require a new
upload, and an explicitly supplied projectId prevents renamed archives from
creating a different project. The existing finally-based workspace cleanup
continues to remove uploaded/cloned source. No ZIP archive is retained.

## Snapshot lifecycle

Two nullable TEXT columns are added to reviews:

- comparison_context_json: coverage version, previous review ID, successful rule
  scan flag and relative analyzed file paths. No source content or raw secret.
- comparison_snapshot_json: schema version, fixed baseline/current IDs and dates,
  before/after risk summaries, canonical finding changes, independent AI changes,
  counts, generation time and limitations. Existing masked evidence is copied.

The project row is locked only while selecting the baseline and saving a review;
network/AI work is outside that transaction. Ordering is createdAt then id.
After remediation and semantic snapshots finish, a conditional update writes the
comparison only when NULL. GET and history never regenerate it. A failed process
between review persistence and finalization can leave a NULL comparison, which is
shown as unavailable; there is no automatic background repair in this phase.

Deletion does not cascade through the baseline ID (it is a snapshot reference,
not an FK). Deleting a baseline does not rewrite an already stored comparison.
The latest-comparison legacy endpoint refuses to silently rebase if the remaining
previous review differs. Legacy reviews retain NULL snapshots and no inferred
resolved findings. Dashboard and AI comparison reuse the stored comparison;
AI interpretation requires COMPLETE comparison coverage.

## Matching and negative evidence

Only canonical RiskAssessment codeFindings and dependencyFindings participate.
Legacy dependency candidate correlations are not re-counted. Analysis coverage
requirements and AI candidates are not deterministic issue-resolution counts.

- Code/config identity: ruleId, slash-normalized case-sensitive relative paths,
  whitespace-normalized masked evidence, SHA-256 fingerprint. Line is excluded.
- Dependency identity: ecosystem, package, intersecting advisory/alias sets and
  manifest paths. Unique matches can cross versions and are then CHANGED.
- AI identity: candidate type plus file/function context, independent of line.

Unique positive matches become REMAINING or CHANGED (priority, severity,
confidence, false-positive risk, dependency version or fixed versions changed).
Duplicate masked anchors are ambiguous and become UNAVAILABLE, not collapsed.

RESOLVED requires compatible coverage schemas, analyzer bytecode fingerprints,
risk policy versions, completed rule scans and the same analyzed file paths.
Dependency absence additionally requires complete SCA on both sides, complete
lookup counts, no unresolved versions and no warnings. Lookup outages, missing
files, unsupported files, absent historical coverage, changed analyzers and
ambiguous matches cannot establish resolution. NEW uses the corresponding
baseline coverage check. Failure is not absence. A code-only review without SCA
can still resolve covered code findings but the overall comparison is PARTIAL.

Analyzer fingerprints include compiled rule, false-positive, dependency and
project/service classes. If analysis behavior is changed by external configuration
or helpers outside these packages, bump the collector coverage contract version.
This intentionally conservative fingerprint may invalidate comparisons after a
non-behavioral code change. It is not a semantic-equivalence proof.

## AI and external knowledge

AI disappearance is NOT_REOBSERVED only when both AI reviews completed, neither
omitted slices, prompt/model match and the current slice contains the old
file/function context. Otherwise it is UNAVAILABLE. AI changes never change
securityScore, severity, priority, blocking count, deterministic deployment or
resolved count. Deterministic counts and AI counts remain separate in the UI.

Updated advisories, EPSS or KEV may change priority without a source edit.
CHANGED represents observation changes, not proof of a successful remediation.
Current fixed versions are advisory suggestions, not a guarantee of safety.

## UI and API

Review details return comparison; global/project history return riskSummary and
comparisonAvailable. Result navigation includes changes, and history has a saved
changes action. The UI shows before/after deployment, required actions, review
requirements and recommended fixes first. Score, CVE, confidence, fingerprints,
evidence and raw messages remain in technical disclosures. Remaining/new issues
reuse the current review's saved remediation; resolved issues do not suggest
reapplying old advice. Old data never receives fabricated zero-risk defaults.

Docker/Kubernetes findings have rule-specific plain-language titles with technical
locations and original messages preserved. This is presentation only.

## Migration and verification

Run with a schema-owning development DB role:

```sh
psql -d securedeploy -v ON_ERROR_STOP=1 -f src/main/resources/db/postgresql/phase5-review-progress.sql
gradle test
cd frontend
npm test
npm run build
```

The migration is additive/idempotent and does not backfill old reviews. PostgreSQL
application was verified twice; pre/post row counts and content checksums were
identical for existing reviews, vulnerabilities, snippets and SCA snapshots.

Unit tests cover code resolution, new/remaining findings, line moves, ambiguous
anchors, missing/failed analyzer coverage, SCA failure, advisory aliases, versions,
legacy NULLs, AI disappearance and converter round trips. MockMvc tests cover
signup, modified ZIP names, same-project GitHub clones, ownership, repository
rejection, history, snapshot immutability and baseline deletion. External clients
are mocked; there are no paid OpenAI calls. Browser tests cover 1440/390/320px,
navigation, disclosures, rescan failure retention and a recorded MockMvc response.

## Limitations and future collaboration

No data-flow/reachability or code-equivalence analysis. Renamed/deleted files and
changed evidence may be UNAVAILABLE even after a valid fix. Multiple instances
with the same masked anchor or advisory/version/module ambiguity need manual
review. Full source is not retained to disambiguate them. Comparisons are not
arbitrary user-selected baselines. Concurrent analyses use persistence ordering;
if the preceding analysis has pending AI work, AI comparison remains unavailable.

Ownership stays on Project, and mutable vulnerability workflow status/comments
remain separate from immutable scan observations. Future team authorization and
audit events can attach to project/review/finding IDs without mutating historical
security facts. Auto-closing/reopening workflow status is deliberately not added.

The user approved packaging Phase 5, result UX and safe large uploads as one
milestone on 2026-10-14.

## Development verification record (2026-10-13)

- Backend: 213 tests, 210 passed, 3 opt-in external smoke tests skipped, 0 failures.
- Frontend: 38 tests passed; TypeScript/Vite build and git diff --check passed.
- Mock browser: existing result flows and Phase 5 at 1440/390/320px passed.
- Live local browser + PostgreSQL: login, STANDARD ZIP upload, renamed modified
  ZIP to the same project, comparison storage/detail/history replay passed.
  Result: RESOLVED 1, REMAINING 1, COMPLETE. Semantic requests: 0.
- GitHub project-scoped re-scan verified with a mocked clone, not a live remote.
- Development backend restarted on port 8080 with its existing environment.
- Migration repeated twice. After live test cleanup, original counts/checksums
  remained unchanged: 7 reviews, 119 vulnerabilities, 19 snippets, 3 SCA reports.
- Temporary local account/project removed; no auth values written to test files.

## Milestone verification (2026-10-14)

- Full backend suite rerun without task-cache reuse: 245 tests, 242 passed,
  3 opt-in external smoke tests skipped, 0 failures/errors.
- Frontend: 41 tests passed; TypeScript/Vite production build passed.
- External smoke flags were explicitly disabled; no paid OpenAI calls were made.
- The comparison migration is included. Runtime DB contents, personal environment
  files, generated ZIPs, logs, build output and generated build-cache changes are
  excluded from the milestone.
