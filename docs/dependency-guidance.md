# Dependency guidance and supplemental lookup

## Evidence and presentation

`VersionClassifier` stores `<unresolved-package>` when a declaration cannot be
resolved to valid registry coordinates. For example, Gradle aliases or project
references reach `GradleManifestParser.OTHER` without a literal name/version.
This is an analysis limitation, not a confirmed vulnerable package. Parsers and
RiskPrioritizationEngine remain unchanged.

Development DB inspection on 2026-10-15 found three stored component occurrences
with MAVEN ecosystem, unresolved identity and missing version in the same Gradle
manifest path. The inspection was read-only; no source content or credentials
were selected.

The shared ZIP/GitHub result UI distinguishes confirmed advisories, known names
with unresolved versions, and unknown names. It exposes actual manifest locations,
explicitly marks missing information, and provides Maven/Gradle/npm-specific
verification steps. Internal sentinel values are not displayed. Fixed versions
come only from stored OSV evidence, without treating them as universally safe or
compatible. Incomplete findings use evidence-based instructions rather than
repeating old generated advice or inventing coordinates, versions or advisories.

## Optional lookup

`POST /api/reviews/{reviewId}/dependencies/supplemental-lookup`

Request: `findingId`, `packageName`, `version`.
Only an owned review's saved `UNRESOLVED_VERSION` dependency finding is eligible.
The ecosystem comes from that finding, not user input. Known package names cannot
be changed. Length limits are 1024/256/128 characters respectively; registry name
syntax and exact version validation reuse `VersionClassifier`. URLs, scripts,
dynamic versions and ranges cannot be queried.

The service reuses `VulnerabilityDataSource` / `OsvClient`: fixed endpoint,
structured JSON, bounded requests, timeouts, response size and advisory limits.
Additional process-local limits: one concurrent request per user, four globally,
six per user per minute and a bounded 10,000-entry window map. These limits are
not shared across server instances. SCA-disabled mode does not make requests.
No user input or upstream body is logged.

The response is `Cache-Control: no-store` with `provenance=USER_PROVIDED`, the
queried identity, timestamp, advisories and `COMPLETE`, `PARTIAL`, `UNAVAILABLE`
or `DISABLED` status. A completed zero-result lookup is not a safety guarantee.
Failures retain uncertainty; partial advisories do not imply complete coverage.

No entities are written, no snapshot is attached, and no risk engine is called.
The UI keeps the response in local component state, clears it when input changes,
and does not merge it into Review/Risk/History. Navigating away can discard this
optional result. Source edits and a rescan are required for official changes.

## Compatibility and limitations

- No DB/schema/migration change. Existing snapshots remain immutable.
- Old unresolved SCA records without a saved risk finding still have guidance,
  but require a rescan before the supplemental API is available.
- This does not execute builds, resolve all Gradle/Maven inheritance, verify the
  user's actual installed version, prove reachability or broaden SCA coverage.
- Risk policy, deployment assessment, threat intelligence, comparison snapshots
  and AI execution permissions are unchanged. No new AI generation call exists.
- No live OSV/OpenAI/GitHub calls are required for this milestone's verification.

## Verification

Backend integration tests cover successful supplemental advisories, full Review
and stored Risk JSON immutability, invalid inputs, wrong owners, authentication,
unresolved Gradle identity, empty results, upstream failure, partial results and
request limits. Remediation grounding tests retain deterministic version bounds.

Frontend tests cover missing information, fixed-version evidence, legacy advice,
escaped text, status semantics and shared ZIP/GitHub rendering. The intercepted
Playwright scenario `frontend/tests/browser/dependency-guidance.cjs` covers the
form and errors at 1440, 390 and 320 pixels without external API requests.
