# Phase 3: deterministic risk prioritization

## Purpose and flow

Rule Engine -> FalsePositiveAnalyzer -> existing score/status
and static SCA -> persisted vulnerabilities -> RiskPrioritizationEngine
-> RiskPolicy -> immutable review snapshot -> detail API and result UI.

Severity describes technical impact. Priority is a policy decision about the next
action. The engine performs no network lookup and never executes uploaded code.
All decisions carry a stable reasonCode and a Korean priorityReason.

The current policy version is risk-v1.1 (snapshot schema 2). New reviews use the active policy; GET does
not reinterpret historical reviews with the current policy. Changes to policy
must use a new version and do not silently rewrite saved decisions.

## Code policy

Missing confidence, falsePositiveRisk, severity or a nonblank analysisNote yields
REVIEW_REQUIRED. Low confidence or high false-positive risk also requires review,
including placeholder findings already downgraded to LOW by the existing filter.
An analysis note's presence is a completeness signal, not proof that a key is valid.
The policy does not parse free-form analysis notes to establish credential validity.

Only these allowlisted credential rules can BLOCK with HIGH/CRITICAL severity,
HIGH confidence and LOW false-positive risk:
HARDCODED_PASSWORD, HARDCODED_SECRET, HARDCODED_FRONTEND_SECRET, DOCKER_SECRET_ENV.
This calls for pre-deployment verification and remediation, not a claim that a
credential has been authenticated with its issuer.

GITHUB_ACTIONS_SECRET_ECHO is an explicit configuration policy that can BLOCK at
MEDIUM or above with HIGH confidence and LOW false-positive risk. It demonstrates
priority escalation without modifying severity.

DANGEROUS_SQL, PERMIT_ALL_USAGE, CORS_WILDCARD, REACT_DANGEROUS_HTML,
UNVALIDATED_REDIRECT, EXPOSED_ACTUATOR and K8S_SECRET_PLAIN_TEXT require context.
They do not automatically block on HIGH confidence: the present analyzers confirm
a pattern, not data flow, external exposure or exploitability. Legacy built-in
VULNERABLE_NPM/MAVEN/GRADLE_DEPENDENCY rules remain review candidates unless they
are correlated as supplemental evidence under the dependency identity policy below.

Other high findings with uncertain metadata require review; remaining findings
default to SHOULD_FIX, except reliable LOW findings, which are INFORMATIONAL.
WEAK_JWT_SECRET therefore defaults to SHOULD_FIX: its current short/simple-string
heuristic alone is not treated as proven authentication bypass.

## Dependency policy

An OSV advisory must join an exact component version in the saved SCA inventory.
The current snapshot has global lookup completeness, not per-component completed
lookup IDs. The policy conservatively requires COMPLETE, no warnings, all exact
versions and consistent discovered/analyzed counts before confirming lookup.
PARTIAL does not establish confirmation even for a returned advisory; it requires
review until finer-grained lookup provenance is available.

For confirmed exact versions:
- CRITICAL: BLOCKING
- HIGH / MEDIUM: SHOULD_FIX
- LOW: INFORMATIONAL
- Unknown severity without a valid numeric CVSS: REVIEW_REQUIRED

A numeric CVSS in [0,10] may raise the effective severity used by the policy, never
lower a known severity. Vectors are not calculated in this phase. Neither direct
nor transitive status, test/dev scope nor the absence of a fix reduces priority.
Those facts (nullable directness, scopes, fix availability, CVSS) are saved for
explanation and future policies. Fixed versions are advisory candidates, not a
guarantee of a safe compatible upgrade.

Unresolved versions produce deduplicated package/version review items with source
locations. Missing, disabled, no-manifest, failed or partial SCA adds an ANALYSIS
review item. This coverage item is separate from vulnerability counts.

## Dependency identity and provenance

DependencyRuleMatchFactory attaches structured DependencyObservation data (source,
ecosystem, package, version, optional advisory ID). False-positive filtering preserves
it. ReviewPersistenceService binds the saved vulnerability IDs and the engine stores
correlations in the risk snapshot. Free-form evidence/messages are never parsed to
guess package or vulnerability identity. Old observations are not backfilled.

DependencyFindingCanonicalizer groups only identical ecosystem/package/version
coordinates with shared explicit advisory IDs/aliases. CVE is preferred as canonical
ID, followed by GHSA and then provider ID. Alias bridges are supported. Distinct
versions, packages and unrelated advisory IDs remain independent. Locations, IDs,
fix candidates and references are unioned; the strongest severity/CVSS is retained.
Additional providers must map trustworthy IDs/aliases into the normalized model.

DependencyFindingCorrelator normalizes Gradle/Maven to the Maven ecosystem. Only
exact versions and completed matching SCA can absorb a catalog observation:
- A known matching advisory ID becomes SAME_ADVISORY provenance.
- A catalog candidate without a CVE becomes PACKAGE_CANDIDATE_CONTEXT. This is a
  package-level signal, not an assertion that it is the same individual CVE. Its
  original ID/location/source is retained, but it is not a second actionable issue.
- Repeated observations from the same catalog/package/version/advisory, such as
  pom.xml and build.gradle declarations, are counted once with original locations.

Different known CVEs, failed/partial lookups, missing provenance, version mismatch,
unresolved versions and candidates with no matching SCA findings are not absorbed.
Other rules such as risky package scripts, Docker policy and source-code risks are
not collapsed merely because they occur in the same manifest.

Legacy vulnerabilities, vulnerabilityCount, raw sca findings and rule scores remain
unchanged for API compatibility. The authoritative risk/deployment summary and the
default UI use riskAssessment's canonical findings. Correlated code observations
are shown once in a supplemental evidence disclosure, not as duplicate issue cards.
This preserves old status records and provenance without treating a package heuristic
as an additional confirmed CVE. Clients seeking deduplicated issues must use the
risk snapshot, not sum legacy Rule Engine and raw SCA counts.

## Overall assessment and completeness

Precedence: BLOCKING -> BLOCKED; otherwise REVIEW_REQUIRED -> REVIEW_REQUIRED;
otherwise SHOULD_FIX -> READY_WITH_WARNINGS; otherwise READY.
Only completed supported Rule Engine and SCA analysis can yield READY.
READY is not proof of deployment safety or complete runtime dependency coverage.

Coverage reports ruleEngine, sca and ai separately. The engine runs only after
successful Rule Engine execution and persistence; scanner/rule failures abort the
scan and do not manufacture a READY review. SCA UNAVAILABLE is FAILED, absent SCA
is UNKNOWN, disabled is NOT_INCLUDED, and other incomplete cases are PARTIAL.
Overall is PARTIAL when required SCA is incomplete. AI is always NOT_INCLUDED.

Counts use canonical package/version/advisory items plus code risks and analysis
requirements. A CVE affecting two versions/packages counts separately; separate
unknown-coverage requirements are not themselves CVEs.
prioritySummaryBySource separates CODE, DEPENDENCY and ANALYSIS. Finding category
separately identifies CODE, SECRET, DEPENDENCY, CONFIG, CONTAINER, IAC and CI_CD.

## DB and API compatibility

Apply src/main/resources/db/postgresql/add-review-risk-assessment.sql before a
managed/validate deployment. It adds nullable reviews.risk_assessment_json TEXT.
No data backfill, destructive migration, enum DDL or score update is performed.
Development ddl-auto=update can create the column. Review deletion removes the
snapshot with the same row. Existing rows remain NULL and need a new scan.

SecurityReviewResponse adds nullable riskAssessment containing schemaVersion,
policyVersion, assessedAt, prioritizedDeploymentAssessment, assessmentReason,
assessmentCoverage, prioritySummary, prioritySummaryBySource, codeFindings,
dependencyFindings, dependencyCorrelations and reviewRequirements. Each finding includes priority,
priorityReason and reasonCode. CODE entries reference the saved vulnerabilityId;
dependency entries reference ecosystem/package/version/advisoryId.

The old securityScore, deploymentStatus and deploymentAssessmentScope=
RULE_ENGINE_ONLY remain unchanged. riskAssessment.assessmentScope is
RULE_ENGINE_AND_SCA and its coverage describes the actual completed scope.
assessmentInterpretation declares the primary risk assessment path, availability,
RULE_ENGINE_REFERENCE_ONLY score role, legacy status role, and
securityScoreDeterminesDeployment=false. Missing risk assessment requires rescan;
it never falls back to treating a high numeric score as deployment approval.
No controller or UI recalculates priorities. Status updates do not alter the
scan-time snapshot; marking RESOLVED/IGNORED is not verification by a rescan.

## UI and validation

The risk assessment appears above the neutral reference score/status metrics as the
primary deployment decision. Counts, analyzer coverage and review requirements are
visible, and existing rule and canonical SCA cards show priority and reason.
Missing assessment never gets a default READY or INFORMATIONAL. Severity filtering,
AI tabs, history, scores and PDF retain their existing contracts.

Tests: gradle test; frontend npm test; frontend npm run build.
Policy tests cover uncertainty, contextual patterns, escalation, CVSS, partial
lookups, missing versions/metadata, nullable directness and assessment precedence.
MockMvc covers ZIP, mocked-clone GitHub, auth/ownership, snapshot reload, legacy
NULL rows, code IDs, status updates, score invariance, AI summary and basic PDF.

Validated on 2026-10-07: backend 102 passed, one opt-in OSV smoke test skipped;
frontend 11 passed and production build succeeded. This includes 36 policy cases,
14 dependency identity cases and eight SCA/Risk API integration tests. Live E2E
used the restarted development backend, PostgreSQL, real OSV and template AI:

| Input | Legacy score | Risk assessment |
| --- | --- | --- |
| Empty dependency manifest | 100 | READY |
| debug=true with completed SCA | 93 | READY_WITH_WARNINGS |
| react ^18.0.0 unresolved | 100 | REVIEW_REQUIRED |
| Fake placeholder password | 97 | REVIEW_REQUIRED |
| Multiline log4j-core 2.14.1 manifest and a synthetic secret | 72 | BLOCKED |
| lodash 4.17.10 + minimist 1.2.0 | 79 | BLOCKED |

The log4j sample returned seven OSV findings including CVE-2021-44228. The snapshot
contained three BLOCKING items (two dependency advisories and one code finding)
and five SHOULD_FIX items. Its separate built-in Maven candidate remained in the
raw rule data but was supplemental evidence, not a ninth priority item. The npm
sample's two catalog candidates were similarly correlated; only nine canonical
OSV risks were counted (two BLOCKING, seven SHOULD_FIX). Results are time-dependent
as OSV data changes. Multiline manifests intentionally exercise the legacy parsers;
their existing limitations were not broadened into a parser rewrite in this phase.
Live login, ZIP, reload/history, AI template summary and basic PDF passed.
Playwright exercised all four states, reasons, missing-version details, severity
filters and desktop/mobile layout using actual API responses, not fixture responses.

The PostgreSQL migration was permanently applied, including repeated application
inside a transaction with data-fingerprint checks. Existing users (2), projects (9),
reviews (12), vulnerabilities (203), snippets (68) and SCA reports (0 at baseline)
were preserved. The new column is nullable TEXT; the 12 old reviews remain NULL.
Live PostgreSQL snapshot save/reload and simulated legacy-null detail API behavior
were verified. The backend restarted with its existing JWT/API environment preserved.
After verification, the seven temporary E2E projects and their test account were
removed. Counts and row fingerprints across all six baseline tables matched the
original data, and the temporary authentication state file was deleted.

## Follow-up boundaries

EPSS, KEV, reachability, exposure and business criticality are not inferred or
fetched. They can be added as structured, provenance-bearing policy inputs alongside
DependencyFacts, with a versioned policy and a new snapshot schema where needed.
RiskPolicy is the replacement point; RiskPrioritizationEngine owns orchestration,
coverage and summaries. Historical snapshots remain reproducible.

No score formula, AI remediation, CI gate, automatic fix, project dashboard priority
aggregation or priority PDF output is introduced in this phase. Additional manual
policy calibration and per-component OSV provenance are the main next steps.
