# SecureDeploy Phase 2: static SCA

## Architecture

ZIP/GitHub -> ProjectScanner -> Rule Engine -> FalsePositiveAnalyzer -> existing score
and, separately, ScaManifestCollector -> exact versions -> VulnerabilityDataSource
-> OsvClient -> ScaResult -> ReviewScaEntity -> review detail JSON -> DependencySecuritySection.

The common SecurityReviewFacade path invokes SCA before ReviewPersistenceService opens
its save transaction. An OSV failure produces UNAVAILABLE/PARTIAL and does not fail
the rule analysis. SCA findings do not modify vulnerabilityCount, securityScore,
deploymentStatus, vulnerability status management, AI inputs or PDF output.
Existing built-in dependency candidate rules remain in the legacy rule list and score.

Uploaded files are data only. The SCA packages never launch Gradle, Maven, npm,
lifecycle scripts, executables, plugins, or subprocesses. No parent POM, remote BOM,
repository, URL dependency, or XML external entity is downloaded during parsing.
The only external requests are package/version queries and advisory detail reads
to the fixed https://api.osv.dev origin. Source files and snippets are not sent.

## Packages

- sca/model: internal DependencyComponent, DependencyVulnerability, ScaResult,
  ScaEcosystem and VersionResolution; no OSV DTO leaks into the application model.
- sca/parser: MavenManifestParser, GradleManifestParser, NpmManifestParser,
  VersionClassifier, ScaManifestCollector.
- sca/client: VulnerabilityDataSource, OsvClient, OsvAdvisoryMapper, OsvSeverityMapper.
- sca/service: ScaService orchestrates parsing and lookup and derives summary.
- sca/config: ScaProperties and dedicated HTTP client configuration.
- sca/persistence: ReviewScaEntity, ScaResultConverter.

## Supported manifests and coverage

| Manifest | Static support | Limits |
| --- | --- | --- |
| pom.xml | Namespace-aware XML, direct dependencies, scope, bounded local property substitution | Parent/BOM/remote properties, dependencyManagement resolution, profiles and transitive resolution are not executed. Missing versions remain unresolved. Profiles produce a coverage warning. |
| build.gradle / build.gradle.kts | Literal string coordinates, common configurations, simple Groovy map notation, comments ignored | Arbitrary DSL, function calls, catalogs, calculated versions are not evaluated. Unsupported dependency expressions remain unresolved where recognized. |
| gradle.lockfile | group:artifact:version=configuration list | No resolved dependency graph; directness is unknown for lock-only entries. Matching declarations use locked versions within the same directory. |
| package-lock.json | v2/v3 packages including nested dependencies; root/workspace declarations identify direct packages | Linked/non-registry entries remain unresolved. No lock v1, yarn/pnpm OSV parser yet. |
| package.json | dependencies/devDependencies/optionalDependencies/peerDependencies | Only exact literal SemVer is queried. Ranges, tags, workspace/Git specs are not queried. Sibling lock takes precedence; missing locked declarations remain unresolved. |

Maven and Gradle use OSV ecosystem Maven and groupId:artifactId.
npm uses ecosystem npm and the package name (including scope).
EXACT means statically known declaration/lock version, not runtime installation verification.
RANGE and UNRESOLVED are retained for review. URL specs are replaced with a neutral
marker so embedded credentials are never persisted or sent.
JSON/XML location line 0 means unavailable; Gradle lines are one-based.

## OSV behavior

Official references:
- https://google.github.io/osv.dev/post-v1-querybatch/
- https://google.github.io/osv.dev/get-v1-vulns/
- https://ossf.github.io/osv-schema/

querybatch returns IDs/modified only. The client batches up to 100 distinct
ecosystem/package/version coordinates, follows per-query page tokens, then fetches
details once per advisory ID within an analysis. Findings deduplicate by
ecosystem/package/version/OSV ID and preserve all manifest source locations.

Details retain aliases (CVE/GHSA where present), summary, affected-package fixes,
published/modified, references and CVSS vectors. Withdrawn advisories are skipped.
Only matching-package, non-GIT fixed events are included; these are branch-specific
advisory fix candidates, not a computed universally safe upgrade version.

Severity mapping uses explicit numeric CVSS scores when present, then OSV database
severity labels (MODERATE -> MEDIUM). A CVSS vector alone is preserved but not
calculated in v1. Missing scores/severity remain null and display as unknown.
Neither a failed lookup nor unknown severity is treated as LOW/safe.

Default limits:
- 100 manifest files, 2 million characters per manifest, 5000 component locations.
- 500 distinct version queries, 100 unique advisory detail requests.
- Batch size 100; at most 50 total HTTP requests and 2000 returned findings.
- 2 MB per HTTP response; 5-second connect/read timeouts.
- 30-second request scheduling budget (an in-flight connect/read can finish later).
- No retries or cross-request cache in v1.

The securedeploy.sca properties in application.yml can be overridden with standard
Spring environment variables, e.g. SECUREDEPLOY_SCA_ENABLED=false.
Normal tests disable SCA by default; SCA integration tests explicitly enable it and mock
the provider. No OpenAI call or payment is required.

## Persistence and API

Review 1:1 ReviewScaEntity (cascade + orphan removal). The new review_sca_reports table
stores an internal JSON snapshot in a PostgreSQL TEXT column, with schemaVersion=1.
This review-scoped snapshot keeps dependencies, sources, unresolved inventory, findings,
status and summary together without forcing dependency findings into VulnerabilityEntity.
Old reviews have no row and return sca: null. Review/project deletion removes the snapshot.
No old review data or score is rewritten.

Development ddl-auto=update creates the new table. For managed/validate environments,
apply src/main/resources/db/postgresql/add-review-sca-reports.sql before startup.
The migration is additive/idempotent. Automated persistence tests use H2.
Development rollout also verified this migration on populated PostgreSQL:
existing table row counts and content fingerprints were unchanged, repeated application
was safe, and live ZIP/OSV/detail/history flows persisted SCA snapshots successfully.

POST upload/GitHub and GET /api/reviews/{id} add a nullable sca field:
- schemaVersion, status, analyzedAt
- summary: dependenciesDiscovered, dependenciesAnalyzed, unresolvedDependencies,
  vulnerableDependencies, dependencyVulnerabilities, severityCounts
- components: identity, scope, nullable direct flag, resolution, sourceFile/line
- dependencyVulnerabilities: normalized advisory data and sourceFiles
- warnings: coverage/availability notes

The response also declares deploymentAssessmentScope=RULE_ENGINE_ONLY. The UI labels
the legacy score/assessment accordingly and shows a prominent notice when SCA is
incomplete or has findings. The numeric score and deploymentStatus values stay unchanged.

Counts are distinct package+version identities; findings are package+version+OSV ID.
dependenciesAnalyzed counts completed paginated package queries; missing advisory
details still force PARTIAL. Unknown severities are counted as UNKNOWN.

Statuses: COMPLETE, PARTIAL, UNAVAILABLE, NO_MANIFEST, DISABLED.
COMPLETE means the supported static inventory was processed, not that all runtime
dependencies or code paths are known or safe.

The frontend keeps the existing rule section and adds Dependency Security with
package/version, ID/aliases, severity, summary, fix candidates, sources, summary counts,
warnings and an expandable unresolved inventory. Historical/missing/partial results
have explicit states. Advisory text is rendered as text and reference links are restricted
to HTTP(S). The panel states that SCA has not yet been incorporated into deployment scoring.

## Validation

Run only in the SecureDeploy repository, never in an uploaded project:
- gradle test
- cd frontend && npm run test:sca
- cd frontend && npm run build

Optional real API smoke test:
SCA_OSV_SMOKE=true gradle test --tests com.securedeploy.sca.OsvSmokeTest --rerun-tasks

src/test/resources/sca contains data-only Maven/Gradle/npm fixture manifests.
They are not build inputs and no vulnerable package was installed in SecureDeploy.

Tests cover static parsing, local properties, XXE rejection, unresolved ranges,
lock precedence, direct/transitive flags, OSV batching/pagination/detail dedup,
timeouts/rate limits/malformed JSON, severity/null handling, score invariance,
authenticated ZIP/GitHub common pipeline, history round-trip and review/project deletion.
React render tests cover partial results, old reviews, escaped text and unknown severity.

## Next phase

Risk Prioritization can use ecosystem/package/version, directness, scope, version
resolution, advisory aliases, severity/CVSS, fix candidates, locations, lookup status
and timestamp. Reachability, deployment impact and blocking decisions remain absent.

Before cross-project SQL analytics, split the versioned snapshot into queryable
component/finding tables (or a JSONB projection). Other follow-ups: robust Gradle AST
and catalog parsing, parent/BOM metadata without execution, additional lock formats,
CVSS vector scoring, and broader multi-module/workspace fixtures.

This is an end-to-end Phase 2 milestone. It does not claim complete dependency
resolution or that a zero-result scan proves deployment safety.
