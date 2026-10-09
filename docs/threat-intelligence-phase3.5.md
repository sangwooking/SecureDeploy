# Phase 3.5: threat intelligence enrichment

## Flow and boundaries

Static SCA -> explicit CVE identifiers -> ThreatIntelligenceService -> FIRST EPSS
and CISA KEV clients -> immutable intelligence snapshot -> RiskPrioritizationEngine
-> versioned deterministic policy -> review transaction -> detail API/UI.

SecurityReviewFacade enriches the SCA result before ReviewPersistenceService opens
its save transaction. RiskPrioritizationEngine has no HTTP client. Both source
failures are contained independently; OSV/Rule Engine results can still be saved.
The existing score formula, severity, legacy deployment status, AI and PDF contracts
are unchanged. No uploaded build or script is executed.

Only syntactically valid, explicit CVE IDs in the advisory ID or aliases are used.
There is no CVE guessing from descriptions, package names or OSV-only identifiers.
Lookups deduplicate CVEs across components; priority still uses Phase 3 canonical
component/version/advisory identities. Separate issues remain separate.

## Official sources

- FIRST endpoint: https://api.first.org/data/v1/epss
- FIRST API reference: https://api.first.org/epss/
- EPSS interpretation: https://www.first.org/epss/articles/prob_percentile_bins
- CISA catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The clients use fixed official HTTPS endpoints, no key, no alternate mirrors and
no redirects. Only CVE IDs are sent to FIRST; CISA receives a catalog GET. Source
code, credentials and project identities are not transmitted to these sources.

FIRST's cve parameter permits 2,000 characters including commas. Requests use at
most 1,900 characters and 100 CVEs, with an explicit response limit. The default
scan cap is 300 CVEs. Missing returned CVEs are NOT_FOUND, never probability zero.
Score and percentile must be finite numbers within [0,1], with a valid date and
matching CVE identity. Truncated/malformed batches are unavailable.

CISA is downloaded once per cache refresh and indexed in memory. Count, unique
CVE IDs and release timestamp validate catalog completeness before negative lookup
is allowed. Optional per-entry metadata may be absent. Catalog version, release
time, dateAdded, requiredAction, dueDate and ransomware information are preserved.
An empty, truncated or regressed catalog cannot overwrite a valid cached catalog.

## Cache, resource limits and freshness

Both caches have a default six-hour TTL and a 60-second failure backoff. EPSS also
refreshes after the UTC fetch date changes; data older than two days is STALE.
The EPSS cache is bounded at 5,000 CVEs. KEV keeps one validated catalog per process.
Synchronized refreshes avoid simultaneous downloads within one application process.
There is no cross-instance shared cache or persistence of cache state.

HTTP connect/read timeout defaults to five seconds. EPSS starts no further batches
after its 20-second budget; an already-started request can finish within its timeout.
CISA has a separate single-request timeout. Responses are capped at 1 MB (EPSS)
and 15 MB (KEV), with at most 50,000 KEV entries. Bounds can cause an explicit
unavailable/partial result as the sources grow, not a false clean result.

On refresh failure, cached evidence retains its original fetchedAt and becomes
STALE. A cached KEV positive remains evidence of previously confirmed exploitation.
A stale catalog absence is UNKNOWN (knownExploited=null), not false. Cached stale
EPSS is displayed for reference but does not trigger a fresh probability promotion.
Source status, dataset date and observation time are separate concepts.

## Policy: risk-v1.2 / schema 3

The existing exact-version and completed-SCA confirmation requirements still apply.
In particular, globally partial SCA cannot establish affected-version certainty.

1. Confirmed exact affected version + explicitly linked CVE + KEV positive:
   BLOCKING, reason KNOWN_EXPLOITED_VULNERABILITY. Applies to every severity,
   including unknown severity. A stale positive remains eligible with a warning.
2. Existing baseline BLOCKING is preserved.
3. HIGH effective severity + confirmed exact affected version + fresh EPSS score
   >= 0.5 AND percentile >= 0.95: BLOCKING, reason HIGH_EXPLOIT_PROBABILITY.
4. Otherwise retain the baseline priority. MEDIUM and LOW are not automatically
   blocked by EPSS. A low probability never reduces an existing priority.

Effective severity continues to take the stronger of the recorded severity and
valid numeric CVSS. CVSS, EPSS and KEV are never added into a synthetic score.
KEV takes precedence over EPSS because it records observed exploitation, whereas
EPSS estimates exploitation activity in the next 30 days at the CVE population
level. Percentile is relative rank, not another independent probability.

The initial 0.5 probability gate is intentionally conservative for automatic HIGH
promotion. The 0.95 rank gate avoids rank-only escalation and keeps both metrics
visible. These are SecureDeploy policy choices, not FIRST recommendations or an
empirically optimized cutoff. Operational calibration is still needed; a high
relative rank with a small absolute probability does not pass the probability gate.

Thresholds are centrally bound and validated in ThreatRiskThresholds:

```yaml
securedeploy:
  threat-intelligence:
    enabled: ${THREAT_INTELLIGENCE_ENABLED:true}
    timeout-seconds: 5
    budget-seconds: 20
    max-cves: 300
    cache-ttl-seconds: 21600
    failure-backoff-seconds: 60
    epss-max-age-days: 2
  risk:
    epss:
      blocking-score: ${EPSS_BLOCKING_SCORE:0.5}
      blocking-percentile: ${EPSS_BLOCKING_PERCENTILE:0.95}
```

The exact thresholds are saved alongside each risk snapshot. Policy code changes
need another policy version; threshold changes affect new scans only.

## Failure and completeness policy

Source lookup statuses: AVAILABLE, NOT_FOUND, UNAVAILABLE, STALE, NOT_REQUESTED.
Snapshot/coverage statuses: COMPLETE, PARTIAL, UNAVAILABLE, STALE, DISABLED,
NOT_APPLICABLE; UNKNOWN is used for missing enrichment on a CVE-bearing assessment.
No CVE identifier means NOT_APPLICABLE, not a claim that the advisory is safe.

SCA coverage and threat intelligence coverage are independent. Incomplete threat
information makes overall coverage partial but does not rewrite SCA's status.
If missing intelligence could increase a confirmed finding's priority, a separate
ANALYSIS / REVIEW_REQUIRED item is added with INCOMPLETE_THREAT_INTELLIGENCE:
- Missing/failing/stale-negative KEV for any severity, because KEV could block it.
- Missing/failing/stale EPSS for HIGH, because fresh probability could promote it.

One coverage requirement aggregates affected paths instead of manufacturing extra
vulnerability findings. Existing finding priorities remain unchanged. Already
BLOCKING findings remain BLOCKING even when enrichment fails; they still show
coverage warnings. Optional EPSS failure for LOW/MEDIUM with complete KEV absence
cannot change this policy's priority, so it adds a warning/partial coverage without
an extra review requirement. Thus low-only results may retain scoped READY with
an explicit optional-enrichment warning. This is not full threat-data coverage.

## Persistence, API and migration

The intelligence snapshot is embedded in the existing nullable TEXT
reviews.risk_assessment_json. No new table/column or destructive migration is
needed. Deployments without Phase 3 still need the existing idempotent
src/main/resources/db/postgresql/add-review-risk-assessment.sql.

GET /api/reviews/{id} and upload/GitHub responses expose:
- riskAssessment.threatIntelligence: snapshotId, observedAt, status, requestedCves,
  findingsWithoutCve, per-CVE epss/kev data, source URLs, fetchedAt and warnings.
- riskAssessment.threatPolicy: the exact EPSS thresholds used.
- riskAssessment.assessmentCoverage.threatIntelligence: separate coverage.
- riskAssessment.policyVersion=risk-v1.2 and schemaVersion=3 on new scans.

This co-locates decision, inputs, provenance and thresholds atomically under the
review. Old schema 1/2 JSON without the new fields remains readable with null
intelligence. GET never calls FIRST/CISA, recalculates priorities or backfills old
rows. New scans always have a new intelligence snapshotId even if the same cached
source evidence is reused. Review deletion also removes the embedded snapshot.

The UI uses the existing dependency card. Details distinguish EPSS score, relative
percentile, KEV positive/negative/unknown, source dates and stale data. CISA text is
React-escaped text, never HTML. Due dates are identified as CISA catalog deadlines,
not automatically imposed project deadlines. Historical cards show saved values.

## Validation (2026-10-07)

- Default backend suite: 151 tests, 149 passed, two opt-in smoke tests skipped.
- New backend coverage: 47 offline tests plus one opt-in live source test.
- Frontend: 15 tests passed; production build passed.
- Separate THREAT_INTEL_SMOKE=true test against official FIRST/CISA passed.
- Real PostgreSQL + ZIP + OSV + FIRST + CISA E2E passed.

The live log4j-core 2.14.1 fixture yielded seven linked CVEs. CVE-2021-44228 had
EPSS 0.99999, percentile 1.0, data date 2026-10-06, and KEV=true in catalog
2026.10.04. Its reason was KNOWN_EXPLOITED_VULNERABILITY and priority BLOCKING.
The legacy rule score was 86 and the independent risk assessment was BLOCKED.
These are observed test-time values, not promises about future source data.

Two uploads under the same project reused source fetchedAt values but had different
snapshot IDs. The first review's detail stayed byte-equivalent at the JSON-value
level. PostgreSQL stored the evidence and thresholds. An unresolved version sample
remained REVIEW_REQUIRED. Live login/history and desktop/mobile browser checks
passed with no text overlap/overflow. MockMvc regression covers GitHub's common
pipeline, auth, Rule Engine/false positives, score invariance, AI summary and PDF.

Offline tests cover KEV precedence, threshold boundaries, no downgrade, failure
isolation, no-CVE behavior, immutable history/rescan, alias normalization, request
chunking, cache expiry/day rollover/backoff, stale positive/negative distinctions,
malformed JSON, invalid/missing probability fields and truncated catalog handling.

The final JAR was restarted successfully on port 8080. Test projects/reviews/account
and the temporary authentication file were removed. All six original DB tables,
including stored risk JSON, matched pre-test row counts and fingerprints. During
cleanup the pre-restart process returned one HTTP 500 after a project deletion had
committed; cleanup was resumed after restart and completed. That response failure's
cause was not established. No deletion failure recurred on the final process.

## Milestone deletion recheck (2026-10-09)

The same final backend process was checked again before the approved Git milestone.
A synthetic account uploaded the same project twice through the real ZIP API. Both
reviews included vulnerabilities, snippets, SCA and nonempty risk-v1.2 threat
snapshots. DELETE /api/reviews/{id} and DELETE /api/projects/{id} each returned
HTTP 200 with the expected JSON success message. Child rows were removed; deleting
the latest review kept the project and moved the dashboard to its previous review.
Comparison then correctly required at least two reviews. Repeating the deleted
project request returned 404, not 500. No new ERROR log lines appeared.

The previous HTTP 500 did not reproduce. It may have been specific to the old
process, but the original cause remains unconfirmed. No current transaction/FK
failure was found, so controller/service/repository deletion code was not changed.
Test data was removed and all six original database table fingerprints matched.
Test authentication was kept in memory, not written to a credential file.

Targeted threat/risk/deletion tests: 100 passed, one opt-in smoke skipped. Full
backend suite: 149 passed, two opt-in smoke tests skipped. Frontend: 15 passed;
production build succeeded. Milestone message:
`feat: enrich risk prioritization with EPSS and CISA KEV`.

## Limits and next phase

No reachability, automatic exposure detection, business-criticality inference,
automatic upgrade, AI remediation or CI gate is introduced. Exact manifest/lock
matching is not proof of runtime installation or reachable exploitation. Global
SCA completeness remains conservative. External feeds can lag; cache TTLs and
source dates are visible. Caches are process-local and reset on restart.

Future AI remediation can consume the saved CVE, priority reason, EPSS date/score,
KEV action/provenance, suggested fix versions and confidence/context without
refetching historical intelligence. The AI must preserve unknown/stale status
and must not interpret percentile as this project's compromise probability.
