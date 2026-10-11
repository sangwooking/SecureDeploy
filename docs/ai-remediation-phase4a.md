# Phase 4A: Finding Remediation

## Purpose and invariants

Risk Prioritization answers what requires attention before deployment. This phase adds reviewable actions and verification steps to those exact findings. It is advice, not an automatic patch or evidence that a finding is fixed.

- Rule/SCA/TI/Risk calculation, scores, deployment assessment, detection confidence and false-positive metadata are unchanged.
- The model output has no severity, priority, blocking or deployment fields. AI remediation confidence is a different field.
- Existing project-level AI endpoints and PDF reports remain unchanged. Their on-demand output is separate from the new immutable finding guides.
- No files, dependencies, commits or PRs are modified by remediation.

## Flow and persistence

1. Existing scan, SCA, TI, false-positive and risk pipeline runs.
2. `ReviewPersistenceService.saveReview` commits deterministic findings with database IDs and canonical dependency identities.
3. `RemediationSnapshotService` invokes `FindingRemediationService` outside that transaction.
4. Sanitized contexts are assembled from the saved response and existing bounded snippet collection.
5. Template advice is prepared. With `AI_PROVIDER=openai`, one bounded batch may replace eligible advice.
6. `saveRemediationOnce` performs a separate conditional update of `reviews.remediation_snapshot_json`. It cannot overwrite a saved snapshot or update risk/status fields.
7. Upload/GitHub response and `GET /api/reviews/{id}` include additive nullable `remediation`. History reads do not call a provider. New scans get independent IDs and snapshots.

Migration: `src/main/resources/db/postgresql/add-review-remediation-snapshot.sql`. Additive TEXT column, repeatable, no backfill. Old reviews remain NULL. Review/project deletion naturally removes the column with its review.

If the process stops between the two transactions, the security result survives with a null guide. There is no implicit history retry. Generation failure can store `UNAVAILABLE`; storage failure returns the already committed result without claiming the guide was persisted.

## Schema and provider contract

`AiProvider.generateFindingRemediations(contexts, prompt)` returns a map keyed by opaque wire finding ID. The service maps each result back to its canonical snapshot finding ID. Unknown, duplicate, missing or malformed items invalidate the batch.

`RemediationSnapshot`: schemaVersion, snapshotId, generatedAt, generationStatus, findings, omittedFindingCount, notices, usage.

Each finding stores findingId, advice, provider, model, promptVersion, generatedAt, generationStatus. Advice contains summary, whyItMatters, recommendedAction, codeExample, configurationExample, verificationSteps, caution and remediationConfidence.

- `GENERATED`: accepted model advice, with deterministic safeguards on secrets/dependencies.
- `TEMPLATE`: offline, budget-limited, review-needed or fallback guidance.
- `NOT_REQUESTED`: no supported finding/unsupported category; never equivalent to safe.
- `UNAVAILABLE`: generation failure; security assessment remains available.
- `FAILED` is reserved for later per-item failure reporting.

## Limits and priority

- Supported now: CODE, SECRET, CONFIG, DEPENDENCY. Other categories are marked NOT_REQUESTED.
- Canonical risk findings are used, not raw duplicate dependency candidates.
- At most 200 guides per review; omitted count is explicit.
- At most six BLOCKING/SHOULD_FIX contexts in one OpenAI batch; no automatic retry.
- REVIEW_REQUIRED uses verification-only templates, no paid call or definite patch. INFORMATIONAL uses templates.
- Maximum instructions + JSON input: 24,000 characters. Batch shrinks to fit.
- One existing snippet from the same file, at most 1,200 characters. Existing collection is limited to 10 files and 1,500 characters/file. A snippet may be an initial excerpt, not the actual finding neighborhood; missing context is not fabricated.
- Output budget 6,000 tokens; transport uses existing configured timeout. Advice field/list limits are validated before storage.

## Privacy and injection defense

`RemediationSanitizer` runs before prompt construction and again before advice storage. It masks named credential assignments (including quoted low-entropy values), common token formats, bearer values, private key blocks, URL credentials and long opaque strings. Snippet string literals are conservatively removed. Environment references without defaults remain usable in suggested configuration.

Canonical IDs may contain untrusted package/version text, so provider IDs are opaque UUID-derived identifiers. Paths, evidence, notes, package metadata and external advisory summaries are separately bounded/sanitized. No archive or entire repository is transmitted.

Privileged `instructions` are separate from the JSON user payload, whose key is `untrustedFindingData`. Code/comments and external summaries are explicitly data, not instructions. No tools or URL fetching are enabled. The output schema disallows additional fields and binds finding IDs. Rendering uses escaped React text, never model HTML. These controls reduce injection risk but do not prove semantic immunity to every adversarial input.

The OpenAI Responses API uses `store:false` and strict `text.format` JSON schema. Reference: [official Structured Outputs documentation](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses).

No request/response/code body is logged by the new path; exception messages are not logged because upstream exceptions may contain bodies. Sanitization is heuristic, not a general secret detector. Obfuscated credentials, unusual formats and sensitive business information require additional policy before broad production use. Legacy AI endpoints retain their existing context policy.

## Grounding and fallback

Secret actions always retain removal, rotation/revocation, Git-history exposure checks, env/Secret Manager use and rescanning. Client-side secret advice warns that frontend environment variables are public.

Dependency actions and verification are generated from stored OSV fixedVersions, not model-proposed versions. Unrecognized numeric version references reject the batch. Explicitly labelled CVSS/EPSS metrics are exempt only when equal to supplied facts (including exact percentage conversions); the same number in a proposed package version is still rejected. Validation diagnostics contain only a static reason code, never model/source text. No fixed version means consulting official advisory/maintainer documentation, not blindly choosing latest. Known fixes can belong to different release branches and are not universal safety guarantees. Free-form explanation still requires human review. EPSS is not the probability that this project will be hacked.

OpenAI quota, timeout, refusal, invalid JSON, ID mismatch and validation errors preserve templates. Actual returned token usage is retained even when content validation later falls back; unavailable usage is zero. USD estimation remains unimplemented, and UI says so.

## UI

Existing code and canonical dependency cards contain a collapsed `AI 해결 가이드`. It distinguishes AI/template provenance, explains independent remediation confidence, shows actions/examples/checks and snapshot metadata. There is no history-triggered generate button. Null history, omitted findings and provider fallback have explicit notices. Existing AI summary and severity filtering are unaffected.

## Verification

Default automated tests use template or mock providers, H2 and mocked external services. Tests cover blocking secret lifecycle, dependency fixes/missing fixes, verification-only guidance, input/output masking, injection separation, strict ID/schema validation, bounded batching, fallback, no active DB transaction during provider calls, immutable history, new scan snapshots, legacy null and deletion.

Commands:

```sh
gradle test
cd frontend
npm test
npm run build
```

An opt-in `OpenAiRemediationLiveSmokeTest` is enabled only with `SECUREDEPLOY_OPENAI_SMOKE=true` and `OPENAI_API_KEY` already set in the environment. It uses a synthetic finding and may incur API cost. Never place keys in fixture files or command arguments.

## Future boundaries

Snapshot/finding identity can link a later user-approved patch proposal and rescan comparison. No apply endpoint, executable patch or upgrade action exists now. Next steps should improve relevant line-window context, format-specific redaction, advisory branch selection and injection evals before any automatic changes. Async generation with durable status/retry and configurable per-user budgets can follow separately.

The [product direction](product-direction.md) records the user-approved evidence pipeline and extension boundaries for Semantic Review, Security Slices, Rule Registry, Data Flow and Reachability. These are future work, not claimed capabilities of Phase 4A.

## Development verification: 2026-10-11

- Repeated PostgreSQL migration succeeded; row fingerprints for the existing users/projects/reviews/vulnerabilities/snippets/SCA data were unchanged after test cleanup.
- A synthetic ZIP with debug/CORS and Log4j dependency findings traversed Rule/False Positive/SCA/TI/Risk and one real OpenAI batch. SCA and TI were COMPLETE, with seven canonical dependency findings.
- Six guides were GENERATED and three TEMPLATE. OpenAI returned 4,310 total tokens; usage remained billable with USD estimation unimplemented. Risk remained BLOCKED.
- PostgreSQL snapshot storage and authenticated detail re-read returned identical remediation and risk snapshots. Template rescan created a new snapshot and did not modify the original.
- Browser login/history, guide rendering and desktop/mobile overflow checks passed. Existing project AI summary and basic PDF also passed.
- Synthetic test accounts/projects were deleted; original data and provider configuration were preserved. The new application build is running on port 8080. No commit or push was performed.
- The earlier 2026-10-09 mixed batch fell back after a response was received. Its precise cause was not recorded and is not proven retroactively. A reproducible numeric-metric/version validation defect was subsequently fixed; the new real batch passed. Fallback success is not counted as generated-AI success.
