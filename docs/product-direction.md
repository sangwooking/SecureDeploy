# SecureDeploy product direction

User-approved direction, recorded 2026-10-11. This guides future phases; each phase keeps its own bounded implementation scope.

## Product outcome

SecureDeploy is a security decision platform for deployment. Its central questions are whether a project can be deployed, what must be addressed first, why it matters, how to fix it, and whether a rescan demonstrates improvement. Finding count and rule count are supporting measures, not the product outcome.

## Evidence sources

| Analysis | Purpose | Current boundary / future work |
| --- | --- | --- |
| Known pattern | Rule Engine with false-positive reduction | Extend through versioned Rule Registry / Rule Packs and positive, negative, false-positive and boundary tests. |
| Known vulnerability | SCA / OSV / CVE / CVSS and EPSS / CISA KEV | Extend ecosystem coverage, SBOM and advisory enrichment while retaining source, date, completeness and uncertainty. |
| Semantic / flow | Find suspicious authorization, logic and input-to-sink behavior beyond pattern matches | Phase 4B adds bounded AI-assisted candidates; independently validated data-flow, taint and reachability evidence remains future work. |

Evidence validation, false-positive reduction and deterministic risk policy connect these sources to deployment assessment. AI helps explain and remediate; it is not the source of truth for severity, blocking, finding confidence or deployment approval.

## Semantic candidate contract

AI Security Candidates should be a separate source/type, initially REVIEW_REQUIRED. Preserve file, line, function/endpoint, suspected issue, reasoning, bounded context, optional source/sink/flow, and independent AI analysis confidence. The server must verify claimed files, ranges and evidence against the exact supplied context. An invalid claim is discarded or remains review-required; AI alone never escalates or lowers deterministic deployment risk.

## Security Slice and data policy

A Security Slice is a small, traceable security flow, such as a transfer endpoint, its controller/service/repository functions, input parameters and relevant authorization checks. Select these server-side before masking, sanitization and size limits. Keep source-file/range provenance for later evidence validation.

Never send entire archives/repositories or raw .env, private keys, API keys, JWT secrets, DB passwords or access tokens. AI requests run on the backend. All project text and external advisory prose are untrusted data, separated from privileged instructions. AI receives no shell, file-write, DB, push or deployment-decision capability.

Phase 4B Standard Scan runs Rule/False Positive/SCA/TI/Risk without external AI code transfer. AI Enhanced Scan explicitly permits semantic review and contextual remediation, subject to the server's provider configuration. The mode is persisted per Review and defaults to Standard. See [Phase 4B implementation and limits](ai-semantic-review-phase4b.md), including the historical NULL-mode compatibility policy. Organization-wide consent controls remain future work.

## Follow-on analysis

- Rule Registry: rule ID/version, CWE/OWASP, category, severity/default confidence, conditions/exclusions, sources/sinks/sanitizers, remediation/references, and quality-test metadata. Measure coverage by security area, not only number of rules.
- Data Flow / Taint: represent source, propagation, sanitizer and sink with static evidence and documented analysis limits.
- Reachability: connect dependencies/advisories to reachable application paths with explicit known/unknown coverage. Absence of proof must not silently mean unreachable or safe.
- Rescan: compare stable findings and evidence, resolved/new/persisted risks and deployment state. Preserve historical snapshots and the policy version used.

An effective unresolved BLOCKING finding still means BLOCKED under the current policy. Illustrative future before/after screens must not display READY_WITH_WARNINGS while retaining an effective BLOCKING count unless the policy explicitly defines a separate, justified exception state.

## Phase 4A extension points

- `RemediationContextFactory` can later consume validated Security Slices with precise source ranges; current snippets are bounded file excerpts, not flow analysis.
- Canonical finding IDs and immutable Review snapshots support linking advice, user-approved future patches and rescans. They are not yet a universal cross-scan identity model.
- `AiProvider` and structured output validation allow additional candidate-producing features; semantic candidate validation must be separate from advice validation.
- Rule Registry metadata can replace rule-specific template selection without changing advice persistence or provider selection.
- Data-flow/reachability facts must enter evidence validation and a versioned deterministic RiskPolicy first. Remediation may explain those saved facts but cannot create or override them.

Implementation decisions should improve deployment judgment, false-positive quality, actionable priority or verified fixes without unnecessary structural complexity. Automatic modification, CI gates, rule packs and flow/reachability analysis remain separately scoped phases; Phase 4B semantic candidates never become verified risk facts on AI authority alone.
