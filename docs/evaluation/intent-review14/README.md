# Authorization Intent Review Preparation 14

Status: PREPARATION_ONLY. No independent review or product implementation is completed.
Date: 2026-10-27 (Asia/Seoul).
Review baseline: `cb63fd09f36b9dbdca4cba16c843026f43af8046`.
Product code baseline: `7dc85d29b27b438a74226e4444b01505bf7bb858`;
Worker v28, RLS v3, column-update-v1. The #13 commit added evaluation material only.

## Release Order

This index is coordinator-facing and contains results. Do not use it as a blind packet.

1. Send only [A: reviewer workbook](reviewer-workbook.md). Record prior exposure,
   conflicts of interest, reviewer capacity and whether the work is hypothetical.
2. Freeze and hash the requirement responses before releasing
   [B: declaration cards](declaration-cards.md). Freeze the SQL/code assessment next.
3. Release [C: coordinator notes](coordinator-notes.md) and the original report only
   after both freezes. Record disagreements, not edits to the old expected labels.
4. Reconcile with a separate reviewer; obtain actual project-owner confirmation
   separately if real-project applicability is claimed. No reviewer is assigned yet.

All files and the original results are public in the repository. File order is an
administrative protocol, not access control or cryptographic blinding. IDs/hashes and
snippets can be looked up. A reviewer who has seen #13 answers must be reported as
nonblind. An independent nonblind technical review is useful but is not blind validation.
ChatGPT/Codex summaries already containing the results cannot serve as an unexposed
holdout reviewer context. Do not describe a different model as real owner approval.

## Frozen Inventory

| Asset | Baseline Fact |
| --- | --- |
| #13 processed records | 68: original 36, additional 24 unique contexts, 8 duplicate replays |
| Distinct canonical source packets / Source+Intent pairs | 36 / 60 |
| Request layouts | Authored Route Handler and Server Function; not independent applications |
| SOURCE_ONLY original metrics | TP12 / FP2 / FN6 / TN8 / UNKNOWN8 |
| DECLARED_INTENT original contexts | 18 conflicts / 6 conditional matches / 12 UNKNOWN |
| Original no-alert normal cases that abstain with intent | 4; not confirmed-protection TN |
| Shared access acknowledgements | 2; raw policy observations and other operations preserved |
| Additional unique contexts | 4 conflicts / 2 conditional matches / 18 UNKNOWN |
| Prior controlled PostgreSQL receipt | 560/560 on PostgreSQL 16.14; not rerun in #14 |
| Real owner approvals / Grade A pairs / new actual vulnerability TP | 0 / 0 / 0 |
| Product Findings promoted / operating authorization unknown | 0 / 68 processed records |

Matching 68 authored expectations is an internal consistency result, not an
independent accuracy estimate. The two metric tasks have different decision meanings;
do not combine them into a product precision/recall number. Missing SQL, invalid
contracts and stale hashes test abstention, not successful vulnerability detection.

Frozen #13 report: [authorization-intent13-results.json](../../../scripts/evaluation/authorization-intent13-results.json)

- File-byte SHA256: `93fe972e3b9177c01317a815607679cf270e91405859e9ca8d21f979bacc3c2e`
- Canonical plan digest: `6e14a9b66e184f73c6b2411665e7f8026ced818bcb98040fc2725d0cfc41e01c`
- Runtime fingerprint: `035dda575ca31f62e020ad625758277d47d4a0263edbafd682bb125d31de2d3f`

These are different hash domains. A source-packet digest includes ordered input and
omission metadata; it is not a Git commit, a raw file hash or deployed database proof.
The old report, cases, interpreter and first labels remain unchanged by this review.

## Evidence And Outstanding Work

| Evidence | Established In #13 | Still Missing |
| --- | --- | --- |
| Requirement authority | Fixture-author EVALUATION_CONFIRMED marker | Real owner identity, scope, consent and approval revision |
| Source observations | Supported request/Client/write-origin metadata | Actual invocation, successful login, arbitrary SELECT selector provenance |
| SQL meaning | Authored declarations and isolated A/B/anon/limited-admin checks | Independent SQL assessment and complete real migration/role context |
| Operating permissions | Explicitly UNKNOWN | Actual role, project association, policy application, bypass and authorized runtime tests |
| Detection quality | Same-author controlled comparisons | Independently frozen labels and new project families; actual vulnerable/fixed pairs |

The SQL oracle verifies effects under its setup, not the appropriateness of a business
requirement. A technical review cannot manufacture owner consent. Owner consent cannot
verify SQL effects or deployment. A trusted auth API observation does not prove its
runtime result or the DB role. Keep all four claims separate.

## Preview Gate: Proposal, Not Approval

Independent review is PENDING. Product implementation remains separately gated even
after this preparation is merged. In particular, resolve the owner-edit/transfer
priority challenge in C before treating all accepted contracts as reliable matches.

For a future optional read-only preview, the minimum is:

- Server-owned immutable Review evidence, owner access checks, exact access/table/
  operation/field scope, verified source and policy digests, engine fingerprint and
  optimistic revision binding. Reject ambiguous or unverifiable legacy/ZIP bindings.
- Separately recorded requirement provenance and explicit confirmation; never accept
  EVALUATION_CONFIRMED or client-supplied analysis as production authority.
- Define PUBLIC as a permission ceiling or an availability requirement before scoring.
  Define editable owner fields, transfer restrictions and mixed UNKNOWN dimensions.
- UNKNOWN on missing/unconfirmed/conflicting/stale requirements, missing SQL, unknown
  roles, unsupported policies and unverifiable auth. Confirmation must not override them.
- Optional questions on the relevant project-detail access only. No registration
  requirement, project-list boxes, safety badge, automatic resolution or warning deletion.
- Show source facts, assumed-role declaration comparison, intent authority and runtime
  unknowns separately. A conditional match is not SAFE. Sharing is not blanket approval.
- Start with request-scoped preview; no policy write, AI call or source transmission.
  Persistence/audit revisions require a separate design and explicit schema approval.
- Future ownership, CSRF/session, cross-user, stale/revoked approval, rate/size and
  unrelated-warning preservation tests are required; no new endpoint was tested here.

Recommended next action: independent staged review and adjudication, not more AST work
or product implementation. For genuinely blind validation, obtain separately authorized
new source families and owner requirements before engine results, with a different
label author and an exposure log. Any runtime check needs separate authorization in
an isolated owner-controlled environment. Do not run downloaded SQL/apps automatically.
