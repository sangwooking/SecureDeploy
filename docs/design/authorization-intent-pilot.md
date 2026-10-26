# Authorization Intent Pilot

## Scope And Trust

This is an offline evaluation, not a product feature. Worker v28, RLS v3,
column-update-v1, Rule/FPR, Risk/score, application APIs and user data are unchanged.
The interpreter receives observed metadata and an optional requirement, never an
expected label or the database oracle. Fixture construction and scoring are separate.
SOURCE_ONLY ignores the requirement. DECLARED_INTENT compares the same observations
with explicitly confirmed fixture intent. It does not strengthen the underlying facts.

`EVALUATION_CONFIRMED` means confirmation by the fixture author. It is not real
project-owner approval, a signature, a verified login, or evidence of the active DB role.
Actual invocation, authentication, DB role and deployment stay unverified in both modes.

## Four Evidence Layers

| Layer | What It Supports | What It Does Not Establish |
| --- | --- | --- |
| Source | Supported Next declaration, Client, auth-result guard, operation, bounded write origins | Actual HTTP invocation, successful authentication or arbitrary SELECT argument provenance |
| SQL declaration | USING/CHECK and positive table/column grants under an assumed role | Effective role, role inheritance, grantor, SQL history completeness or deployed state |
| Confirmed requirement | Intended private/shared/public access and allowed/protected fields for the exact scope | New factual SQL protection or permission to erase unrelated warnings |
| Isolated SQL oracle | Controlled A/B/anon/limited-admin row counts and SQLSTATE | Production Supabase Auth, HTTP exploitability or deployed application safety |

The original private-read misses need explicit private-data intent. The four protected
property misses need an explicit prohibition; the illustrative management helper was
not shown to be invoked in production. A field name supplies neither requirement.
Both also depend on real role/project/deployment alignment. The two shared-data FPs
are review burden relative to explicit sharing requirements, not false claims that
the SQL declaration is broad. Original 36 labels and first results are retained.

## Evaluation Contract

The prototype accepts only a small JSON object (8 KiB maximum, 16 names per field
list), with exact identifiers and the supported hypothetical `anon`/`authenticated`
roles. Version/revision, author-confirmation marker, canonical source-packet SHA256,
entry file, qualified table and operation must match. An absent, unconfirmed,
contradictory, stale, mis-scoped or unsupported requirement abstains. Missing keys
do not become permission or protection. README/comments/table names never approve intent.

Optional questions are represented by `readScope`, `writeScope`, `ownerColumn`,
`editableColumns`, `protectedUpdateColumns` and `ownershipTransfer`. An explicit
PUBLIC/SHARED scope permits broader access for the assumed role; it does not prove
anonymous availability or require the application to provide it. INSERT/DELETE row
conditions are separate from UPDATE fields. The column feature remains UPDATE-only.

The prototype does not infer a role from a key name, treat getSession as verification,
or equate an API call/absence guard with successful authentication. A missing grant
is not denial. A normal oracle case with no established grant remains UNKNOWN rather
than a proven protection match. Unknown policy functions, missing SQL, unsupported
roles and uncertain auth context are not overridden by confirmation.

## Result Meaning

- CONFLICT: a positively observed declaration conflicts with an approved fixture
  requirement under the stated role hypothesis. Not a reproduced vulnerability.
- CONDITIONAL_MATCH: supported observations match the requirement for this access
  and selected fields. Not a whole-table, whole-project or runtime safety verdict.
- UNKNOWN: at least one necessary requirement or observation is not established.
- SOURCE_REVIEW / NO_SOURCE_CANDIDATE_OBSERVED: existing source-only behavior,
  never a claim that a warning-free case is safe.

Conflict dimensions and unknown dimensions remain visible together. Sharing can
acknowledge review burden only for the exact table, SQL scope, operation and access.
It cannot override protected fields, missing migrations or uncertain auth, and does
not remove the original policy candidate or its INSERT/DELETE observations.

No new product Finding is created. Conditional conflicts might later support an
explicitly approved REVIEW_REQUIRED/NOT_COMPARED section, not automatic BLOCKING,
score changes or RESOLVED. Real project approvals and runtime confirmation are absent.

## Evaluation Protocol

The original 36 observed controls are Regression. The additional 32 controls were
frozen before the first interpreter run; they contain eight duplicate source-plus-
intent replays and 24 unique additional contexts. All duplicates stay in the raw
records and are excluded from the new-Validation count. Counterfactual intent is
not a correction to the original project truth. Route Handlers and Server Functions
are two authored request layouts, not two independently sourced web applications.

The unchanged restricted Worker processes each of the 68 inputs twice. The initial
frozen plan and preliminary evaluation receipts stay outside Git for audit. Grade A
pairs and independent external review remain zero. The directly authored #11 SQL
oracle is rerun in an isolated PostgreSQL cluster; external SQL/apps are not executed.

Compare tasks, not a single blended accuracy number: source-only candidate labels,
intent/declaration conflict labels, acknowledged sharing burden, conditional matches,
normal abstentions and runtime UNKNOWN are different measures. In particular, four
normal source-only no-alert cases abstain in DECLARED_INTENT; they are not quietly
counted as confirmed TN. No overall automatic precision/recall improvement is claimed.

## Minimal Product Interaction: Proposal Only

Do not change registration or the project list. On a relevant project-detail access
record, optionally ask one scoped question at a time: private vs shared/public vs
unknown; whether the selected field is editable by ordinary users; whether ownership
transfer is allowed. Show the source/SQL scope and role hypothesis before confirmation.
Do not ask a user to declare missing SQL or an unknown actual role safe.

Show source observations, approved intent, conditional conflicts and runtime unknowns
as separate sections. Keep raw warnings, Risk/score and history unchanged. Withdrawal
of intent returns the additional interpretation to UNKNOWN; it does not rewrite history.
No automatic/AI permission patch or automatic vulnerability resolution follows consent.

## Minimal API And Storage: Proposal Only

Start with a request-scoped preview, for example
`POST /api/reviews/{reviewId}/authorization-intent-previews`. Reuse existing ownership
checks. Read observations from the server's immutable Review, never from client-supplied
facts. Require expected Review/source digest, full source revision, policy digests,
analysis fingerprint, exact table/operation/access binding and intent revision. Use
conditional requests and fail closed for stale, conflicting or incomplete input.

Old Reviews may lack source hashes. Reacquire and verify source using the existing
read-only flow before enabling binding; do not invent hashes or retroactively certify
unverified ZIP inputs. A preview stores nothing, sends no code/intent to AI and changes
no policy. Requirements contain metadata, not credentials or copied source literals.

Persistence is a later separately approved design/migration: append-only approval
revisions with actor/time, provenance, source/Review and scope binding, requirements
and revocation history, separate from original analysis snapshots. Ownership, optimistic
concurrency, payload limits, CSRF/session checks and cross-user/stale-source tests are
mandatory. A preview nonce/digest must match the exact final approval. This evaluation
marker must never be accepted as production owner consent. No endpoint or table exists
as a result of this milestone.

## Next Gate And Stop Condition

The result supports a bounded read-only intent preview, subject to explicit approval,
not a new AST framework. Before persistent product behavior, have a different reviewer
freeze requirements for permitted real projects, test unsupported/unknown cases, and
verify that unrelated operations/warnings never disappear. Keep an independently
reviewed validation set separate from development. Runtime safety still needs the
project owner's authorized A/B sandbox tests. Stop expanding the pilot when scoped
confirmation, stale/cross-user rejection and preservation of source facts are verified;
do not turn this into a general RBAC engine or mandatory project policy questionnaire.
