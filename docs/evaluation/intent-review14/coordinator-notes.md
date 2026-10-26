# C: Coordinator Notes And Review Challenges

Unblind after A and B are frozen. This is author-prepared material, not an independent
review, new ground truth, a new benchmark score or real project-owner approval.

## Circularity And Bias

The interpreter does not receive expected labels or the SQL oracle. That structural
separation is useful but insufficient for independence. In intent13_cases.py, the
original expected comparison is derived from existing RISK/NORMAL labels and selected
scenario names. The same author supplied requirements, SQL, cases and interpretation
rules. The code/SQL patterns and original outcomes were already observed.

The SQL oracle validates authored SQL effects, not why a service should be private,
shared or management-restricted. Counterfactual intent variants reuse source. Eight
duplicate Source+Intent replays are excluded from new Validation; 24 unique additional
contexts are still not 24 independent projects. Source-only TN and conditional matches
have different meanings, and four normal cases still abstain. Invalid-intent tests
are not vulnerability detections. No confidence interval from this sample establishes
product-wide precision/recall. Passing expectations does not validate every accepted
contract combination, deployment premise, identifier or source pattern.

Mitigations: disclose exposure; independently freeze requirements before showing
policies; independently assess code/SQL without engine answers; retain UNKNOWN;
separate owner consent from technical review; keep original labels and adjudication
revisions; reserve genuinely new source families for later externally reviewed tests.

## Original Source Bindings

These are canonical full-packet hashes, not hashes of B's formatted excerpts.
The original request/config/helper and policy context must be reobtained and verified
before a byte-exact reproduction or real-project claim. All are authored controls.

| Card | #13 Reference | Canonical Source SHA256 |
| --- | --- | --- |
| R14-01 | action-validation-public-read | 1835d7dc8f2c67f62083aa8c1655cdf3b60cc36bb2947e97acfd0512b828f984 |
| R14-02 | route-private-read | 47822822299311c087c7df249ed5b23bead68771580e0fddce607f7c3d00a70d |
| R14-03 | route-intentional-share | 74abe60913aa3437310c020536d929c3c42522bb79640cda7b239e5f62650362 |
| R14-04 | route-role-field | dc84ce8280bb0e2d5c4147092cc8eb46d379134fbc2066155731a048b7f798e8 |
| R14-05 | action-transfer-owner | cac9ec6339980fac6766429ee397e7afc922e6293059a5933a5448edda87b36d |

Original report: [#13 metadata](../../../scripts/evaluation/authorization-intent13-results.json).
Do not give this mapping to an unexposed reviewer before response freeze. Public
availability nevertheless makes lookup possible; this process is not enforceable blinding.

## Diagnostic D1: Editable Owner And Forbidden Transfer

Read-only diagnostic against the unchanged #13 interpreter and its existing captured
authored source, not a change to the 68 official cases:

- Parent: route-transfer-owner; source packet
  `5c86824a868341e6c42a55add64a478be9ef116436084bc98d365cc75801315f`.
- Keep ownerColumn=user_id, writeScope=OWNER_ONLY and ownershipTransfer=FORBIDDEN.
- Change only editableColumns from [payload] to [payload, user_id].
- Observed: CONDITIONAL_MATCH, with WRITE_SCOPE and EDITABLE_COLUMN:user_id matches.
  No OWNERSHIP_TRANSFER dimension was emitted; runtime role remained UNKNOWN and
  productFindingCreated remained false.
- Code inspection: the editable-column branch precedes the forbidden-transfer branch.
  The card's policy has old-row owner equality but WITH CHECK(true), so allowing an
  owner field edit must not silently answer the separate no-transfer requirement.
- The prior #13 authored SQL receipt records authenticated A and B transfer-owner
  operations each changing one row under open-replacement. That existing receipt was
  inspected and its canonical digest matched #13; SQL was not rerun in #14. It does
  not establish a real session, deployment, or approval of this new contract variant.

This is an author-discovered coverage/contract challenge requiring independent
adjudication. It is not a verified production vulnerability. Decide whether this
combination must be rejected as ambiguous or interpreted with a separate transfer
constraint. Also define ALLOWED, which the schema accepts but the interpreter does
not fully implement as a transfer-compliance check. No fix is made in #14. Do not
implement the product preview while this accepted-contract boundary is unresolved.

## Diagnostic D2: Public Permission Versus Availability

Changing route-private-read's readScope to PUBLIC produces CONDITIONAL_MATCH under
the assumed authenticated role. #13 defines PUBLIC as a permission ceiling, not
anonymous availability. The code still contains an auth-result absence guard. Ask
the reviewer to freeze the business meaning first. Do not call a match a proof that
anonymous users can access an endpoint or that a required public feature works.

## Diagnostic D3: Conflict With An Unknown Dimension

Changing route-role-field's ownerColumn to tenant_id produces overall CONFLICT while
WRITE_SCOPE is UNKNOWN and PROTECTED_COLUMN:role is CONFLICT. Preserve both dimensions.
The aggregate must not be displayed as full authorization coverage, a known runtime
role, or a confirmed attack. Review the aggregation and future wording independently.

## Adjudication And Exit Criteria

```text
Challenge/card:
Independent response IDs and disclosure status:
Agreement/disagreement and independent rationale:
Requirement authority vs test stipulation:
Code/SQL facts and artifact bindings:
Unresolved semantics and UNKNOWN dimensions:
Decision owner and evidence still needed:
Future protocol/test change proposed (not applied to #13):
Separate approval needed for code/product/schema changes:
Status: PENDING / REQUIRES_DECISION / TECHNICALLY_REVIEWED
```

No completed answers are supplied. Existing first labels/results stay unchanged.
Before requesting product approval, resolve D1 and PUBLIC/aggregation meanings,
review the five requirement families, agree on UNKNOWN behavior, and obtain an
independently frozen test plan. Real applicability still requires owner authority
and source scope. Operating safety requires separately authorized deployment/role
evidence; the 560 authored SQL checks cannot substitute for it.

This preparation is complete when packets, provenance, missing-evidence categories
and review gates are usable. Completion does not approve Intent Preview implementation.
