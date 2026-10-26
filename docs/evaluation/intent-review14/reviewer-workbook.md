# A: Requirement Review Workbook

Unfilled template. No approval, answer, signature or completed review is supplied.
Read this file before B, C, the interpreter, case generator or result JSON.
Public access cannot enforce this sequence. Declare previous exposure honestly.

## Reviewer Record

| Field | Response |
| --- | --- |
| Reviewer / capacity / date | UNASSIGNED |
| Relationship to the implementation and original labels | UNRECORDED |
| Files/results previously seen and time of exposure | UNRECORDED |
| Real owner authority or delegated scope | NOT PROVIDED |
| Hypothetical fixture review or real-project review | UNSELECTED |
| Requirement-response revision / byte hash / freeze time | UNRECORDED |
| Phase B response revision / byte hash / freeze time | UNRECORDED |

A technical reviewer may accept a stipulation for a hypothetical test. That is not
approval on behalf of a real project. With no owner evidence, real applicability stays
UNKNOWN. Do not infer intent from field names, comments, README or existing SQL.
Do not submit private code, credentials, tokens or confidential owner responses to Git.

## Proposed Requirements To Assess

All five cards describe author-created controls, not real deployed services. Ordinary
member and administrator are business concepts; their DB roles are not verified.
Assess each requirement for coherence, scope and missing facts before seeing SQL.

| Card | Proposed Requirement | Questions To Freeze |
| --- | --- | --- |
| R14-01 | Ordinary members may read any document in this scoped collection. | Is this merely permission to disclose, or must every member/anonymous visitor actually be able to read? Which subject groups are included? |
| R14-02 | A member must not read another member's private document. | Who owns a document? Does delegated/shared access exist? What evidence establishes that mapping? |
| R14-03 | Members may collaboratively edit the display text of documents owned by other members. | Which exact fields and operations are shared? INSERT, DELETE and protected-field changes are not specified by this proposal. |
| R14-04 | A member may edit their own display text but must not assign a designated management attribute. | Is the attribute explicitly protected? Is its management use verified? Are administrator exceptions specified or unknown? Do not decide from its name. |
| R14-05 | A member may edit their own document but must not transfer ownership to another member. | Can the owner field be written with the unchanged value? How should an editable-owner declaration interact with a no-transfer rule? What about delegated/admin transfers? |

## Repeat This Response For Each Card

```text
Card:
Requirement response revision:
Prior exposure:
Test-model decision: ACCEPT_STIPULATION / NEED_CLARIFICATION / DISAGREE
Real-owner authority: PROVIDED / NOT_PROVIDED / UNVERIFIABLE
Authority reference and scope (no secrets):
Subject group and assumed-role mapping:
Resource/table and owner mapping evidence:
Allowed operations/fields:
Forbidden operations/fields:
Exceptions and unconfirmed dimensions:
PUBLIC meaning, if relevant: PERMISSION_CEILING / AVAILABILITY / UNRESOLVED
Owner-field edit and transfer precedence, if relevant:
Independent rationale (not copied from an engine label):
Missing information and responsible party:
Author/date/revision and response hash:
```

Freeze responses before requesting B. Record a new revision for later clarifications;
do not overwrite the first response. Do not fill acceptance from #13's 68/68 result.

## After Requirement Freeze: Declaration Assessment

Use B without opening C or the result JSON. Keep the role hypothesis explicit.

```text
Card and frozen requirement revision:
Code/SQL artifact scope and digest supplied:
Independent request -> auth observation -> Client -> operation trace:
USING / WITH CHECK / table UPDATE / column UPDATE / PUBLIC evidence:
Declaration comparison: CONFLICT / CONDITIONAL_MATCH / UNKNOWN
Dimensions established and dimensions still UNKNOWN:
Assumptions about roles, auth.uid(), grantor, schema and migration completeness:
SQL action and predicted outcome: SQLSTATE / ZERO_ROWS / CHANGED_ROWS / UNKNOWN
Oracle receipt inspected or independently checked (state which):
Actual runtime claim: NOT_VERIFIED unless separately evidenced
Evidence needed to change this decision:
Rationale, revision, author and hash before unblinding:
```

Do not execute these cards, the external application or any user database. An optional
future SQL check must use reviewed authored controls in an isolated environment and
record the exact setup; it is not an HTTP or deployed Supabase security test.

After unblinding, log each disagreement and whether it concerns a requirement, scope,
SQL semantics, missing evidence, interpreter behavior or wording. Both original
responses and old benchmark labels remain preserved. An independent adjudicator may
revise a future evaluation protocol, never silently rewrite #13's first results.
