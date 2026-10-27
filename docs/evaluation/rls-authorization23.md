# Supabase RLS and authorization enforcement #23

## Baseline, implementation and outcome

Baseline `1956a2d4c8035a4dbba76c3c9a350d46a6e6125c`: Worker v33, RLS v3,
column-update-v1. Product commit `32d12bd`: Worker v34, RLS v4. The latter
version labels the changed declaration interpretation; it is not a new runtime
authorization engine. The isolated development branch leaves original local
main `15070416`, port 8080/v28/PID 99387, user DB and three private documents
untouched. No server restart, migration, API/UI or automatic policy patch.

One concrete product omission was reproduced: the RLS write candidate considered
table-level UPDATE grants only. The existing parser already recorded individual
column grants, including PUBLIC grants, but failed to use them as UPDATE
capability. A broad policy plus UPDATE(body) can permit cross-user body updates
without a whole-table UPDATE grant. This is a declaration-review omission, not
a newly discovered application CVE or automatic proof of an intent violation.

`rls.mjs` now recognizes table OR column UPDATE capability when producing an
operation's EXPLICIT_GRANT and existing broad-write candidate. The separate
`updatePrivileges.tableGrant` and `columns` retain exact grant scope. No new
field or column-update-v1 implementation change. Other verbs do not inherit
UPDATE capability. No role, owner-column or business intent is guessed.

## Official contracts reviewed

- [PostgreSQL 16 CREATE POLICY](https://www.postgresql.org/docs/16/sql-createpolicy.html):
  old-row USING, replacement-row WITH CHECK, omitted check fallback for UPDATE/
  ALL, permissive OR plus restrictive AND, and SELECT/RETURNING prerequisites.
  Their meanings are not interchangeable with oldOwner = newOwner invariance.
- [PostgreSQL 16 row security](https://www.postgresql.org/docs/16/ddl-rowsecurity.html):
  default denial with enabled RLS/no applicable policy; ownership, FORCE and
  BYPASSRLS exceptions; whole-table operations such as TRUNCATE are separate.
- [PostgreSQL 16 GRANT](https://www.postgresql.org/docs/16/sql-grant.html):
  a column privilege can authorize that column independently; revoking one
  column does not cancel a surviving table grant.
- [Supabase RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)
  and [column security](https://supabase.com/docs/guides/database/postgres/column-level-security):
  key origin does not establish the active user/role or deployed policy; row
  restriction and column privileges are separate review dimensions.
- [OWASP API1:2023 BOLA](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/)
  and [API3:2023 BOPLA](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/)
  motivate separate record/field requirements. They do not label broad shared
  data a vulnerability without its requirements.
- [ASVS 5.0.0 V8](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md):
  8.1.1/8.1.2 documented data/field access; 8.2.2/8.2.3 explicit item/field
  authorization; 8.3.1 trusted enforcement. These are coverage references, not
  a claim that SecureDeploy verifies ASVS compliance.
- [CWE-639](https://cwe.mitre.org/data/definitions/639.html),
  [CWE-862](https://cwe.mitre.org/data/definitions/862.html) and
  [CWE-863](https://cwe.mitre.org/data/definitions/863.html), MITRE 4.20 pages,
  are relevant classifications only when bypass/missing/incorrect authorization
  is established. The existing broad declaration rule was not promoted to an
  automatic CWE vulnerability verdict. Direct fetches for 862/863 timed out;
  official search-index results were available. An incorrect initial ASVS raw
  path returned 404; the pinned v5.0.0 V8 path above was then verified.

## Code audit: actual supported scope

| Area | Existing implementation and boundary |
| --- | --- |
| SQL collection | Recognized Supabase migrations/scoped SQL sources; deterministic lexical migration ordering, omission/duplicate/ambiguous-root provenance. Not deployed DB history. |
| Parser | Static bounded token/cursor grammar, explicit schema.table; selected CREATE TABLE body is skipped, not a full schema/constraint verifier. |
| CREATE/ALTER/DROP POLICY | Supported clauses/defaults, roles, rename/change/drop; unsupported or incomplete declaration can invalidate table/scope. |
| ENABLE/DISABLE RLS | Tracked declaration, not actual activation. |
| FORCE RLS | Stored flag; owner identity, superuser/BYPASSRLS and effective role remain unmodeled in product verdicts. |
| Table GRANT/REVOKE | SELECT/INSERT/UPDATE/DELETE, supported explicit single-table static grants; not complete ACL/grantor/default privilege semantics. |
| Column GRANT/REVOKE | UPDATE only, bounded static column sets; table/PUBLIC/direct additive scopes kept separate. |
| Roles | Candidate output for anon/authenticated plus PUBLIC applicability; actual memberships, role switching, custom admin/inherited/BYPASSRLS execution are UNKNOWN. |
| USING/WITH CHECK | Boolean literals, supported auth.uid equality/authentication/boolean-column atoms and bounded AND/OR. Unknown helper expressions are not assumed safe. |
| Policy combination | Applicable command/ALL and role/PUBLIC policies; permissive OR, restrictive AND; no permissive policy means denial. |
| UPDATE direction | Existing/new row predicates separate; one-sided unrestricted states retained; no arbitrary old/new equality inference. |
| SELECT prerequisites | Per-operation declarations available; product does not emulate every SQL query's read/RETURNING prerequisites. Runtime controls test these separately. |
| Column-update-v1 | Unchanged local write-field ACL evidence, not effective row authorization or a protected-field requirement engine. |
| Requests/auth | Existing Next/Client/guard/write provenance reused. Auth API result is not successful login, and server key presence is not active service_role proof. |
| Evidence/Risk | Existing SUPABASE_BROAD_WRITE_DECLARATION, REVIEW_REQUIRED/NOT_COMPARED, source locations and separate Coverage; score/decision formula unchanged. |

Functions, triggers, SECURITY DEFINER, views, dynamic SQL and role inheritance
are not a complete supported authorization model. Unsupported policy functions
produce UNKNOWN; other ignored SQL can be marked PARTIAL rather than interpreted.
An absence of a candidate must not be read as comprehensive verification of all
such side effects, schema constraints, actual roles or deployed DB state.
TRUNCATE is not analyzed as an ordinary RLS row operation.

## Three independent evidence dimensions

1. SOURCE_DECLARATION: exact source hashes, static policies and scoped ACL sets.
2. DECLARED_REQUIREMENT: authored control requirements only; no new project
   owner approval, no field-name ownership inference, no Intent #13 integration.
3. CONTROLLED_RUNTIME: PostgreSQL 16.14 behavior for fixed controlled roles,
   auth.uid setting stub and authored data. Not Supabase JWT/PostgREST/production.

PUBLIC policy permission is not actual public availability. Sharing intent and
effective role remain unresolved even if a broad declaration is established.
A protected column is protected in the control only because the authored test
contract names it. A column called owner_id is not thereby a product business
ownership assertion. General field edits and ownership transfer remain distinct;
the prior Intent evaluator's branch order/CONDITIONAL_MATCH is not rewritten.

## Same-population static differential

Fourteen fixed SQL controls were evaluated on v33 and v34 twice each. Eight
require a broad-write review candidate and six do not. Their input SQL hashes
and expectations are fixed separately from engine output. Cases include column
grant, revocation, PUBLIC, restrictive-only, restrictive guard, permissive
widening, omitted check, old/new row asymmetry and disabled RLS.

| Declaration-review contract (not real-app BOLA metrics) | v33 | v34 |
| --- | ---: | ---: |
| TP candidate contracts | 4 | 8 |
| FN candidate contracts | 4 | 0 |
| FP candidate contracts | 0 | 0 |
| TN reviewed declaration contracts | 6 | 6 |

No case moved to UNKNOWN to obtain this improvement. Separate Worker cases test
UNKNOWN for missing SQL, inheritance, dynamic SQL and unsupported policy helper;
those cases are not appended to the 14-case denominator. Normal ownership/column
protection and intentionally shared access are not asserted solely by no warning.
An explicitly intended shared/public column-write control can still have a
broad-declaration review candidate. That is not counted as a confirmed BOLA TP
or business-intent FP; the product has not been given an approved intent contract.

The missing static-tool failure gate was found in non-blind technical review and
fixed: baseline now exits 2 at 10/14 matching contracts (expected baseline misses)
and the new engine exits 0 at 14/14. Results are written before this diagnostic
exit, not hidden. The reviewer did not independently approve requirements or
rerun PostgreSQL, and the controls are not an external blind holdout.

## PostgreSQL 16 isolated oracle

Only authored SQL is executed in a fresh private temporary cluster. No TCP
listener; unique socket directory, fixed separate port, data_directory assertion,
statement timeout, restricted environment and finally stop/delete cleanup.
Authenticated A/B share one controlled DB role with different synthetic UUIDs;
anon and limited_admin are separate NOBYPASSRLS roles. limited_admin's explicit
policy/grants authorize its control operations, not arbitrary real admin code.

- Main matrix: 14 configurations x 4 actors x 8 probes = **448/448** matched.
  SELECT other, INSERT other, own/other UPDATE, protected own field, ownership
  transfer, DELETE other and claiming another user's row by changing its owner.
- Owner/FORCE/BYPASS exceptions: **8/8** matched. FORCE constrains the non-bypass
  table owner; a BYPASSRLS role remains exempt. These roles are runtime controls,
  not new effective-role inference in the product.
- Query prerequisites: **13/13** matched. UPDATE without reading other columns
  can work without SELECT; WHERE/RETURNING can require SELECT, and returning an
  ungranted column fails. With SELECT privileges but no SELECT policy, the same
  UPDATE can affect two rows without reading them but zero with a read-dependent
  query. Owner SELECT policy filters the other row and rejects a returned changed
  row that no longer satisfies it.

Every main/probe record captures SQLSTATE, affected count, RETURNING values and
exact pre/post rows, including preservation of the uninvolved user's row.
Zero matched rows differs from SQLSTATE 42501; neither is silently counted as a
successful write. Main 448 and exceptions 8 were repeated consistently; the
final 13 prerequisite checks were run once, not claimed twice.

The earlier 392-probe run was extended with 56 explicit claim-other probes;
these counts are not independent samples. Existing historical #11 **560** oracle
records are preserved unchanged and not included as newly executed tests.

An initial local evaluator attempt failed while reading multiline json_agg
output; jsonb_agg output handling fixed the tool before the completed runs.
No database expectations were changed based on a favorable engine outcome.

## Controlled correction and actual backend integration

Column-broad allows authenticated A to change B's body and vice versa (one row).
It denies the ungranted protected/owner columns. Column-owner-fixed retains
UPDATE(body) but adds reviewed USING/WITH CHECK equality for the fixture's
explicit owner relationship: own body update succeeds, other update is zero,
protected/owner update is denied. This is a controlled correction, not SQL to
copy into an unknown customer's schema. Table UPDATE plus a column REVOKE still
permits that column; the corresponding test is preserved.

Three authored Next PATCH/Client/write/SQL controls were analyzed on both actual
backend builds with isolated H2, identical input bytes/plan, two runs each.
Plan SHA-256 `78e11ed3769d5ee56445f6e1410accf55633cf292ce748879f0fe6381b0aac7d`.

| Input | v33 | v34 |
| --- | --- | --- |
| Column-only broad SQL | 0 policy candidates / UNKNOWN | 1 candidate / BROAD_ACCESS_REVIEW |
| Owner-restricted correction | 0 / UNKNOWN | 0 / CONFIRMED_POLICY_EVIDENCE |
| Missing later SQL | 0 / UNKNOWN | 0 / UNKNOWN |

All three have confirmed request association and UPDATE declaration. Effective
role remains UNKNOWN in both versions; CONFIRMED_POLICY_EVIDENCE means repository
predicate evidence, not safe field permissions or a successful runtime request.
Legacy rules remain 0, score 100, Risk REVIEW_REQUIRED; Coverage is PARTIAL for
the first two and FAILED for the deliberately missing-input control. No case is
promoted to READY. New candidate NOT_COMPARED does not resolve old snapshots.

New real original-application vulnerability TP = **0**. No independently approved
requirements or real Supabase operating authorization was obtained.

## Existing apps, regression and resources

- Existing 15 fixed inputs, source SHA/plan unchanged, each twice through actual
  H2 analysis: legacy raw/filtered rules, Score/Risk/SCA and all old structural
  candidates retained. RLS table metadata and candidate identities unchanged;
  explanatory guidance differs intentionally. DVNA/Goof and the four prior
  AI-assisted app families are retained regression, not independent new TP.
- #18 35 / #19 53 / #20 36 classifications unchanged against v33. #21 26
  identity-filter/request/role evidence contracts unchanged (known 25/26 full
  desired evidence still 25/26). Comparison excludes only worker version and
  revised explanatory reason/recommendation, not state/role/filter facts.
- #22 90 cases against v33: unchanged TP32/FN1/FP0/TN30/UNKNOWN27; repeat stable.
  The known Express URL-selector miss remains a miss.
- Worker **698 pass**; Backend **702 tests, 0 failures/errors, 9 existing skips**;
  evaluation tools **244 pass**; Frontend **165 pass + build passed**. Frontend
  build metadata is reverted/excluded. Python analyzer is unchanged; no new
  separate Python suite run is claimed for this SQL-only change.
- ZIP/mocked public/private GitHub, Workspace/revision/isolation, repair/rescan,
  Snapshot/Before-After/history existing suites pass. No new browser/live GitHub
  or operating-service E2E was performed. No paid AI, target build/install/run,
  original downloads or beta deployment. No access denial was bypassed.
- App analysis observations **221-913 ms**, maximum sampled parent JVM heap
  **179639808 bytes**, not peak Worker memory. Single authored SQL Worker RSS:
  v33 **128253952/129875968**, v34 **129826816/129236992** bytes, about 0.16s.
  Work steps **109 -> 109**, unchanged limits and 192 MiB old-space. Small samples
  do not establish a speedup or hard RSS bound.
- Pre-existing Gradle deprecation warnings remain; no unrelated dependency edits.
- column-update-v1 and Intent contracts unchanged. Intent #13 SHA-256:
  `93fe972e3b9177c01317a815607679cf270e91405859e9ca8d21f979bacc3c2e`.
  Historical #11 result SHA-256:
  `966d3453c1e9eb19e3761053351bda49bd799d4cc993bc386a628a285b3b9698`.

## #22 accounting clarification (no old records changed)

The same 90 records, not different populations, contain these BEFORE categories:
TP15 + FN18 + FP4 + TN16 + normal-deferred10 + UNKNOWN22 + unexpected-candidate5.
The earlier short handoff omitted normal-deferred10 and compressed the 27
uncertain controls imprecisely. Full #22 JSON and report already kept all states.
Those ten are not TN. Five uncertain candidates moving to UNKNOWN are not known
normal FP reductions. Only the four reviewed normal FP count toward FP4 -> 0.
No improvement percentage is derived by dropping deferred or uncertain cases.
Original #22 result SHA-256 remains
`45ee4d57edd4de51a6fd34360950c21ea6d175f498b51d61aea05cdbfeeb573b`.

## User guidance and next boundary

The existing Finding now explains possible column-only scope, real-role and
sharing intent checks, SELECT prerequisites, table grants surviving column
revocation, normal/admin feature impact, old/new row distinction and local
two-user verification. It explicitly disclaims a ready-to-run operating patch.
Locations still point to policy/table/grant declarations, and direct request
write evidence remains separately available for manual remediation/reinspection.

Next P1 priorities: bound additional SELECT/INSERT column ACL declarations;
validate explicit role/schema/owner premises with an independent reviewer;
connect precise per-field query prerequisites without claiming a full SQL/role
interpreter. Complex inheritance, views, SECURITY DEFINER, triggers, deployed
policy state and real JWT remain UNKNOWN/not supported, not silently safe.
Do not auto-integrate Intent #13, infer business ownership from names, add
generic absent-auth Findings or expand automatic SQL repair without approval.
