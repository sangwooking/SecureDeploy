# Access-control evidence hardening #21

## Baseline and decision

Origin baseline `8c35a52b409b61d424c82e1c48170b755bbc43ce` (Worker v31).
Implementation `3bff39521d5b26783dbc3ef99ecb625c4663a08e` (Worker v32).
The runtime checkout remains `15070416`, v28 process PID 99387 on port 8080.
No restart, user PostgreSQL/Review/Workspace update or product API/schema/UI change.

[The P0/P1/P2 matrix](security-coverage21.md) inventories the requested areas,
actual rules/modules, normal and UNKNOWN boundaries, tests, application evidence
and guidance availability. General JS missing-auth/admin/IDOR detection is not
claimed. Target upload, end-to-end CSRF and target rate limiting are not implemented.

The safe selected improvement is identity-to-row-filter evidence consistency,
NOT a generic absent-permission Finding. The existing analyzer could observe
awaited getUser/getClaims, an absence exit and direct user.id/claims.sub in eq,
but lost the same immutable value through a const alias, destructuring or match.
The write-origin evaluator already used the bounded origin resolver, creating
inconsistent descriptions of the same local write/filter.

## Implementation boundary

- `analyzers/typescript/auth-result-evidence.mjs:41` reuses existing origin
  resolution for ID values; `:64` links eq and inline static match predicates.
- Same Client provenance, same enclosing function, awaited identity result,
  local absence exit, immutable bindings and existing escape checks are required.
- A match object must have at most 16 plain/shorthand fields. Spread, computed
  fields, duplicates and prototype-sensitive keys are rejected. At most four
  filter locations are emitted; existing 5000 link-work budget remains.
- Existing `authorizationEvidence.authChecks[].resultEvidence.userIdFilters`
  and Coverage count receive locations, not new fields or security states.
- A column compared to a user ID is NOT automatically an owner column. No
  runtime login, role, sharing intent, deployed policy or actual row access is
  inferred. No new Finding or repair allowlist was added.
- Worker version handshake/tests move to v32; old v31 snapshots round-trip
  unchanged, and structural NOT_COMPARED behavior is preserved.

The [official match API](https://supabase.com/docs/reference/javascript/match)
describes multiple column equalities; [eq](https://supabase.com/docs/reference/javascript/eq)
describes a single equality. These API semantics do not prove authorization.
The [getUser API](https://supabase.com/docs/reference/javascript/auth-getuser)
also supports an explicit JWT; that pre-existing result-evidence gap was observed
in CopyMonster but is NOT expanded in this implementation.

## Controlled results

26 authored controls compare frozen v31 and v32 twice. These are not a blind
holdout or an external security oracle. They include read/update/delete, Next
Route Handler/Server Function, request-object IDs plus a separate identity
filter, public/shared intent uncertainty, client-only checks, administrator names,
sessions, mutations, dynamic filters and unverified helpers.

| Evidence contract | v31 | v32 |
| --- | --- | --- |
| Positive cases with complete expected filter evidence / 10 | 1 | 9 |
| Positive cases still partial / 10 | 9 | 1 |
| Controls that must not gain identity-filter proof / 16 | 16 | 16 |
| All complete contracts / 26 | 17 | 25 |

The remaining partial control wants two filter observations but retains one:
the first ID argument use triggers the existing conservative escape rule before
the second call. Its desired count was not changed to manufacture success.
Other UNKNOWN conditions are not marked safe. Request-controlled record ID and
verified-API-result evidence remain distinct write-filter sources in the update
control. VERIFIED_USER_EVIDENCE is the existing enum for local API/guard evidence,
not runtime authentication success.

These counts are NOT TP/FP/FN/TN for IDOR. New independently verified real-app
IDOR TP = 0. Runtime two-user authorization tests = 0. Real-app FP/FN/TN are not
measurable without an independent owner/schema/intent/runtime oracle.

## Real application and equivalent-code differential

All fixed 15 retained application inputs were re-evaluated twice through actual
analysis services with isolated in-memory H2; no Review persistence or external
SCA/AI calls. The prior #20 evaluated product code is byte-identical to baseline
8c35a52 (the later changes were tests/docs only), so its frozen receipts are used
for same-source comparisons. The new alias control additionally runs on freshly
built baseline v31 and current v32.

- Original 15: exact structural Finding identities, legacy raw/filtered rules,
  Risk, score, SCA observations, Client/table/policy metadata and authorization
  summaries retained. Sources/SHA/plans unchanged, repeated results stable.
- DVNA SQL/shell, Goof shell and #20 login candidate, Echoverse environment
  response, Next/Deno/Express regressions retained. No extra IDOR warning.
- Chatbot UI original SHA `81328b61d2a4ab597a7a057be70e785cf756d9f8` (MIT):
  `lib/server/server-chat-helpers.ts` has a local getUser/absence guard and direct
  user-ID predicate; both versions retain one identity-filter observation.
- A separate full-source Grade B differential changes only the helper's direct
  ID expression to an immutable local alias. All 308 retained source file hashes
  were verified before copying, the original was not modified, and the altered
  file hash is `9f6e73314a39db9c9b4e3f88c1116413041977bc8571516a4d0e5914a659d0ab`.
- Same differential plan hash on both engines:
  `a7f72d10671f15dc7999a1e62b64a7d8d9daa6464d5665da2e87f1ea4c2207d0`.
  v31 identity-filter observation 0 -> v32 1; all legacy judgments unchanged.
- This helper has **no requestEntry association** in both runs. Its policy and
  effective role remain UNKNOWN. This proves preservation of local evidence in
  actual-app structure, NOT an HTTP end-to-end vulnerability fix or new real TP.
- CopyMonster getUser(token), calls between guard/access and external role RPC
  prevent stronger evidence. They are recorded as unsupported/unknown, not
  authentication absence, missing admin checks or a confirmed IDOR.

No external source was downloaded for this task, installed, built, executed or
attacked. Only SecureDeploy's own code and authored analyzer tests were built/run.
External application source/control copies and raw local receipts stay outside Git.

## Tests, resources and compatibility

- Worker: 597 passing tests, including 28 new access-control checks.
- Backend: 698 tests, 0 failures/errors, 9 existing skipped tests.
- Python analyzer: 117 passing tests; evaluation tools: 238 passing tests.
- Frontend: 165 passing tests and production build passed; generated build
  metadata excluded. No browser/live GitHub App E2E performed in this task.
- #18 35 / #19 53 / #20 36 cases retain original source/expectations and exact
  before/after state counts. RLS v3/column-update modules unchanged. Historical
  PostgreSQL oracle data preserved; PostgreSQL was not rerun or contacted.
- #13 result SHA-256 unchanged:
  `93fe972e3b9177c01317a815607679cf270e91405859e9ca8d21f979bacc3c2e`.
- Original 15 input analysis observations: 211-822 ms; maximum sampled parent
  JVM used heap 169922208 bytes. This is not peak Worker RSS.
- Single authored alias Worker RSS, v31: 132431872 / 133316608 bytes;
  v32: 130891776 / 130039808 bytes. Work steps: 341 -> 352 of 100000.
  Existing 192 MiB old-space limit is not a hard RSS limit. Small local samples
  do not prove a performance improvement or a bound for all projects.
- Full-app alias control wall times: v31 902/697 ms, v32 1177/790 ms. No
  speed improvement claimed. File, depth, AST, time and memory limits unchanged.
- Existing ZIP/mocked public/private GitHub, workspace ownership/revision,
  editing, AI/deterministic repair, rescan, comparison and history tests passed
  in the complete Backend/Frontend suites. New live acquisition not claimed.
- RLS v3, column-update-v1, Intent #13-#15, Risk/Score/BLOCKING, existing Review
  and Snapshot data were not reinterpreted. No migration, paid AI or deployment.
- Gradle deprecation and pre-existing ANTLR 4.11.1/4.13.0 mismatch warnings were
  present on both fresh baseline and current app-control builds; builds passed.
  Their dependency cleanup is outside this access-control change.

## Beginner review guide (not an automatic patch)

1. Identify the API and the request value selecting a record; this is different
   from the current user's authenticated identity.
2. Check which server code rejects a missing/invalid identity. A client-side
   button or a variable named admin is not enough.
3. Confirm the application's actual ownership/share/admin requirements with its
   owner; do not select an owner column by its name alone.
4. Check the record query/update/delete and the corresponding stored DB policy.
   An application filter does not establish the behavior of direct DB access.
5. With two owned local test accounts, verify permitted actions, another user's
   ID, unauthenticated access, shared/public exceptions and protected fields.
   Do not run these tests against someone else's deployed service.
6. Reinspect the same source/policy revision after changes. UNKNOWN is not
   resolved; no supported automatic/AI fix is enabled for this evidence.

The current result details already show auth checks, filter locations, policy
locations and unknowns. There is no new vulnerability Finding requiring new
product copy. Broader IDOR conclusions still need independent ground truth.

## Next priority

P0 is NOT complete. Prefer bounded request/principal/target/policy contracts and
separately reviewed two-user evidence over an absent-check rule. Keep explicit
JWT arguments, middleware, role functions, protected-property intent and runtime
policy activation separate until validated. For #22, reproduce environment
object mutation/return -> actual response gaps and public-vs-secret distinctions
before expanding secret patterns. Do not turn a helper-only observation into a
client exposure claim. Matrix and evaluation tooling are preparation, not those
new detectors.
