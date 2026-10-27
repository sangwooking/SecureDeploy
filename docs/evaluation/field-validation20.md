# Field-scoped validation and actionable remediation #20

## Baseline and scope

- Baseline: e278a87cc8eca9bbd2af5c1c424f8442ac54ae50, ts-server-v30.
- Evaluated implementation: 9f849069cb8272bb0c1e668163c5da0b208411ed, ts-server-v31.
- RLS v3, column-update-v1, Intent contracts, Risk and score formulas unchanged.
- The runtime checkout remains at 15070416 and the existing v28 process is not restarted.
- No new API, schema, UI, automated patch or Mongoose query API was added.

## Source-reviewed real application

The retained Apache-2.0 Goof source is pinned to
`add14ba59e98240d9e00a235dd7d42cd61ae9912`. All 50 retained file hashes were
checked; 10 omitted binary assets remain omitted. This is not a new independent
project, blind evaluation, verified upstream fix pair or runtime exploit test.

The prior documented-vulnerable-application-path standard was retained, not
relaxed. The [pinned README](https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md)
lines 110-127 describe the login query issue. Locally verified evidence:

| Evidence | Location |
| --- | --- |
| JSON / form request parsers | app.js:47-48 |
| POST login registration | app.js:55 |
| validator module binding | routes/index.js:12 |
| Email condition on username only | routes/index.js:51:7 |
| Independently unvalidated password source | routes/index.js:52:56 |
| Mongoose query filter | routes/index.js:52:5 |
| Model declaration | mongoose-db.js:17:1 |
| Callback reference / execution request | routes/index.js:52:77 / 52:5 |

The manifest and lock declare validator ^13.5.2 / 13.5.2 and Mongoose 4.2.4.
Installed versions, schema casting, middleware, actual database state, password
storage and authentication bypass are not execution-verified facts.

The failure was the unresolved validator result marking the enclosing request
path uncertain. It was not a missing query sink or callback-version contract.
The fix preserves a known boolean branch while recording exactly which field
was checked. Username format evidence cannot certify password or another field.

## Supported contract

Verified native validator provenance, a static declared 13.x.y / ^13.x.y /
~13.x.y version, one-argument direct `isEmail` calls, simple if/else or early
return, negation, boolean aliases and local request-field aliases are supported.
Static body/query leaf identities are request-local; equal names in different
containers do not share facts. Strict typeof string guards provide a separate,
field-local primitive-type fact. Facts are bounded to 32 per branch, consume the
existing work budget, and are invalidated by unsupported effects.

The official [13.5.2 isEmail implementation](https://github.com/validatorjs/validator.js/blob/13.5.2/src/lib/isEmail.js)
and [assertString implementation](https://github.com/validatorjs/validator.js/blob/13.5.2/src/lib/util/assertString.js)
were read, not executed or vendored. assertString also accepts boxed String
objects: email format is not primitive-string proof or general query sanitization.
The 13.0.0 isEmail and 13.15.0 assertString sources were also checked; this is a
bounded static API contract, not testing every installed 13.x release.

Unknown modules/versions, overwritten validators, optional validator arguments,
dynamic/nested fields, AND/OR, helper effects and stale/mutated values retain
UNKNOWN. Field facts do not become SQL, shell or eval sanitization. A full shared
heap, validator execution, regex execution or arbitrary callback interpreter was
not introduced.

## Results

Each real-app version and authored control was evaluated twice through the
production analysis services with isolated in-memory H2 and external lookups off.
No Review was saved and no user PostgreSQL connection was used.

| Goof measurement | v30 original | v31 original | v31 authored type control |
| --- | --- | --- | --- |
| Selected / parsed JS files | 10 / 10 | 10 / 10 | 10 / 10 |
| HTTP entries | 15 | 15 | 15 |
| Target login result | UNKNOWN | REVIEW_REQUIRED | STATIC_OR_STRING_FILTER |
| Structural findings, all kinds | 1 | 2 | 1 |
| Existing shell finding | 1 | 1 | 1 |
| Legacy score | 23 | 23 | 23 |
| Wall ms, two observations | 659 / 503 | 622 / 481 | 617 / 475 |
| Charged steps / 100000 | 26097 | 26231 | 26515 |

The new login finding is source-reviewed static TP 1 under the existing standard;
new independent-project TP 0 and runtime-verified TP 0. It remains
REVIEW_REQUIRED / NOT_COMPARED. Its primary Source is password, while username
validation is separately retained in defenses. There is one query finding, not
one duplicate warning per input field.

The control inserts two primitive-string rejection guards into a separate local
copy. It is Grade B authored differential evidence, NOT an upstream patch or a
real fixed-app TN. Original files remain unchanged. The query and shell path are
still observed; absence of the target warning is not an uninspected-path claim.

### Authored development controls, not independent accuracy

The 36 controls have 13 labeled risks, 4 normal contracts, 16 deferred contracts,
and 3 separate unreachable/query-construction/unrelated-API cases.

| Labeled subset | v30 | v31 |
| --- | --- | --- |
| Risk candidates / 13 | 2 | 12 |
| Known risk not detected / 13, all UNKNOWN | 11 | 1 |
| Normal false candidates / 4 | 1 | 0 |
| Normal static/string confirmations / 4 | 1 | 4 |
| Normal UNKNOWN / 4 | 2 | 0 |
| Deferred contracts, UNKNOWN / 16 | 16 | 16 |

Total UNKNOWN is 30 -> 18, including the unrelated API observation. Unreachable
code and query creation are not counted as TN. The nondominating type-check case
retains RISK truth and an explicit known gap: branch heap merging loses the
callback version proof. It is NOT relabeled normal or resolved to pass a test.
No product-wide precision/recall claim follows from these authored controls.

## Regression and resources

- Worker: 569 passing tests (38 new field-focused checks).
- Backend: 697 tests, 0 failures/errors, 9 existing skips.
- Frontend: 165 passing tests and production build passed; no UI files changed.
- Evaluation tooling: 236 passing tests.
- Existing #18 35 and #19 53 source/expected-state fixtures unchanged; all state counts preserved.
- Fixed 15 application inputs, two runs each: all legacy raw/filtered rules,
  score, Risk and SCA observations unchanged. All previous structural identities
  retained; only Goof adds the target candidate. Four vibe-app observations,
  DVNA shell/SQL and Deno/Next exposure regressions retained. Other 14 inputs have
  identical structural identities and Client/access/table/policy metadata.
- Repeated observations match after excluding timing/heap measurements.
- Goof selected-worker RSS: v30 146653184 / 147898368 bytes; v31
  143196160 / 144539648 bytes. These are small local samples, not a speed/memory
  improvement guarantee or whole-backend peak. The 192 MiB V8 old-space setting
  is not a hard RSS cap. File/AST/time/work/heap limits were not increased.
- #13 result SHA-256 remains
  `93fe972e3b9177c01317a815607679cf270e91405859e9ca8d21f979bacc3c2e`.

The complete suite includes input isolation, timeout, ZIP and mocked GitHub
integration, editing/revision/permission and Before/After tests. No new live
GitHub acquisition, browser E2E, external reviewer, attack or runtime application
test was performed. User Review/Workspace/Snapshot data and three private
untracked documents were not modified. No paid AI, installation or deployment.

## User guidance and remaining work

Existing riskExplanation, recommendedAction, evidence and execution locations
carry the new copy to result details and Workspace. Guidance explains object vs
string input, checking every queried field, fixed operators, conditional review
of hash-based authentication, local normal/object/rejection tests and reinspection.
It does not claim plaintext storage, a successful attack, an automatic fix or
runtime compatibility. No unsupported AI/automatic-fix button is enabled.

Remaining: complex validators, helper/callback effects, some branch capability
merges, runtime casts/hooks and real fixed-pair independent validation. Prefer a
separately reviewed fresh Mongoose application and bounded branch-merge evidence
before another API expansion. No FlintCMS class/event expansion is authorized.

Reproduction tools: `field_validation20.py prepare` verifies and constructs the
private control; `audit` checks paired H2 receipts; `mongoose18.py --case-set
field20` compares frozen and current workers without running target modules.
Outputs must be outside checkouts. Source-free result metadata accompanies this
document; retained source, control source and raw local logs are excluded.
