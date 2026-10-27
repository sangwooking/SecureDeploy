# Version-Aware Mongoose Callback Execution 19

This is a static API-contract extension, not an exploit reproduction, independent
evaluation or a new real-application vulnerability TP. The baseline is
e12fae9 (v29); results and receipt hashes are in
`scripts/evaluation/callback19-results.json`.

## Verified Contract

The [Mongoose 6 Model contract](https://mongoosejs.com/docs/6.x/docs/api/model.html#model_Model.findOne)
and [Mongoose 4 Query contract](https://mongoosejs.com/docs/4.x/docs/api.html#query_Query-exec)
support callbacks. The [Mongoose 7 migration guide](https://mongoosejs.com/docs/7.x/docs/migrating_to_7.html#dropped-callback-support)
explicitly removes callbacks for find, findOne and exec.

v30 recognizes resolved function/arrow/declaration values, aliases and limited
source imports for declared 4.x-6.x. Direct find/findOne requires an explicit
filter, followed by a callback or a static null/string projection and optional
supported options before the callback. Options retain the v29 sanitizeFilter/
strictQuery whitelist. exec(callback) supports exactly one resolved callback;
the optional exec operation-string overload is not supported. Dynamic argument
positions, object/array projections, unresolved callbacks and ambiguous version
ranges remain UNKNOWN. Declared versions are not installed-runtime proof.

7.x-8.x callback forms are unsupported execution requests, not injection
findings; adding await to an invalid callback form cannot manufacture execution
evidence. A string merely named callback remains projection data. Query creation
without execution remains separate. Same-Query repeats and callback/Promise
mixing preserve the first valid request and record later uncertainty without a
second finding. Distinct queries remain distinct; shared query locations retain
multiple source evidence paths in one user finding.

No callback body is invoked or data-flow analyzed. Nonempty callback effects
invalidate subsequent Mongoose protection certainty in that request graph,
without suppressing unrelated existing SQL/environment findings or contaminating
another request. Execution/source/model/defense uncertainty reasons are explicit.
String, limited toString, sanitizeFilter and trusted boundaries remain v29's.
Risk, RLS, columns, auto-fix allowlists and old snapshots are unchanged.

## Measurements

53 authored development controls run twice per Worker and twice through the
isolated H2 product pipeline. 21 risk-candidate cases (one containing two distinct
queries) yield 22 validated candidates. The other controls yield 6 removed-API
states, 3 static/string results, 3 declared defenses, 18 UNKNOWN and 2
construction-only results. Non-risk cases generate zero selector candidates.
These are not 53 independent applications or product-wide Precision/Recall.
The v29 baseline recognized one risk case (its repeated await produced two raw
candidates); this is not a claim of 20 repaired real-app vulnerabilities.

The old 35 sources and expected classifications remain unchanged: 8 candidates,
5 static/string, 3 declared defenses, 18 UNKNOWN, 1 construction-only. One new
control changes from a prior defended observation to UNKNOWN because callback
effects on a subsequent query were previously unmodeled. This is not an FP
removed by establishing safety.

## Retained Applications

Both engine versions replay the retained applications with unchanged source
plans and per-file verification. Goof uses Mongoose 4.2.4 in its manifest and
lockfile, not a verified installed runtime. Its routes/index.js:52 now preserves
request body sources, mongoose-db.js:17 model declaration, callback reference
and callback execution request. The validator.isEmail branch is still
MONGOOSE_REQUEST_PATH_UNRESOLVED, so no selector candidate is promoted.
Its existing command finding remains; 15 entries are recognized before/after.

node-express-boilerplate (^5.7.7 declared; runtime unverified) still has zero
entries with its wrappers/plugins. FlintCMS's pinned vulnerable and patched
trees still have zero entries and zero target findings. Callback support does
not solve class/event initialization. Zero-warning targets are not counted as
safe TN. New real-application TP: zero.

The 15 fixed regression inputs retain rules, Score, Risk, existing TS findings
and RLS evidence. All application/control repeats are consistent. Samples of
parent JVM heap are not whole-service peak RSS; resource limits are unchanged.
Live GitHub acquisition and browser tests were not performed.

## Reproduction and Operational Boundary

Use the existing evaluator with `--case-set callback19`, a clean v29 baseline
checkout, and outside-Git outputs. Generated batches use applicationEvaluation
with H2 and external lookups disabled. No npm installation, target code execution
or exploit request is used. An initial runtime symlink was correctly refused by
clean-tree/Node read boundaries; copying the existing trusted parser runtime
inside the baseline checkout resolved setup without broadening permissions.

The running v28 backend and its original main checkout are preserved. v30 must
not be applied there without separate coordinated-update approval. No existing
user Review, Workspace, source or database was modified.

Next priority: evaluate the remaining external-predicate/branch uncertainty with
independent source/defense evidence. Do not merely trust a function named isEmail
or let a check on username certify a different password field. Callback result
data flow, sort/other query chains, class startup and DB events remain separate
future contracts, not implied support in this milestone.
