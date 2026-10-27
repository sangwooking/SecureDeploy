# Mongoose Selector MVP 18

This is bounded static analysis, not a reproduced exploit or an independent
accuracy evaluation. The implementation commit and source-free measurements
are in `scripts/evaluation/mongoose18-results.json`.

## Contract

The existing Express registration, symbolic values, CommonJS/ESM links,
per-request isolation and AST budgets are reused. The supplemental rule is
`JS_MONGOOSE_SELECTOR_INPUT_FLOW` (CWE-943), REVIEW_REQUIRED and NOT_COMPARED.
It is not input to the legacy score, Risk or automatic-fix allowlist.

Declared Mongoose 4.x-8.x versions, default imports or require,
explicit flat scalar Schema/model registration and a same-instance model
registry lookup are supported. Aliases and static module exports retain origin.
Schema options, custom setters, plugins, hooks, missing registrations,
dynamic model names and unknown versions are outside the verified contract.
Installed versions, schema casts and deployed database state are not proven.

`find`/`findOne` create query observations. Only await or direct no-argument
`exec()` requests generate execution observations and eligible candidates.
Callbacks, arbitrary chaining, then/catch handlers, class startup and DB events
are not promoted into execution proofs. Filter mutation after construction
is UNKNOWN rather than an assumption about Mongoose copying behavior.

Only String conversion and already-proven primitive string toString results
reduce selector-object risk; an arbitrary request value's toString is UNKNOWN.
This metadata never certifies SQL, HTML or other sink safety. The old unknown
call behavior is retained for other analyses.

Mongoose 6 introduced sanitizeFilter and trusted; see the
[official migration contract](https://mongoosejs.com/docs/6.x/docs/migrating_to_6.html#sanitizefilter-and-trusted).
Static query/global settings are considered for ordinary field filters only.
Dynamic options, pre-6 sanitizeFilter, trusted exceptions and whole request
filters with sanitization remain UNKNOWN. strictQuery is not this defense.
[Query casting](https://mongoosejs.com/docs/tutorials/query_casting.html)
occurs at execution, not merely at construction; real runtime behavior is not
observed by this analyzer.

## Evaluation

35 authored development inputs were replayed twice against v28 and v29, and
twice through the isolated H2 product pipeline. Before: no selector contract
in all 35. After: 8 candidates, 5 static/string cases, 3 declared defenses,
18 UNKNOWN, 1 construction-only. One UNKNOWN is the ordinary API control:
its object-method syntax is unsupported, not proven to be a Mongoose receiver.
There were zero unexpected candidates on the non-risk controls. This does not
establish product-wide Precision/Recall or actual runtime remediation.

The 15 fixed regression inputs preserved raw/filtered rules, Score, Risk,
existing TS findings and RLS evidence. DVNA's command/SQL and Goof's command
findings remain. FlintCMS's original pair still has zero recognized entries
and zero target findings; the known CVE remains unsupported, not solved.
The retained node-express-boilerplate also has zero recognized entries.
Goof's callback query and initialization context do not yield a new selector
finding. New real-application TP: zero; unexamined/no-warning paths are not TN.

To reproduce authored Worker results without target execution:

```sh
python3 -B scripts/evaluation/mongoose18.py --repo /path/to/new-checkout \
  --baseline /path/to/v28-checkout --output /outside/results.json \
  --prepare-root /outside/new-controls
```

Use the existing `applicationEvaluation` task on each generated batch for H2
integration. No dependency install, app build, database connection or PoC is
needed. External original sources and raw temporary receipts stay outside Git.
Live GitHub acquisition and browser testing were not performed for this change.

## Follow-up Boundary

Callbacks/query execution and schema/model initialization are separate future
contracts requiring evidence and approval; neither is implicitly enabled here.
The user's v28 backend and its dynamically referenced Worker checkout must
stay together. Do not fast-forward that checkout to v29 without a separately
approved coordinated update. This milestone does not restart the server or
recalculate old Reviews, Snapshots or Intent results.
