# EPIC-01 PHASE D+ — static handler links and evidence completeness

Baseline 614838ff8084f13ef9ded764f86a07360b37b538 / ts-server-v51.
Candidate ts-server-v52, same codex/epic01 worktree. No operating deployment,
paid model request, external project execution or new Rule ID.

## Pipeline audit and measured population

The production path is ProjectFileCollector/CoverageRecorder ->
TypeScriptSourceSelector -> TypeScriptServerAnalyzer -> worker/analyzer.mjs ->
node-server/next + module/export/async/object adapters -> Source/Sink observations ->
Java validation/ServerFlowFinding -> immutable Review. Python uses its separate
bounded Django/DRF evaluator. Project inventory and parser admission are different.
SourceSelector schedules declarations/import hints; a regex hint never proves an
endpoint or vulnerability. The current selector does not promise .mts/.cts support.

33 newly authored TypeScript/Node scenario inputs, identical before/after:

| Observed stage (scenario occurrences, not unique real-project files) | v51 | v52 |
|---|---:|---:|
| Supplied source file occurrences | 51 | 51 |
| Worker recorded file occurrences | 51 | 51 |
| Parsed successfully | 50 | 50 |
| Parse failure | 1 | 1 |
| Declared supported entries (includes Worker fetch) | 14 | 21 |
| Express registration observation records | 8 | 11 |
| Next route contexts | 4 | 8 |
| Function bodies entered | 15 | 22 |

One additional inventoried source is deliberately not supplied. It remains
UNRESOLVED_OR_UNSELECTED/UNKNOWN, distinct from the malformed parsed file. Java
selector regression separately supplies108 source candidates, admits100 and records
8 omissions by SOURCE_FILE_COUNT_LIMIT. The product upload/Workspace integration
has2 discovered/selected/parsed source files before and after,2 HTTP registrations,
and removes only the selected helper response while preserving the other Sink.
No whole-project/deployed-endpoint percentage or total call graph denominator exists.

`evaluatePipeline` is an evaluation-only Symbol-gated sidecar; ordinary worker JSON
schema is unchanged. It reports observed module target selections, resolved user
call targets, main-flow fallback calls and bodies entered/blocked by depth/cycles.
It is capped at1000 records per category, explicitly marks truncation and does not
interpret missing observations as safety. Native/adaptor operations can be handled
in separate passes (notably Supabase); fallback calls are not a complete inventory
of unsupported functions. Older v51 has no sidecar: missing old counters are unknown,
not zero. Registration/target observations and Source/Sink locations are retained in
normal NodeUse/Finding evidence. This is a bounded graph, not whole-program proof.

## Implemented structural changes

1. Express local ESM namespace callbacks: selected static named function exports and
   explicit re-export barrels can connect app/Router registration to imported handlers.
   CommonJS namespace interop, mutation, wildcard exports, client modules, missing/
   cyclic targets and side-effectful initialization remain outside the new contract.
   Existing mount/reachability/middleware checks still apply. An unmounted Router
   never acquires HTTP reachability merely because a function contains a Sink.
2. Next App Router static named re-export/local export lists: registered method location
   stays in route.ts; request/Sink locations stay in the actual selected helper file.
   Version/convention checks remain. Type-only, mutable, wildcard, client-boundary,
   missing and cyclic bindings do not become verified handlers. Pages API is still
   unsupported. Supported routing declarations are not deployed endpoint counts.
3. Evidence completeness: a scalar/exposure pass-through retains the callee parameter
   file/line; a registration file whose body is analyzed elsewhere is PARTIAL with
   an explicit linked-body reason, rather than NO_SUPPORTED_SERVER_ENTRY_OR_CALL.
   Large response Source/trace truncation now has explicit limitations. The observed
   risk remains; a truncated Source set never enables automatic Patch generation.

All new linked modules use a closed top-level grammar (functions, literal/function
constants, explicit imports/exports, types/directives). No target code is imported,
required, evaluated or installed by analysis. Dynamic module paths and unknown effects
are not resolved by guesses. Function invocation/AST/node/result/depth budgets remain.

## Independent results and oracle scope

`epic01-dplus-inputs.mjs` and Python evaluator are new local synthetic inputs, not
copies of a private application or an external accuracy benchmark. Code-reviewed
oracles concern explicit static data flow or an explicitly stated toy owner policy.
Source SHA256 manifests bind both cohorts to identical text. Existing external real
app regression inputs7 remain INPUT_UNAVAILABLE; hongik_bot source was not acquired.

TypeScript scenarios: TP7->12, FP0->0, TN3->5, FN9->4, UNKNOWN14->12; PARTIAL31/33
in both cohorts. Known-normal callbacks uninspected by v51 receive UNKNOWN rather
than TN until the engine actually enters them. All12 matched candidate Findings are
HIGH/REVIEW_REQUIRED static evidence, not runtime exploit or whole-app safety proof.
Five new matches: namespace callback, mounted namespace/barrel callback, Next named
method re-export, local import/export method list, multi-hop method barrel.

The object/destructuring + identity-helper control is already TP in v51, but v51
omits identity.mjs from its flow. v52 retains its exact parameter location. Do not
count this evidence improvement as an independently new vulnerability.

Remaining TypeScript FN: three-argument Router mount with middleware, Next pages/api,
computed env-name join, direct request HTML response. HTML/IDOR obligation names in
the evaluator are oracle labels, NOT registered Rule IDs. These worker-structural
results do not imply the legacy regex engine has no warnings for the same family.
Undefined sanitizer names remain UNKNOWN; parameter binding/string selector evidence
is scoped to supported library/usage contracts, not authentication or business policy.

Python (unchanged v8):5 new scenarios, TP2/TN2/FN1/FP0. In-memory A/B principal/owner
matrix executes only our synthetic function AST with fake ORM rows: correct guard,
inverted guard and authentication-only delete,4 combinations each. It proves those
12 toy owner-branch outcomes, not DRF login, installed ORM or real database behavior.
The inverted guard is detected; absence of ownership filtering is not inferred into
an IDOR Finding, even though our explicitly supplied owner-only oracle exposes a FN.
Remote Supabase effective role/RLS enforcement stays UNKNOWN. No arbitrary auth
middleware or a call named sanitize is treated as authorization/sanitization proof.

## Performance and stability

Fresh192MiB-heap Node processes:11 scenarios per version,3 repeats, including5/25/80/
120 files,1/3/6 call layers, cycles, dynamic imports, step cap and40 env-read sites.
Results are deterministic per same input/config. 120 submitted files admits100 with
explicit file cap;6 layers/cycles retain depth/cycle limits; step cap is PARTIAL.
40 read sites retain19 origin locations in the bounded trace; v52 explicitly reports
Source/trace truncation and keeps the observed risk and refuses automatic repair.
RSS is an observed before/after process sample, not peak or production capacity.
The uninspected v51 callbacks do less work; a runtime speedup is not claimed.

## Product integration and compatibility

New namespace evidence passes restricted child parsing, Java validation, Review,
owner checks, exact file/line selection and manual Workspace editing. The helper's
source file lacks the complete inline Express registration required by Patch: API422,
GUIDED_REMEDIATION retained. Manual Diff/export/rescan removes that response's risk,
keeps the other Sink,2 files/entries and unchanged original Review/reference score.
Existing deterministic A/B restart/restore E2E and8 Mock patch E2E pass on v52.
No new live GPT call or new actual-model claim. Old v51 snapshots remain readable and
unmodified. Candidate Java/Worker must be deployed or rolled back as a matching pair;
current operating Backend/Worker remain v51. Structural Finding IDs intentionally
include analyzerVersion; same v52 input/config remains stable, cross-version structural
results stay NOT_COMPARED. 72 Rule/Risk/Score/RLSv4/Deploymentv2 contracts unchanged.

Remaining EPIC-01 blockers are unchanged: old UX-03 provenance rollback reader,
operating key provisioning/restore/rotation and durable unified AI admission ledger.
Next engine priorities: bounded middleware-aware Router mounts; Pages API registration
with server response/HTML context; bounded computed env keys plus richer cross-file
identity/ownership contracts grounded in explicit policy and independent real inputs.

Framework references (declarations do not establish actual deployment):
https://nextjs.org/docs/app/api-reference/file-conventions/route
https://nodejs.org/api/esm.html
