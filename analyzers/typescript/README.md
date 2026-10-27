# Bounded server analysis runtime

## Static named export links (v41)

Existing registered requests can reach top-level functions exported through
`export { local }`, aliases and explicit `export { name } from './module'` chains.
Named default functions may be forwarded as `default`. Type-only exports are not
runtime values. Mutable, ambiguous, missing, cyclic, wildcard and namespace
bindings remain unsupported or UNKNOWN; syntax plans never cache request values.

Worker/Next source mapping stops at the first inventoried candidate, even when
that file was not parsed. It does not select another file because an export is
missing. Node continues to use its separate runtime-oriented resolver: explicit
ESM extensions and supported CommonJS directory contracts are not interchangeable.
Node forwarding modules must have no runtime initialization beyond declarations
and explicit exports; unknown initialization order is not treated as a valid link.

This does not add HTTP registration conventions, Pages middleware scope, package
exports/imports, conditional exports, wildcard barrels, class/event initialization
or general Promise execution. Existing depth, AST, step, output, file, time and
memory budgets apply. Parsing, static module references, reached functions and
Source/Sink evidence remain different measurements. No whole-project safety or
complete call graph is claimed. Rule IDs, RLS v4, Deployment v2 and Risk formulas
are unchanged; new reached candidates retain REVIEW_REQUIRED/NOT_COMPARED.

Contracts: [TypeScript modules](https://www.typescriptlang.org/docs/handbook/2/modules.html),
[module resolution](https://www.typescriptlang.org/docs/handbook/modules/reference),
[Node ESM](https://nodejs.org/download/release/v26.9.0/docs/api/esm.html).

Version ts-server-v30 recognizes version-declared Mongoose 4.x-6.x callback
execution requests for find/findOne and exec(callback). Functions must have a
resolved static origin and optional argument positions must be unambiguous.
Mongoose 7.x-8.x callbacks are recorded as unsupported; ambiguous versions or
callbacks remain UNKNOWN. Bodies are not invoked or traced, and unmodeled
callback effects make subsequent Mongoose protection context uncertain. Unrelated
SQL/environment contracts are not downgraded by this uncertainty. One Query's
repeated/mixed execution is not counted as another finding. RLS, columns,
Risk and historical snapshots are unchanged.

Version ts-server-v29 adds bounded Mongoose selector evidence; RLS v3 and
column-update-v1 meanings are unchanged. Mongoose support covers declared
4.x-8.x APIs, explicit flat String/Number/Boolean/Date Schema/model registration (and same-instance
registered-model lookup), CommonJS/ESM source links, and find/findOne consumed
by await or direct exec(). Merely constructing a query is not execution.
Input objects may produce REVIEW_REQUIRED/NOT_COMPARED candidates; runtime
casts, plugins, middleware, installed versions and database access are unverified.
String conversion evidence is local to this selector contract, not SQL/XSS safety.
sanitizeFilter is considered only for declared 6.x-8.x and static field filters;
unknown settings, trusted exceptions, whole untrusted filters and missing model
registration remain UNKNOWN. Class/DB-event initialization is not supported.

Version ts-server-v28 preserves RLS v3 row-policy meaning and adds optional
column-update-v1 declaration evidence. Explicit UPDATE(column, ...) GRANT/REVOKE
is tracked separately from table privileges. Table REVOKE also clears that role's
column grants; column REVOKE does not remove table privileges. Direct and PUBLIC
grants add. Existing static request write fields are matched per anon/authenticated
role, never inferred as the runtime role. NOT_ESTABLISHED is not denial proof.
Column SELECT/INSERT, role membership, grant options, dynamic SQL and incomplete
migrations remain unsupported/UNKNOWN. No protected-property intent is inferred
from names, and no new protected-property Finding or automatic fix is added.
Column state is bounded to 32 grant roles and 64 column entries per role/table;
existing token, step, output, memory and process limits remain unchanged.

Version ts-server-v6 additionally tracks known new Error().stack to returned responses. Only a direct
literal new Error throw and its catch without finally are precisely modeled; general catch values and
masking remain uncertain. Logging alone is not HTTP error exposure. Missing fetch AbortSignal does
not establish missing platform limits or generate a service-failure finding. Version v5 added
bounded Workers/Pages response-return and console log provenance. Sources
are selected credential-shaped literals, explicit authentication/cookie request headers and environment
references (sensitivity unknown). Names and VITE_/NEXT_PUBLIC_ prefixes alone are not secrets.
Response construction must reach the supported entry return; JSON.stringify retains provenance but
custom replacers, unknown transforms and unknown conditional paths are unresolved. Actual log access,
credential validity, middleware masking, Next.js server/client boundaries and browser bundles are not
verified. Only location/classification metadata is stored. Ship operator-owned exposure.mjs with the
runtime. Old exposureUses remain null; new candidates are supplemental REVIEW_REQUIRED/NOT_COMPARED.

This is SecureDeploy-owned tooling, not an uploaded project's dependency install.
Install the locked parser with `npm ci --ignore-scripts` in this directory. Node
22.13+ with the permission flag is required; local verification used Node 26.0.0
and TypeScript 6.0.3. Ship this directory and its installed parser beside the backend.

Backend settings: `TYPESCRIPT_ANALYSIS_ENABLED` (default true),
`TYPESCRIPT_NODE_EXECUTABLE` (default node), `TYPESCRIPT_ANALYZER_DIRECTORY`
(default analyzers/typescript, relative to the backend working directory).
Use trusted absolute paths in deployment; uploaded data must never control these settings.

The child receives bounded source strings over stdin, not a checkout path.
It does not load target imports, tsconfig, plugins, dependencies or execute code.
Its environment is cleared; filesystem reads are limited to this runtime directory,
addons/child processes are not granted. Node permissions are defense in depth, not
an OS sandbox against parser/runtime vulnerabilities. Use OS isolation in deployment.
The Java parent enforces an 8-second wall timeout (configurable 1-15 seconds),
192 MiB V8 old-space, 2 concurrent children, 2 MB output, 100 files, 100k characters
per file, 1M total characters. The worker additionally limits AST nodes, traversal
steps, function index size and call depth (3). These are not whole-process RSS limits.

Only Workers default-export fetch and Pages Functions named request handlers are
entry points. Local named functions and supplied relative named imports are followed.
Dynamic dispatch, callbacks, aliases through arbitrary objects, full loop/exception
semantics, path feasibility, third-party frameworks and runtime reachability are not
fully modeled. Authentication contexts are observations, never proof of authorization
or proof of IDOR. D1-like prepare/bind calls on handler environment bindings are
recognized structurally, without checking deployed binding types.

Results contain locations and observation codes, not source or string literals.
They are stored separately from Rule findings/Risk/score and comparison counts.
Legacy snapshots stay null. Runtime/parser failures are explicit, never a clean scan.
Run `npm test` here, then backend `gradle test` and frontend tests/build.

`ts-server-v4` connects only HIGH-confidence input-to-query paths with a matching
execution-call observation to `validatedFindings`. A sink has one version-scoped
finding identity and retains all validated input paths. Unknown transformations,
unmodeled guards, partial control flow and unexecuted prepare calls remain candidates.
Inline literal identifier allowlists and strict literal comparisons can narrow values;
arbitrary validators cannot. Known string/array length is numeric, not arbitrary JSON fields.
Execution observations are syntax evidence, not proof of a deployed D1 binding or
successful attack. Findings have REVIEW_REQUIRED priority but do not enter risk or
legacy comparison counts (`NOT_COMPARED`). Old snapshots are not promoted on read.

Version 3 captures scalar expression results before later side effects, evaluates
references/receivers before RHS/arguments, and isolates conditional branch state.
Logical/nullish operators short-circuit when known and join possible states otherwise.
Block shadowing, var bindings, named function aliases and parameter/object defaults
are bounded models, not a JavaScript interpreter. Unknown closures invalidate their
syntactically observed writes. Heap writes/joins, callbacks, loops and exceptions
remain partial; uncertainty is never evidence of a safe transformation.

The fixed quality set in test/quality-cases.mjs was authored before implementation
changes, separately from focused regressions. It labels SQL input flow, not successful
exploitation: 8 input-flow cases, 7 safe-flow cases, 5 expected abstentions. This is
an internal evaluation set, not an independently authored or whole-project benchmark.
Results, failure diagnostics and coverage contain no target source or literal values.

Version 4 adds an initial HTTP destination abstract value to the same evaluator.
Global fetch is a sink only in a reached supported handler/function. Query, body,
route and header inputs can propagate through strings, URL, Request, local functions
and supplied relative imports. Object fetch methods do not shadow the global binding.
Initial fixed authority with a terminated /, ?, # or backslash boundary is distinct
from user-controlled authority; a base URL alone does not restrict absolute input.
Exact parsed hostname and http(s) protocol checks with rejecting branches are observed,
not arbitrary startsWith/regex validators. Port policy, redirects, DNS and runtime
network reachability remain unverified, including fixed/allowlisted destinations.
Incoming request.url alone does not prove arbitrary host control in Workers routing.
Unknown wrappers, aliases of global fetch, other HTTP clients, URL authority mutations,
complex control flow and unsupported guards remain partial, never certified safe.
HTTP observations are additive nullable snapshot fields; old snapshots are not filled.
Only a matching HIGH-confidence input-to-destination observation becomes an SSRF
REVIEW_REQUIRED/NOT_COMPARED finding. Neither HTTP observations nor findings enter Risk.
The SSRF composed quality set is synthetic and internal, not a whole-project accuracy claim.
URL parsing semantics: https://url.spec.whatwg.org/
Defense limitations: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

Version 13 adds bounded Next.js declaration contracts using the nearest supplied
package.json dependency, not target module loading. Recognized version declarations
are 13.2 through 16 for App Router and 14 through 16 for async Server Functions;
this is an API-shape range, not verification of installed packages or patched versions.
Default app/**/route.ts/js (or src/app if no root app is present) HTTP exports receive
Request input. Only path-declared dynamic params are input; params may be awaited.
json/text/formData, headers, URL query and nextUrl reuse the existing value evaluator.
Direct async exports under file/function 'use server' receive symbolic external
arguments. Their serializable returns are separately labeled, not observed network
execution. Inline closures, reexports, Pages API, aliases, dynamic Next config,
middleware/auth libraries and client bundles are not resolved. server-only/use client
are boundary declarations, not runtime protection or exposure proofs.
Unshadowed process.env references record location and public/secret-name hints only,
never actual names or values. Only a supported returned body with private-name or
request-selected provenance connects to the existing review-only exposure finding.
Fixed-destination fetch data is distinct from user-controlled authority; unknown
transforms retain uncertainty. Existing Supabase client/policy declarations remain
separate from unverified factory/context, authentication and live database state.
All previous process/file/step/depth/memory budgets remain unchanged. Versioned
structural findings remain NOT_COMPARED, never automatically resolved across versions.
Official contracts:
- https://nextjs.org/docs/app/api-reference/file-conventions/route
- https://nextjs.org/docs/app/api-reference/directives/use-server
- https://nextjs.org/docs/app/guides/data-security
- https://nextjs.org/docs/app/guides/environment-variables
- https://nextjs.org/docs/pages/building-your-application/routing/api-routes

Version 14 changes input scheduling, not sink, RLS or Risk semantics. The Java
selector uses bounded lexical/convention hints (at most 1,000 prefixes and
1,000,000 hint characters, at most 16,000 per file) and relative-import edges to
depth 3. Hints never establish a real entrypoint; the existing worker revalidates
every supplied registration and call. Oversized files are skipped, not truncated
and certified. Unknown or prefix-truncated hint coverage is reported.
The existing combined 100-file/1,000,000-character input budget and 100,000 per-file
limit remain. Soft reservations protect up to 24 related code files (250,000
characters), up to 8 general files within a 32-file/350,000-character code share,
and up to 68 policy SQL files/650,000 characters. Unused shares are reclaimed for
related code, SQL, then general code, subject to the same global caps. A file that
does not fit cannot stop later small files. SQL interpretation stays chronologically
ordered in the original parser; missing inventory/SQL still invalidates certainty.
Selection reasons and combined candidate/submitted/omitted counts are optional
snapshot metadata. Parsed files and traced flows remain separate. SCA/deployment
inputs still use the original project inventory and their independent existing caps.
When selected SQL exists, the policy pass runs before request-flow traversal and
may use at most 25% of the same shared step cap when parsed code exists (90% for
SQL-only inputs, reserving finalization work). Unused work remains available to
code tracing; no additional global steps/time/memory are granted. On policy quota
exhaustion, prior declaration facts remain, the interrupted migration is limited,
later inputs are NOT_RUN, and affected migration scopes yield UNKNOWN operations
and no broad-write candidate. Finalization also consumes the global budget.
Client declarations run before entry discovery/flow, with at most 15% of the same
global step budget; unused work remains available to flow tracing. Client and Node
dependency inspection reuse syntax indexes produced by the existing bounded AST
walk instead of repeating whole-tree traversals. The indexes preserve the existing
API/shadow/write contracts and source order, not new alias or factory semantics.
Optional `budgetUsage` records AST node visits and charged steps for setup, policy,
client, discovery and flow; steps sum to at most the unchanged shared limit. AST
visits are a separate existing resource cap, not full security-flow validation.
This is scheduling/partial-evidence handling, not a new policy grammar or stronger
authorization judgment. Selected SQL may still be NOT_RUN at the policy work cap.

## Client and authorization policy evidence (v16)

An optional access-level evidence record joins bounded immutable aliases, explicit
relative named exports, straight-line factories, unique static parameter origins and
the known `@supabase/ssr` browser/server constructors to repository policy facts.
Official `@supabase/server` `withSupabase` default-fetch declarations with a literal
single auth mode expose separate user/admin context contracts. Mixed/dynamic modes,
Proxy clients, path aliases, arbitrary middleware, default/reexports and destructured
wrapper context remain unsupported. Direct immutable object members and aliases are
bounded; writes/argument escapes through indexed aliases invalidate protection claims.
Factory/context links are declarations, not proof that a request or query executes.

Linking runs after legacy Client declarations with at most 5,000 additional ticks
inside the existing 15,000 Client / 100,000 global shares. It cannot erase prior
Client/access/SQL facts. Remaining links have no evidence on budget/output truncation;
missing evidence is not a clean result. Deno shadow/write checks reuse the same
bounded parse index without changing the registration contract or resource caps.

`getSession` is a session read, while awaited `getUser`/`getClaims` on a linked Client
are verification-call observations only. They do not prove a successful result,
guard dominance, request JWT application, object authorization or the runtime DB role.
Key names/formats are hints; key values/tokens are never included. Custom schema,
transport, mutable/escaped objects and ambiguous origins prevent a protection claim.
Broad write evidence wins over another role's ownership condition. Public/shared
read declarations are not automatically vulnerabilities. Admin context yields a
review state, not a finding based solely on missing application checks. Existing
policy findings, Risk formulas and RLS declaration grammar are unchanged.

Official contracts reviewed:
- https://supabase.com/docs/guides/getting-started/api-keys
- https://supabase.com/docs/guides/auth/server-side/creating-a-client
- https://supabase.com/docs/guides/database/postgres/row-level-security
- https://supabase.com/docs/guides/functions/auth

Installed SDK versions and actual deployments are not verified by these API-shape
contracts. Policy evidence is repository-local; matching the operational project,
headers, role inheritance and applied migrations requires authorized external tests.

## Bounded Sequelize raw queries (v20)

An exact/caret/tilde dependency declaration for major 4-6 establishes only the
static constructor/query API contract, not the installed version or runtime DB.
Proven Express input in the SQL text is distinct from values in fixed SQL's
bind/replacements options. Unknown transformations, escaped/mutated receivers,
custom hooks and unsupported options do not become confirmed paths.

The optional CommonJS registry summary supports the closed v4/v5
readdir/filter/import scaffold with define-only model files and pure configuration.
All non-hidden directory entries must be inventoried and parsed. Missing inventory,
custom association/model effects, prototype writes and v6's removed import API
reject the summary. Source inventory is not proof of the deployed directory.
The scanner supplies bounded completion evidence for individual directories, so
an ignored sibling such as .git does not make a completed model directory unknown.
Incomplete upstream collection or directory-metadata truncation grants no such proof.
No target initialization is executed. Model.find and general ORM authorization
are not proven by this summary. New findings remain REVIEW_REQUIRED/NOT_COMPARED.

Contracts: https://sequelize.org/v4/class/lib/sequelize.js~sequelize
and https://sequelize.org/docs/v6/other-topics/upgrade/

## Static Next/Supabase alias and identity observations (v23)

The collector supplies up to 32 `tsconfig.json` JSONC texts (64k characters each,
128k combined, within the existing hint budget). Only static `baseUrl` and
single-target `paths` mappings without `extends` are resolved. Resolution uses
the nearest supplied config and selected source inventory, never a compiler host,
target filesystem access, package installation or target execution. Duplicate keys,
ambiguous targets, missing nested configs and workspace escapes do not establish
a link. Explicit local mappings cannot masquerade as the official Supabase SDK.
Existing function-depth, AST, step, file, character, time and heap limits remain.

Aliases reuse existing function and SSR Client return/argument provenance; they
do not add React.cache, Proxy, dynamic context or arbitrary framework semantics.
The optional `authChecks[].resultEvidence` records direct zero-argument awaited
`getUser`/`getClaims` results, supported local absence return/throw guards, and
matching `.eq()` ID fields. Reassignment, escapes, arbitrary intervening calls and
unsupported branches invalidate this observation. A guard is not authentication
success, an application filter is not database authorization, and `getSession`
does not gain identity-verification evidence. Installed SDK behavior is unverified.

Optional `requestEntry` identifies a supported Next declaration in the very same
function as a data access. Helper-internal evidence is not promoted to an HTTP
request or an invocation proof. Policy state and actual DB role are not upgraded
by these new observations. Old snapshots deserialize missing fields as null;
Worker version changes preserve the existing conservative comparison boundary.

`scripts/evaluation/modern_supabase_validation.mjs <absolute-analyzer-path>` runs
authored Grade B controls in root-app and src-app layouts. Its confusion counts
measure connected policy classification, not new real-CVE detection. Actual
Grade C project receipts are recorded separately in `modern-supabase-results.json`.

## Directional UPDATE policy evidence (v24 / supabase-rls-v3)

UPDATE USING evaluates existing rows while WITH CHECK evaluates replacement rows.
Combining these as predicates on a single row can incorrectly claim ownership.
An explicit broad replacement condition alongside UID-restricted existing rows,
or the reverse, is now a directional REVIEW_REQUIRED/NOT_COMPARED candidate when
the corresponding GRANT is explicit. Omitted WITH CHECK still inherits USING.
Denials, unknown expressions, missing grants and restrictive constraints are not
automatically upgraded to risk or protection. Existing Risk/Score formulas remain.

`scripts/evaluation/authorization_matrix.py` separates static engine replay from
an optional local PostgreSQL oracle. Database mode executes only authored constants
in a new private cluster with TCP disabled, explicit socket/user/database arguments,
no inherited PG settings, statement limits, and stop/removal in finally. Never pass
external migration SQL to this runner. Its A/B results validate PostgreSQL semantics,
not a public application's deployed Supabase project or HTTP authorization.
Official semantics: https://www.postgresql.org/docs/16/sql-createpolicy.html

## Configuration-guarded Client factories (v25)

The existing bounded factory return contract additionally permits a no-else
`if (!localEnv || !otherLocalEnv) throw ...` prefix. Each referenced value must
be an earlier immutable local read of unshadowed `process.env.NAME`. Only a
single throw (optionally in a one-statement block) is accepted. Conditions have
depth <=4; the existing eight-statement factory, three-call-depth, client work,
output, file, time and memory limits are unchanged. Custom conditions, mutation,
alternative returns, extra effects and unresolved wrappers remain unknown.
`FACTORY_CONFIGURATION_ABSENCE_THROW` is Client provenance, not an authentication
guard, sanitizer, successful invocation, deployed policy or runtime-role proof.
Supabase write-argument taint and arbitrary helper request graphs are not added.
The evaluator `write_flow_validation.mjs` separately counts existing policy
warnings and connected policy evidence; a link improvement is not a new CVE TP.

## Local Next write-value evidence (v26)

After existing Next entry registration, linked Clients may record an optional
`writeEvidence` for INSERT/UPDATE static object fields and UPDATE/DELETE eq/match
filters. The payload and existing-row selection are separate. Only local const
aliases, bounded object destructuring, awaited Request json/formData/text, explicit
Server Function arguments and whitelisted primitive conversions are followed.
An ID from getUser/getClaims plus the existing absence-exit evidence is labelled
VERIFIED_USER_EVIDENCE; this names observed code evidence, not runtime success.
getSession IDs are SESSION_UNVERIFIED. Constants are SERVER_CONTROLLED; unknown
transforms, mutation/escape, spread/computed/duplicate fields remain UNKNOWN.
No field name (including owner/user) establishes a resource ownership model.

The write pass shares the existing 5,000 link-work / 15,000 Client / 100,000 global
step limits and 275k evidence output limit. Depth is eight local expression edges,
not increased function-call depth. At most 16 fields, eight filters and four source
locations per value are emitted, with no raw literals. A budget failure is recorded
as WRITE_EVIDENCE_BUDGET_OR_CONTEXT_LIMIT; absent evidence is not a safe result.
Helper graphs, UPSERT, arrays, query/params extraction and dynamic wrappers are
not added. Policy v3, effective DB role UNKNOWN, existing Findings/Risk and
REVIEW_REQUIRED/NOT_COMPARED semantics are unchanged. Older snapshots have no
invented write origins. Target sources are never executed or installed.

## Acquisition policy omissions (v27 bridge)

The backend now forwards known uninspected SQL files from the existing Coverage
Ledger as NOT_RUN descriptors, including LFS/symlink acquisition omissions with
no file type. It reuses ProjectFileCollector's supported SQL paths and the ignore
policy. Canonical migration omissions invalidate their existing RLS scope;
truncated/redacted metadata, unavailable SQL directories, descriptor overflow or
non-migration SQL sources conservatively invalidate inventory completeness.
At most 100 SQL descriptors are retained, with no missing-file contents loaded.
Unrelated images and ignored dependency SQL do not establish policy uncertainty.
RLS v3 semantics, risk formulas, resource limits and candidate rules are unchanged.
Worker version 27 distinguishes this changed input contract for comparisons.
