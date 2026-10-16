# Bounded server analysis runtime

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
