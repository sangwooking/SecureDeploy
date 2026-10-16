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

`ts-server-v2` connects only HIGH-confidence input-to-query paths with a matching
execution-call observation to `validatedFindings`. A sink has one version-scoped
finding identity and retains all validated input paths. Unknown transformations,
unmodeled guards, partial control flow and unexecuted prepare calls remain candidates.
Inline literal identifier allowlists and strict literal comparisons can narrow values;
arbitrary validators cannot. Known string/array length is numeric, not arbitrary JSON fields.
Execution observations are syntax evidence, not proof of a deployed D1 binding or
successful attack. Findings have REVIEW_REQUIRED priority but do not enter risk or
legacy comparison counts (`NOT_COMPARED`). Old snapshots are not promoted on read.
