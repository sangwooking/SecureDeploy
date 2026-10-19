# Bounded Python server flow analysis

Trusted CPython standard-library AST worker, version `py-django-v3`.

Version 3 adds bounded request-to-file and pickle/YAML evidence using the existing Django/DRF flow evaluator.
Supported calls include open/io.open, pathlib.Path file operations, pickle.load/loads and selected PyYAML loaders.
Literal-base Django safe_join is lexical confinement evidence only; symlinks, permissions and runtime activation remain unverified.
Unknown transforms, unknown YAML loaders, lazy load_all execution and unsupported argument types are not confirmed resource findings.
Java/Spring and general Node.js file/deserialization flows are outside this milestone.
No Django install, target import, target evaluation, build, pip, or network requests.

## Runtime

CPython 3.10+ on a POSIX host is required (tested locally on 3.14.5).
Configure `securedeploy.python.python-executable` and
`securedeploy.python.analyzer-directory` for deployment. The default directory is
`analyzers/python`; it must be shipped beside the backend, owned by the operator,
and never point into uploaded source. `securedeploy.python.enabled=false` records
DISABLED, not a clean scan. Timeout defaults to 8 seconds (clamped to 1..15).

The parent clears the environment and uses `-I -S -B`. Input arrives on stdin;
only locations, fixed messages and structural evidence leave stdout. Limits:
100 files, 100k characters/file, 1M characters total, 60k AST nodes,
30k evaluation steps, depth 5, 200 results/type, 2MB output, 2 concurrent workers.
CPU limit is 6 seconds. Linux uses a 384MiB address-space ceiling; macOS uses
bounded input and periodic peak-RSS checks, NOT a hard memory ceiling. Parent
timeout kills the child. This is not a filesystem/network/OS sandbox.

## Source selection and coverage

The parent schedules files using bounded lexical Django/DRF import and routing
hints, then at most five rounds of exact local import expansion. Remaining files
use deterministic path order. Hint inspection is capped at 1,000 files and 1M
characters, independently of the unchanged worker source limits; omitted hint
inspection is explicit. Hints are not verified endpoints: the AST worker
independently resolves entries. No repository-specific names or suffix-based
module guesses are used. Multiline/dynamic imports and package search paths may
not be resolved. All source, file, node and execution limits remain unchanged.
An AST too large for the remaining node budget is omitted without spending the
budget needed for a later smaller AST. Parsing and traversal stay time-bounded.

`selectionCoverage` counts Python files received from the common file collector,
not files excluded before that collector. It distinguishes submitted/omitted
files and omitted detail rows. Per-file `selectionReason` is optional for old
snapshots. File-count, per-file-character, total-character, AST and work/time
limits have separate reasons. Parsed files, discovered entries, traced functions
and unresolved paths are different coverage stages, never full-code assurance.

Flow v2 preserves uncertainty across returns/context managers, isolates branch
state, validates local argument binding, and keeps nested local scopes separate.
Literal tuple/list unpacking preserves individual values; unknown mutable calls
invalidate collection precision. Unknown input validators remain deferred,
including conditional expressions and short-circuit calls.

## Supported scope and uncertainty

Static Django `urlpatterns` path references, direct `as_view()` on supported
View/APIView subclasses, DRF api_view, and direct DefaultRouter/SimpleRouter
registrations. No claim that project settings enable every observed route.
GET/POST/data/query_params/header maps and literal path converter parameters;
local functions and unambiguous local import names; assignments, branches,
short-circuit operators, f-strings, percent formatting and str.format.

Django connection cursor execute/executemany: a confirmed input-to-query
construction with an observed call becomes a CWE-89 REVIEW_REQUIRED supplemental
finding, outside score/BLOCKING and resolved counts. Parameterized values are not
SQL text. Local model objects.raw is lazy and remains unconfirmed.
Middleware/settings/ownership, dynamic dispatch, star imports, decorators with
unknown behavior, generators, loops, exception flow, arbitrary ORM wrappers,
async helpers, other frameworks and external libraries are not fully analyzed.
Unknown transformations are never considered sanitizers. Absence is not safety.

The optional `serverAnalysis.pythonAnalysis` JSON snapshot preserves old reviews
without a migration. Findings are NOT_COMPARED. Private project source is not a
fixture and is not stored in this snapshot.
The outer `serverAnalysis.status` retains its existing TypeScript meaning;
Python has its own status and Coverage Ledger entry. Neither is whole-project assurance.

Run `python3 -B -m unittest discover -v` here, then backend and frontend tests.
The synthetic evaluation and variation files are not external, independently
authored or statistically representative. v2 development regressions reproduced
eight failing assertions before correction. Post-implementation variations add
28 classifications across renamed/split files (10 confirmed, 10 no finding,
8 deferred); they now become regression cases, not future blind holdouts.

References: [Python AST](https://docs.python.org/3/library/ast.html),
[isolated invocation](https://docs.python.org/3/using/cmdline.html),
[Django SQL binding](https://docs.djangoproject.com/en/5.2/topics/db/sql/).
