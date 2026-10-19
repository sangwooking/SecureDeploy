# Static engine evaluation

Evaluation only. These tools do not modify engine/Risk policy or existing Reviews.
Never use production credentials in fixtures. Keep downloaded source, raw results,
private evidence and process-environment launch helpers outside Git.

- `prepare_cases.py DIR`: freeze 38 internal cases before running the engine.
- `acquire_public.py DIR`: explicitly opt in to anonymous, bounded public text downloads at pinned SHAs.
- `prepare_external.py DOWNLOAD_DIR CASE_DIR`: preserve upstream Java truth and unmodified sources.
- `prepare_probes.py DIR`: six exploratory variations, **not** a blind holdout.
- `EngineEvaluation.java CASE_DIR RESULT_JSON`: run existing scanner, Rule/FPA,
  Python/TS worker, deployment inspector and manifest extraction twice per case.
  No OSV, threat intelligence or AI calls; no target execution. This is **not**
  the complete persisted Review/Risk pipeline. Requires the backend runtime
  classpath, trusted analyzer runtimes and local application DB configuration;
  schema validation/read-only DB connections are forced. Use operator-owned paths.
- `summarize.py RESULT_JSON SUMMARY_JSON`: warning/candidate accounting with
  explicit UNKNOWN/NOT_SUPPORTED/NOT_INSPECTED and repeated-result comparison.
- `python3 -B -m unittest -q` here: accounting tests, no network.

Run preparation in a new private directory, then invoke Java with the backend
runtime classpath: `java -cp "$SECUREDEPLOY_EVAL_CLASSPATH" scripts/evaluation/EngineEvaluation.java "$CASES" "$RESULTS"`.
Do not put secret values directly into command arguments or saved shell commands.

Labels describe a named static condition, not successful exploitation or overall
safety. A timeout warning is not proof of DoS; permitAll is not proof of broken
authorization. Legacy npm candidate rules and OSV-backed SCA are different layers.
The raw baseline preserves one target-rule identifier typo; the summarizer's
explicit mapping corrects accounting without changing truth or engine output.
Do not merge PyGoat's unsupported try/ORM path into supported-flow recall.
Sources are independently authored, but manual review was by the same developer.
These cases have now been observed and are regression material, not future blind tests.

## Versioned public pilot and failure packs

`prepare_pilot.py` collects 38 pinned public cases: 24 previously observed OWASP
Servlet cases, five Django security-fix pairs, and one Hono and one h3 fix pair.
Only the named path/condition is labelled SAFE, never an entire patched project.
Python/TypeScript framework internals may be outside the current HTTP-entry
contracts. Such cases measure scope gaps, not automatically confirmed engine bugs.
The pilot covers five security areas, not all eight. It is not a random sample or
an independently blinded study. CWE-116/1333 are path-level analyst classifications;
they must not be presented as an official CVE weakness assignment.

The original sources and cached advisory/license text stay outside Git with
700/600 directory/file permissions. Source URLs must match the exact repository,
SHA and path. A failed acquisition has no success manifest; retain its status,
use a new output directory and reuse the bounded hash-checked cache. Public
metadata references do not grant redistribution rights to upstream code.

From the repository root (use a NEW directory when collecting):

```sh
ROOT="$HOME/.local/share/securedeploy/benchmark/pilot-new"
python3 -B scripts/evaluation/prepare_pilot.py "$ROOT"
python3 -B scripts/evaluation/benchmark.py validate "$ROOT"
python3 -B scripts/evaluation/benchmark.py run "$ROOT" "$ROOT/regression.json" REGRESSION
python3 -B scripts/evaluation/benchmark.py run "$ROOT" "$ROOT/validation.json" VALIDATION
python3 -B scripts/evaluation/benchmark.py run --release-holdout "$ROOT" "$ROOT/holdout.json" HOLDOUT
python3 -B scripts/evaluation/benchmark.py score "$ROOT" "$ROOT/regression.json" "$ROOT/score-regression.json"
python3 -B scripts/evaluation/benchmark.py score "$ROOT" "$ROOT/validation.json" "$ROOT/score-validation.json"
python3 -B scripts/evaluation/benchmark.py score "$ROOT" "$ROOT/holdout.json" "$ROOT/score-holdout.json"
python3 -B scripts/evaluation/benchmark.py combine "$ROOT" "$ROOT/score-all.json" "$ROOT/score-regression.json" "$ROOT/score-validation.json" "$ROOT/score-holdout.json"
python3 -B scripts/evaluation/benchmark.py merge-raw "$ROOT/raw-all.json" "$ROOT/regression.json" "$ROOT/validation.json" "$ROOT/holdout.json"
python3 -B scripts/evaluation/benchmark.py packs "$ROOT" "$ROOT/raw-all.json" "$ROOT/score-all.json" "$ROOT/packs"
python3 -B scripts/evaluation/benchmark.py show "$ROOT/packs" owasp-BenchmarkTest00113
```

The runner invokes actual production beans: Scanner, all Rule Engine beans,
Java reconciliation, FPA, Java/Python/TypeScript/deployment analyzers, manifest
extraction, score and Risk. It starts a loopback-only server with a private
in-memory H2 DB, not PostgreSQL. It does not persist Reviews, call AI or query
OSV/EPSS/KEV. Risk receives SCA UNKNOWN: its review requirement is **not** a new
deployment assessment of the original project. Authentication/ZIP/GitHub
acquisition and frontend rendering are not exercised by this local-directory
adapter. Existing source-path integration tests cover those paths separately.

`run` strips credential environment variables, checks for committed production
code, caps the whole trusted Gradle process group at 15 minutes, and runs each
case twice. Target code is never compiled, installed, imported or executed.
Raw outputs omit Rule evidence/source text. Parent heap samples are not peak
RSS or worker memory; timing includes worker startup. Existing worker resource
limits stay intact. Python/TypeScript parser versions are in the raw output;
the JDK build and child-worker peak memory are not yet recorded as full metrics.

Matching requires a declared rule, target file/line span and, for structural
alerts, a request-origin trace inside the source span. A matching pattern alert
is not proof of a verified source-to-sink path. Missing/partial inspection is
not TN. Rule, filtered Rule, AST, candidate and final-user alert layers remain
separate. A candidate merged into a legacy warning is not a candidate FN.
Exact duplicates mean identical rule/location records, not every alert about a
package or function. Wilson bounds are descriptive only for these correlated cases.

Manual cause review is optional, but automatic hypotheses must stay LOW and
unconfirmed. A review JSON uses `manifestSha256`, `engineCommit`, `runnerVersion`
and `cases: {caseId: [{category, evidence, improvementProposal}]}`. Pass it as
the final argument of `packs`. `EVALUATION_CONTEXT_INCOMPLETE` distinguishes
missing helper source from an actual analyzer call-resolution defect.
Only public metadata, not source excerpts, belongs in review evidence.

Replay one case and compare later engine versions with unchanged data:

```sh
python3 -B scripts/evaluation/benchmark.py run "$ROOT" "$ROOT/replay.json" REGRESSION owasp-BenchmarkTest00113
python3 -B scripts/evaluation/benchmark.py score "$ROOT" "$ROOT/replay.json" "$ROOT/replay-score.json"
python3 -B scripts/evaluation/benchmark.py compare BEFORE_SCORE_JSON AFTER_SCORE_JSON NEW_COMPARISON_JSON
```

Comparison rejects changed data/split/matcher/runner versions and never approves
an engine automatically. If the matcher changes, re-score both old and new raw
outputs with the same matcher. If source selection or rule mappings change,
create a new dataset version and re-run both committed engine versions on it.
Once holdout results inform engine changes, move the entire affected repository,
fork/clone and vulnerability family to regression in a **new** manifest. The
immutable old baseline and holdout observation events remain preserved.
Exact and whitespace-normalized duplicates, repository/CVE/GHSA/family groups
are checked; undiscovered forks or renamed semantic clones still need review.

External-tool adapters can supply rule/location/flow signals for later comparison,
but CodeQL/Semgrep alerts are never ground truth. They were not run in this pilot.
Vul4J/CVEfixes and SARD/Juliet remain future acquisition candidates; their
reproduction/build tooling is not executed by this collector.

Accounting/security tests: `python3 -B -m unittest discover -s scripts/evaluation`.
The new JVM runner has its own hash/path/symlink safety tests under `src/test`.
