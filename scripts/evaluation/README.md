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
SARD/Juliet remain future acquisition candidates. Vul4J/CVEfixes intake is
described below; no reproduction/build tooling is executed.

Accounting/security tests: `python3 -B -m unittest discover -s scripts/evaluation`.
The new JVM runner has its own hash/path/symlink safety tests under `src/test`.

## Real-world expansion: Vul4J and CVEfixes

`realworld-pins.json` and `prepare_realworld.py` freeze 20 different CVEs in
20 upstream projects: ten Vul4J and ten actual CVEfixes fixes-table records.
Each has a first-parent/fixed pair: 40 cases, 54 original file versions,
15 path-level CWEs, Java/Python/JavaScript/TypeScript. The new corpus does not
reuse BenchmarkJava cases. Project/family pairs stay together: 16 regression,
14 validation and 10 holdout cases. Related XXE and JWT-algorithm patch families
are explicitly grouped even across different projects. Holdouts have now been observed in this
baseline; curation and review were not independently blinded.

The 12.7 GB official CVEfixes v1.0.8 ZIP is NOT downloaded/restored in full.
`cvefixes_metadata.py` reads a fixed 2 MiB HTTP range containing the beginning
of its SQL gzip member. Bounded nested decompression extracts the complete
fixes-table prefix: 12,864 GitHub fix rows; 59 other/nonmatching rows are not
selected. SQL is never executed. The receipt records URL, byte range and
SHA-256 of retained bytes; the complete ZIP checksum and gzip CRC are NOT
verified. Layout, member-name, status, size and decompression bounds fail
closed. Do not silently change offsets to make a changed archive pass.

The Vul4J CSV is pinned at `376411da11fa705019f731404de1d0679fe73537`.
Its dataset license is CC-BY-4.0; its tooling is not run. CVEfixes' pinned
license/attribution and each project's original license are retained outside
Git. Original upstream files are not relicensed or published in this repo.
CCM's historical license is the MIT header in its original implementation.
Dataset attribution: Bui, Scandariato and Diaz Ferreyra (Vul4J, MSR 2022);
Bhandari, Naseer and Moonen (CVEfixes, PROMISE 2021). This intake adapts
metadata/path labels, not the upstream code license.
Official sources: https://github.com/tuhh-softsec/vul4j and
https://github.com/secureIT-project/CVEfixes with archive
https://zenodo.org/records/13118970 .

From this repository, with NEW external paths:

```sh
META="$HOME/.local/share/securedeploy/benchmark/cvefixes-prefix-new"
ROOT="$HOME/.local/share/securedeploy/benchmark/realworld-new"
python3 -B scripts/evaluation/cvefixes_metadata.py "$META"
python3 -B scripts/evaluation/prepare_realworld.py "$ROOT" "$META" scripts/evaluation/realworld-pins.json
python3 -B scripts/evaluation/benchmark.py validate "$ROOT"
```

Use the same run/score/combine/merge-raw/packs commands above. New baseline
metadata is in `realworld-{catalog,baseline,cause-review,failure-index}.json`.
`realworld-secondary-review.json` separately records non-CVE warning review.
Full raw results, code, license assets and packs are operator-private under
`~/.local/share/securedeploy/benchmark/realworld-2026-10-20-v3/`.
The v1 metadata called `.js` TypeScript; v2 corrected language/framework labels.
Final v3 explicitly groups related XXE/JWT families and moves both XXE projects
into regression. Each version was evaluated; original results remain, not
overwritten. Only metadata/splits changed, never engine code or target source.
All holdouts were observed during these baseline runs, not a new blind experiment.

Important interpretation:

- Labels cover the named patched condition and stated assumptions only.
  Historical prefix checks, symlink policies, Next host fallback and logger
  tracebacks have residual conditions; SAFE never means an entirely safe project.
- Actual source files and selected adjacent context are collected, NOT complete
  installed applications. Some input is a library caller contract rather than a
  proven HTTP request. Missing callers/wiring are explicit; no PoV was executed.
- CWE is an analyst path classification unless it equals the retained Vul4J
  label. Original disagreements remain (`vul4j-51`: dataset CWE-918, XML patch
  reviewed as CWE-611). Do not present these as official NVD corrections.
- Actual final CVE-target result: 38 NOT_SUPPORTED, 2 RESOURCE_LIMIT (Bottle
  character budget), zero scored paths. Precision/recall are not estimable.
  This is not 40 true negatives, 20 confirmed false negatives or an engine fix.
- The engine emitted 14 other INSECURE_API_URL alerts. Review confirmed 10
  documentation-comment false alerts and two URL-parser-base false alerts;
  two server-address alerts need context. Both revisions are counted as alert
  observations, not 12 independent defects. They are NOT CVE-target detections.
- 40 scope/limit packs and 14 secondary-alert packs preserve exact public
  paths/line/hash references without source bodies. Replay the parent case ID
  through `benchmark.py run`; secondary pack IDs are not manifest case IDs.
- No engine/Rule/Risk/DB/UI changes or OSV/EPSS/KEV/AI calls. The isolated H2
  adapter is not Review persistence, ZIP/GitHub acquisition or browser E2E.

Next decisions should separate lexical warning quality, missing context and
unsupported framework/sink contracts. Expand bounded original app context
before calling scope gaps proven data-flow bugs. Move any family used for
engine tuning into regression in a NEW manifest; preserve this baseline.
