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

## URL hardening and separate application track

A engine commit `bd12409888f28bd1316b34c70f92052706d6f952` uses a bounded
official TypeScript syntax worker to reconcile only INSECURE_API_URL matches.
Proven comments and inert URL parser bases are excluded; aliases sent to fetch,
unknown calls, mutations, parser failures and limits retain warnings. Uncertain
request context is LOW confidence/REVIEW_REQUIRED under the unchanged Risk policy.
Loopback exemption uses an exact parsed host, not a hostname prefix. Uploaded
code is not run. If changing the URL worker, bump its protocol/version in both
Node and Java and recheck comparison fingerprints.

`url-hardening-delta.json` records actual before/after results on the same
40 frozen cases: 12 false warning observations removed, two uncertain retained,
no new warning locations, no claimed improvement to the unsupported CVE paths.
The actual old run is c718638 (production code identical to milestone f24d831);
old results are preserved. Scores change because warnings were removed, not
because the score/Risk formulas changed. Rule fingerprints differ, so old
Reviews must not be silently reclassified as RESOLVED or recomputed.

Library/Framework track and Real-World Web Application track are distinct.
The latter has 19 inspected candidate metadata records, eight selected public
repositories and seven acquired/analyzed trees at pinned SHAs. Each completed
tree was run twice through actual production beans in isolated H2. SHA/path
verification precedes scanning. The remaining selected repository failed strict
encoded-filename policy; one pinned public tree lookup confirms the cause.
No failed acquisition is converted into zero findings or a SAFE project.

```sh
ROOT="$HOME/.local/share/securedeploy/benchmark/applications-new"
python3 -B scripts/evaluation/application_track.py collect scripts/evaluation/application-selection.json "$ROOT"
python3 -B scripts/evaluation/application_track.py run "$ROOT" "$ROOT/raw.json"
python3 -B scripts/evaluation/application_track.py run "$ROOT" "$ROOT/replay.json" --project cloudflare--d1-northwind
python3 -B scripts/evaluation/application_track.py summarize "$ROOT" "$ROOT/packs" --raw "$ROOT/raw.json" --review scripts/evaluation/application-review.json
```

The committed review is tied to the original plan hash: a fresh collection has
to be verified as the same source/inventory before a NEW review is frozen; do
not patch hashes to bypass this guard. Full sources/results/packs stay under
`~/.local/share/securedeploy/benchmark/applications-2026-10-20-v2/`; only public
metadata and tooling belong in Git. No archive is saved wholesale: 32 MB
compressed, 128 MB expanded, 4 MB/member, 20,000 entries; links/special files,
generated/binary assets and credential-shaped text are explicitly omitted.
Original root licenses and per-file license headers remain with sources.
Root license metadata does not relicense third-party/generated files.

An expanded credential-shape audit found a Google-key-shaped value in the
public Bakery example base settings file. Its value was never printed or
validated. The file was removed from our v1 copy and omitted from v2 with an
explicit reason; v1 is no longer an intact replay corpus. V2 is a verified
projection of the same pinned SHAs: every retained file is byte-identical and
was re-evaluated twice without downloading again. Effective Bakery settings
are not fully reviewed. `application-privacy-receipt.json` records this change.
Shape checks are not a guarantee that arbitrary credentials cannot be present.

The seven trees contain 3,008 discovered files: 1,761 selected by production
scanner, 1,010 unsupported, 234 excluded, three acquisition-size limits.
AST parse counts are not complete security analysis. Actual Java parser replay
confirms OutOfMemoryError at JavacTask creation for both Spring apps under
unchanged 192 MiB heap / 96 MiB metaspace limits. Framework delegation and
Python budgets remain explicit. No engine fix or limit increase is hidden here.

19 reviewed packs include three conditional dangerous NodeGoat paths, five
narrowly safe paths/conditions and 11 unverified context/failure records. They
do NOT establish whole-project recall. The source-supported dangerous paths
are outside current entry/sink contracts, not labelled confirmed engine FN.
New app review confirms seven false warning observations (five SVG namespaces,
one generated-type license comment, one UI label). The UI-label warning causes
NetBox BLOCKED in this evaluation. Preserve that false-block evidence rather
than rewriting policy or dismissing it. App-wide pre-A evaluation was NOT run.

SCA extraction runs, but OSV/EPSS/KEV/AI lookups are NOT RUN; Risk receives SCA
UNKNOWN and actual risk-v1.2. These are not deployed-service safety decisions.
No user PostgreSQL/Review, target install/build/import, PoV, attack or remote
write. No new browser E2E; frontend source is unchanged. Times exclude Gradle/
Spring startup and memory values are parent samples, not total peak RSS.
Observed holdouts become development material after use; future engine gains
need NEW projects. Exact/whitespace code clone checks found no cross-project
groups; semantic clones and unrecorded forks remain unverified.

V2 repeated engine segments total 8,616 ms; maximum sampled parent heap is
145,228,800 bytes. These are observations, not a performance guarantee.
A separate single-project replay matched the frozen Cloudflare signals and
metadata, excluding clocks/heap. Public metadata contains no source bodies;
the 19 complete packs remain outside Git and can be regenerated from the
version-bound manual review and unchanged corpus. Java failure diagnosis is
the earlier trusted v1 worker replay on byte-identical retained Java input;
the v2 full run independently repeats JAVA_WORKER_FAILED.

## Hardening #2: semantic strings and Java parser lifecycle

`hardening2-results.json` links the unchanged v2 source plan and baseline to
committed A/B engine runs. Seven warning observations are removed (five SVG
namespaces, one declaration-file license comment, one cross-literal UI match),
not seven independent vulnerabilities. Five follow-up packs reference the
original case IDs without rewriting the earlier failure evidence. Full packs
and raw outputs remain in the external v2 corpus under `hardening2-*`.

String-context v3 preserves actual calls, unknown consumers and credential-like
values, including quoted/computed property keys and embedded configuration text.
Only literal intrinsic SVG namespace attributes are excluded, not custom props
or URLs sent to fetch. Oversized source is NOT fully parsed: a maximum 100k-char
prefix can prove completed comments before the first syntax diagnostic; later
code and the remainder remain unknown. Existing time/node/process limits apply.

Java SQL v2 shares one parse-only JavacTask across the bounded selected input.
Per-file SourcePositions previously retained JavacTrees/task/compiler services
for every indexed Unit. Heap exhaustion was reproduced, not inferred from a
generic worker failure. Source text, cross-file method index and error locations
are preserved. No attribution, target compilation or annotation processing is
performed. File syntax errors remain per-file; a batch-level parser/stack failure
is explicit and does not certify earlier methods as safe. Fatal worker failure
still retains legacy warnings. Limits stay at 192 MiB heap / 96 MiB metaspace,
100 files / 1M chars / 60k AST nodes / 30k flow steps / 5s internal / 8s parent.

Both Spring apps now parse all selected 50/80 files. Entry/function tracing is
17/23 and 40/45, but traced supported SQL executions are still zero; this is not
whole-app Java/JPA/MyBatis analysis. NetBox changes 86/BLOCKED to
100/REVIEW_REQUIRED solely by removing its false signal; SCA stays UNKNOWN.
Risk/score policies, user DB and historical Reviews are unchanged. Version and
comparison fingerprint changes prevent treating analyzer changes as fixed code.

The separate worker probe reports macOS maximum RSS separately from GC
high-water and exit-heap samples. Two post-change observations are retained;
these few measurements are not a universal performance guarantee. Existing
40-CVE regression still has 38 NOT_SUPPORTED / 2 RESOURCE_LIMIT. The 14 new
synthetic string-context variations are same-curator tests, not an external
blind evaluation. No new source acquisition or external vulnerability/AI query.

Replay the memory probe on macOS with our trusted baseline/current worker JAR:
`python3 -B scripts/evaluation/java_worker_probe.py DATA_ROOT TRUSTED_WORKER_JAR NEW_EXTERNAL_JSON`.
It verifies the original failed selection's file hashes and sends text through
the worker protocol; it never runs an upstream build or saves raw stderr/source.

## Hardening #3: bounded Java data-access contracts

Engine `0209ed3fba4d69021eb58c3573d6566b2afa6a01` adds typed source DI,
unique implementation calls, static MyBatis declarations and separate JPA
contract observations. `hardening3-results.json` preserves the actual repeated
v2-corpus evaluation and two follow-up failure packs. Use `hardening3.py` with
the external corpus, a NEW output and a NEW pack directory to replay the core
same-source comparison; its baseline is the production-equivalent #2 engine.
External raw outputs are `hardening3-*` in the existing application/Pilot/CVE
roots. Original sources and the Bakery omission are unchanged.

PetClinic has nine JPA operation contracts, not proven SQL execution. Mall has
87 traced functions and six static Mapper calls with value binding. These are
different sites from the six earlier SQL-name candidates. MyBatis-Plus inherited
implementations, dynamic XML, ambiguous targets and object transformations stay
unknown. Mall reaches the 200-observation cap: evidence is incomplete. No new
SQL candidate, legacy warning, score or Risk change occurs in these app runs.

The actual 12-case Java and 24-case Pilot regression results are unchanged;
known false alerts and unknowns remain. Sixteen real-world CVE regression cases
remain 14 unsupported / two resource-limited, not safe. The other observed
validation/holdout splits were not rerun. The newly acquired official Spring
guide is pinned and licensed outside Git: two parsed Java files but no supported
HTTP entry (CommandLineRunner), not an independent vulnerable/fixed evaluation.
Synthetic variations are development tests, not external accuracy estimates.

MyBatis parameter semantics follow its [official Mapper XML documentation](https://mybatis.org/mybatis-3/sqlmap-xml.html).
JPA contract scope follows [Spring Data query methods](https://docs.spring.io/spring-data/jpa/reference/jpa/query-methods.html).
No target compilation, dependency installation, external XML loading or paid AI.
Real loopback HTTP/H2 tests and shared ZIP/mocked-GitHub integration tests cover
persistence and access isolation; no new live private GitHub analysis was run.

## Hardening #4: bounded Express execution flows

Engine `ce556e2bc5add4ac070e4b6904a129300364fe52` reuses the TypeScript
worker for static Express registrations, literal CJS/ESM imports, bounded
constructors and closures. Library capabilities require a known import origin;
MongoDB API contracts also require a supported declared dependency family.
Unknown receivers, mutable captures, middleware effects and dynamic routes do
not become verified execution Findings. Worker protocol is `ts-server-v7`;
both the Java validator and comparison fingerprint track this engine change.

`hardening4-results.json` records repeated same-source evaluation of seven
acquired applications. NodeGoat at `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`
changes from zero traced entries/functions to 19/48 across 44 parsed files.
Three request-to-eval anchors belong to one teaching defect family, not three
CVEs. Its MongoDB `$where` receiver remains unverified and is not a verified
Finding. Three ordinary data queries are not ownership/authorization proof.
Rule warnings, scores, deterministic Risk and Java summaries remain unchanged.
The original acquisition failure and source omission remain explicit.

Replay with `hardening4.py DATA_ROOT NEW_OUTPUT NEW_PACK_DIR PROBE_JSON` and
`node_worker_probe.py DATA_ROOT NEW_OUTPUT --public-root PUBLIC_GUIDE_ROOT`.
Raw sources, detailed outputs and three follow-up failure packs stay outside
Git. Original failure packs are preserved. Pilot regression still includes six
known false positives; 16 CVE regression cases remain 14 unsupported and two
resource-limited. Other validation/holdout splits were not rerun.

Nine later same-curator synthetic variations give TP=3/TN=3/UNKNOWN=3,
FP=0/FN=0 in their labeled supported scope, not independent general accuracy.
Two newly acquired MIT-licensed official Express examples at
`0dee2c52c7c873498f8ed7d8ee4ddd0a04d3ada8` parse, but their self-package
relative require is unresolved in the acquired subset: no verified entries,
no TN or safety claim. No external vulnerable/fixed Express pair was acquired.

The identical-input NodeGoat probe observed 226 to 233 ms and maximum RSS
about 139 to 146 MiB; these single process samples are not performance
guarantees. Existing 192 MiB heap, file/text/node/time/depth/result caps remain.
Real ZIP/H2 persistence/detail/access tests and mocked public/private GitHub
acquisition exercise the common pipeline; live private GitHub E2E was not
repeated. No target execution, dependency installation, paid AI, external
vulnerability lookup, user database evaluation writes or migration occurred.

## Hardening #5: receiver provenance and external source pairs

`hardening5-results.json` records the pinned implementation and repeated H2
regressions; `hardening5.py` rebuilds the public summary and external follow-up
Failure Pack from the frozen receipts/results, without copying source bodies.

`receiver_provenance.py APPLICATION_ROOT EXTERNAL_ROOT OFFICIAL_ROOT NEW_OUTPUT`
replays hash-verified source subsets through trusted v7/current workers. No
target module is imported or executed. File-wide coverage notes no longer
invalidate unrelated Node calls; per-call object identities preserve bounded
fields/aliases and propagate unknown mutations, including expression-bodied
closures and depth-limited calls. Cached module lookup precedes the import
depth check. Worker protocol is v8; resource limits and Risk are unchanged.

NodeGoat's remaining nested DAO constructor exceeds the existing call-depth
boundary: `$where` remains unverified, not fixed or safe. Official Express
examples lack their self-package implementation in the acquired subset;
registration is unproven, not a true negative. External CVE source pairs are
observed, not blind. A reported fix/release commit alone is not ground truth:
mongo-express's linked release commit only bumps package version and history,
so its immediate parent is not labeled vulnerable. Mongoose populate's patch
and added tests establish a narrower change, not full application safety;
its library API and oversized test file remain outside supported flow scope.
Original sources and failed candidate-pair evidence remain outside Git.

## Hardening #6: strict constructor effects and cursor execution

Worker v9 caches AST-only constructor plans, never argument heaps or results.
At the existing depth boundary, only fresh fields, const aliases, deferred
method declarations and verified collection factories can be applied as MUST.
Unknown calls/branches/computed writes remain UNKNOWN; MAY is not promoted.
Returning a different object/function and non-constructible functions cannot
leave a phantom instance. Summary evidence is bounded and explicitly not a
whole-function trace. File, call/import depth, work and memory caps are unchanged.

MongoDB find creates a cursor; toArray/next provide separate consumption
evidence. Creation alone is neither an execution Finding nor a true negative.
Origin uncertainty propagates through client/db/collection/cursor references.
See the [official cursor documentation](https://www.mongodb.com/docs/drivers/node/current/crud/query/cursor/).

`constructor_effects.py` replays frozen Grade B manifests from outside Git.
Validation and explicitly released implementation-held-out variants are
separate, not independently authored or blind. Original five-module failures
are retained alongside added local-helper variants; do not silently replace
or relabel them. No new supported Grade A CVE pair was established. Original
official examples remain Grade C scope observations, not safe projects.
