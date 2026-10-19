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
