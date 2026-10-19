# Comprehensive static security evaluation baseline

Engine: `66fdb7391627cb7138f9f8a801b5a86d8a2a60ed`, STANDARD.
Date: 2026-10-19 KST. Evaluation only: no detector, Risk, score or DB schema changes.
Private project results/source/identities are deliberately excluded from this document.

## Support Matrix

Each cell describes the **specific limited capability**, not complete domain support.
P = PATTERN_ONLY, S = STRUCTURAL, F = DATA_FLOW_PARTIAL, N = NOT_SUPPORTED.
Unverified framework/API versions are UNKNOWN, not automatically supported.

| Area | Java/Spring | Python/Django/DRF | TS/JS server | React/frontend | Deployment files |
|---|---|---|---|---|---|
| Input/execution | P: SQL/Statement text | F: supported cursor SQL; no general command injection | F: Workers/Pages D1 SQL + fetch destination | P: HTML/redirect text, not XSS flow | N: code execution flow |
| Authentication/access | P: permitAll declaration | F: bounded declared permissions, user-FK scope, inverted owner rejection | S: entry/auth observations, no proven resource authorization | N: UI guards are not server authorization | S: selected Django declarations; runtime activation unknown |
| Secret/data exposure | P: selected config secrets | F: known sources to response/log in supported handlers | F: Workers/Pages response/log provenance | P: ENV candidates, storage calls | P: selected ENV/secrets/CI output patterns |
| Supply chain | S: Maven/Gradle static manifests, selected locks | S: requirements/standard pyproject, exact PyPI queries | S: npm manifest/package-lock graph | S: same npm capability | P: image/tag candidates, not image CVE scanning |
| Server/deployment | P: selected Spring config | S: selected literal Django settings | S: Wrangler environments | N: complete bundle/deployment verification | S: Docker final user, Compose, Wrangler; P: K8s/Nginx/Actions |
| File/deserialization | N: Java source-to-sink flow | F: supported open/Path/pickle/YAML calls | N: general Node filesystem/object restoration | N | N: runtime filesystem access |
| Crypto/token | P: JWT secret config, not verification flow | F: bounded PyJWT 2.x-shaped calls and access decisions | N: JWT library verification flow | P: token storage, not crypto correctness | P: key declarations only |
| Stability/errors | P: explicit stacktrace config | F: Requests/HTTPX module timeout observations, narrow traceback responses | F: narrow Error.stack response flow; no fetch timeout proof | N: general client stability | S/P: selected config only, not operational availability |

Source anchors: `rule/rules/DangerousSqlRule`, `PermitAllUsageRule`, `RuleFileTypes`,
`analysis/typescript/TypeScriptServerAnalyzer`, `analysis/python/PythonServerAnalyzer`,
`analysis/deployment/DeploymentAnalyzer`, `sca/parser/ScaManifestCollector`,
`project/service/ProjectFileCollector`, and the two analyzer READMEs.
All paths above are below `src/main/java/com/securedeploy` unless otherwise stated.

Java AST indexing in `ai/semantic/SecuritySliceCollector` is only slice preparation;
STANDARD does not call it. It is not Java taint analysis. Semantic AI was not evaluated.
Express, NestJS, Next.js server handlers, Flask/FastAPI and generic Python programs
do not acquire supported flow coverage merely because their files are collected.

## Materials And Frozen Labels

- 38 new internal pre-labelled cases cover the eight areas. Same developer;
  not independent, statistically representative or a future blind holdout.
- 12 unmodified external Java SQL cases: first six `sqli,true` and first six
  `sqli,false` in the pinned upstream CSV, before running the detector.
  [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava/tree/bc5ffeb09fb18ab039806d84ca1f718c2e332c54),
  SHA `bc5ffeb09fb18ab039806d84ca1f718c2e332c54`.
- Two unmodified source files from [PyGoat](https://github.com/adeyosemanputra/pygoat/tree/19d17cc8874861142b330636d068bbde54e86b85),
  SHA `19d17cc8874861142b330636d068bbde54e86b85`, one project-context case.
  Before execution, manual review labelled POST concatenation into ORM raw SQL
  followed by result indexing as dangerous static SQL evidence. No full truth set.
- Six later exploratory probes test formatting, statement splitting and renamed/
  split files. These are explicitly **post-baseline**, not independent validation.
- Total 57 cases, each run twice without external lookups: 114 static executions.
  Snapshot/coverage/candidate fields matched within each pair, excluding elapsed time.
  A later tool-validation rerun of the six probes adds 12 executions, outside baseline counts.

Source acquisition is anonymous, bounded and pinned. No target build/import/
installation, running service, exploit or paid AI call. Upstream source stays out of Git.
Manual review was by the same developer, not an independent security assessor.

## Results

Accounting unit is the named warning/candidate signal, not proven exploitability.
`SAFE` concerns the target condition only. `UNKNOWN` must not become TN.
Machine summaries preserve raw signal misses; manual scope classification is separate.

| Set | TP signal | FP signal | FN signal | TN signal | Unknown | Unsupported |
|---|---:|---:|---:|---:|---:|---:|
| Internal 38 | 11 | 1 | 2 | 11 | 12 | 1 |
| External Java SQL 12 | 5 | 5 | 1 | 1 | 0 | flow support partial/pattern only |
| PyGoat context | 0 | 0 | 1 raw miss | 0 | final classification below | partial |
| Exploratory 6 | 3 | 1 | 1 | 0 | 1 with signal | 0 |

For **this selected Java pattern-warning subset only**, precision is 5/10 and
dangerous-case warning coverage is 5/6. This is not the OWASP Benchmark score,
Java/Spring data-flow recall or whole-product accuracy. The missed prepareCall path
has no implemented source-to-sink model. Its unsupported sink context remains visible.
No global precision/recall or BLOCKING accuracy is inferred from mixed small sets.

Internal per-area TP/FP/FN/TN/UNKNOWN/unsupported:
input 3/0/1/3/3/1; authorization 1/1/0/0/1/0; exposure 1/0/0/1/1/0;
supply-chain 0/0/1/1/1/0; deployment 1/0/0/1/1/0;
file/deserialization 2/0/0/2/2/0; crypto 1/0/0/1/1/0; stability 2/0/0/2/2/0.

The harness initially used the wrong exposure rule identifier. An explicit alias
in `summarize.py` corrects accounting from PY_SENSITIVE_RESPONSE_EXPOSURE to
PY_SENSITIVE_DATA_EXPOSURE; no label, fixture, engine output or raw result was changed.

## Important Gaps Preserved Without Engine Fixes

1. Java upstream-labelled safe cases still trigger SQL warnings
   (BenchmarkTest00104/00105/00107/00110/00113). Constant-overwrite defenses were
   manually confirmed in 00104/00105; the other labels come from upstream truth.
   Statement creation alone also warns.
   BenchmarkTest00008's request header reaches prepareCall without a matching warning.
   Splitting query construction across statements reproduces another missed signal.
2. Python encode/decode round-trip before cursor.execute retains MEDIUM/unresolved
   provenance but does not produce the validated SQL candidate: known danger with
   an abstaining analysis, **not** a certified-safe result.
3. PyGoat parses both files and observes 73 entries/functions, but custom decorators,
   general try and ORM raw execution are not resolved. No SQL use/finding is returned.
   Manual classification: NOT_INSPECTED for the relevant execution path, with
   unsupported constructs. Do not count 73 parsed/traced functions as full SQL coverage.
   Its Python SSRF and command execution examples are NOT_SUPPORTED, not clean scans.
4. Compact package.json misses the legacy built-in dependency candidate while the
   structural SCA collector extracts the exact lodash version. Pretty-printing the
   same manifest produces the legacy warning. OSV is not called by this fixture runner,
   so this is **not evidence of a full SCA/OSV missed vulnerability**. The pretty range
   also produces a legacy candidate while SCA version resolution remains unknown.
5. An intentionally public login route triggers permitAll review. This is a
   low-specificity review signal, not proof of an authorization vulnerability.

## Coverage, Risk And UI

Risk COMPLETE means the supported Rule/SCA/intelligence inputs were assessed;
it does not mean all code/authorization paths were inspected. Supplemental flow/
deployment candidates do not change deterministic Risk, score or resolved counts.
Existing ReviewResultWorkspace, AnalysisCoverageSection and ServerAnalysisSection
explicitly disclose those boundaries; zero findings is not whole-project assurance.
Remaining usability risks: READY is visually stronger than caveats, raw analyzer
codes can be opaque, and unsupported paths are harder to connect to a requested
security property than to a file. Policy changes require separate review.

## Validation And Next Priorities

Backend: 455 tests, 0 failures/errors, 5 opt-in skips; actual `--rerun-tasks` run.
Python: 110; TypeScript: 123; frontend: 99; evaluation tooling: 9. All pass.
Frontend build passes. Mock browser coverage/context and server-analysis tests
pass at 1440/390/320 with zero external requests; not real private-result browser QA.
Existing common ZIP/public/private source and snapshot regressions are included;
the fixture runner itself bypasses acquisition and persisted Review/Risk generation.

Priorities: (1) bounded Java/Spring SQL structure and binding evidence;
(2) Python common exception/decorator/ORM execution coverage with honest abstention;
(3) consolidate legacy manifest interpretation with structural SCA;
(4) property-specific coverage/abstention/action provenance;
(5) broader independently authored per-domain tests and untouched holdouts.
Do not tune detectors to these case IDs. Observed evaluation cases become regression material.

Not performed: real exploit/DAST, target execution, AI evaluation, full OWASP score,
independent human assessment, broad external Spring/Express/Next.js tests, or
representative accuracy measurement for all eight domains. These are limitations,
not successful validations. Private results and source cleanup are reported separately.
