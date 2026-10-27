# Security Coverage Matrix #21

Baseline: `8c35a52b409b61d424c82e1c48170b755bbc43ce`, Worker v31,
RLS v3, column-update-v1. Read the implementation, not the older historical
`current-analysis-support.md`, as the current contract. This matrix covers the
requested P0/P1/P2 areas and adjacent existing engines, not every CWE.

## Meaning and references

- FULLY_VERIFIED: only a named, bounded contract checked by its stated controls;
  not complete coverage of a vulnerability family or independently proven accuracy.
- PARTIAL: useful implemented patterns, declarations or flows with material gaps.
- NOT_IMPLEMENTED: no target-code analysis contract for the stated scope found.
- NOT_VERIFIED: implementation exists, but the stated external/runtime claim has
  not been established. This qualifies the real-app column throughout.
- No whole vulnerability family below is FULLY_VERIFIED. A parsed file, HIGH
  confidence, zero findings and a high legacy score are not safety proofs.

Path abbreviations (all repository-relative):

- T = `analyzers/typescript/`; TT = `analyzers/typescript/test/`.
- P = `analyzers/python/`.
- R = `src/main/java/com/securedeploy/rule/rules/`.
- J = `src/main/java/com/securedeploy/analysis/javaflow/`.
- D = `src/main/java/com/securedeploy/analysis/deployment/`.
- ST = `src/test/java/com/securedeploy/`; tests named below are actual files.
- FPR = `src/main/java/com/securedeploy/rule/filter/FalsePositiveAnalyzer.java`
  plus `R/InsecureApiUrlContext.java` and T/static-display-context.mjs.
- F = final Finding guidance exists; E = evidence only, no new Finding guide;
  N = no guide for an unimplemented detector. Guidance is not automatic repair.

## P0

| Area / status | Actual rule ID and implementation | Supported input, framework and judgment | Normal / UNKNOWN / unsupported boundary | Tests and real-app evidence | Guide |
| --- | --- | --- | --- | --- | --- |
| Missing authentication: PARTIAL | `PERMIT_ALL_USAGE`, R/PermitAllUsageRule.java; P/authorization.py; T/auth-result-evidence.mjs | Java permitAll pattern; Django/DRF permission declarations; Supabase getUser/getClaims call plus local absence exit observations | Public API is not automatically vulnerable. Calls are not successful login. Express arbitrary middleware, Next auth wrappers, actual settings activation unknown. No general JS missing-auth Finding | ST/rule/rules/ScannerGeneralizationTest.java; P/test_authorization.py; TT/modern-supabase.test.mjs. Chatbot helper has local guard, not HTTP proof; CopyMonster explicit JWT argument remains unsupported for result evidence | F/E |
| Missing administrator check: PARTIAL | P/authorization.py; `PY_AUTHORIZATION_INVERTED_OWNER_GUARD` is NOT an admin-missing rule; R/PermitAllUsageRule.java is NOT one either | Django IsAdminUser / staff decorator / role rejection evidence | JS isAdmin variable, RPC named has_role, client UI and admin client key do not prove a server role check. Missing-admin finding for arbitrary JS API NOT_IMPLEMENTED | P/test_authorization_permissions.py, P/test_authorization.py; CopyMonster admin-users has external RPC/branch context, NOT_VERIFIED as runtime authorization | E |
| IDOR/BOLA: PARTIAL | `PY_AUTHORIZATION_INVERTED_OWNER_GUARD`, P/authorization.py:396; T/supabase-evidence.mjs and T/node-server.mjs `JS_MONGO_RESOURCE_ACCESS` observations | Django request resource lookup, schema-backed user relation, inverted denial and subsequent mutation; limited Supabase access/policy links | No Finding from request ID or absent visible check alone. Middleware, RLS, sharing intent, role and deployment remain separate. Prisma/general ORM IDOR NOT_IMPLEMENTED | P/test_authorization.py, P/test_authorization_variations.py; TT/access-control.test.mjs. New independent real-app IDOR TP is 0 | F/E |
| User-specific access: PARTIAL | T/auth-result-evidence.mjs; T/write-origin.mjs; P/authorization.py | Next request/Server Function association, local user ID and eq/match row filter; Django FK query scope | Filter column names do not establish ownership. getSession unverified; helper effects, dynamic filters and runtime identity unknown. SELECT filter evidence is not complete SELECT data provenance | TT/modern-supabase.test.mjs, TT/write-origin.test.mjs, TT/access-control.test.mjs; Chatbot helper observation; #21 original-app counters reported separately | E |
| Protected fields / ownership transfer: PARTIAL | T/column-update.mjs `column-update-v1`; T/write-origin.mjs; no automatic protected-field rule | Next INSERT/UPDATE fields and DELETE/UPDATE filters; table/PUBLIC/column UPDATE grants and revokes | No role/owner inference from names. Explicit intent is needed for protected semantics; column SELECT/INSERT, role inheritance, deployed state unknown. Intent pilot remains evaluation-only | TT/column-update.test.mjs; #11/#12 frozen controls and historical isolated PostgreSQL oracle. Not a new runtime test in #21 | E |
| Keys / secrets: PARTIAL | `HARDCODED_SECRET`, `HARDCODED_PASSWORD`, `HARDCODED_FRONTEND_SECRET`, `WEAK_JWT_SECRET`; R/*SecretRule.java, R/HardcodedPasswordRule.java, FPR | Java/config/JS supported declaration patterns, strong credential shapes and limited declaration context | Public-key hints, templates/examples and static display context differ from usable credentials. Key validity, entropy, rotation and runtime use unknown | ST/rule/filter/FalsePositiveAnalyzerTest.java; TT/display-context.test.mjs and html-context.test.mjs; fixed vibe apps are observations, not key-validity truth | F |
| Environment response / client boundary: PARTIAL | `TS_SENSITIVE_DATA_EXPOSURE`, `PY_SENSITIVE_DATA_EXPOSURE`; T/analyzer.mjs, T/exposure.mjs, P/exposure.py; frontend-secret pattern above | Supported Express/Deno/Next/Cloudflare response or log paths; Django request/log/response subset; relative helpers | Server-only use and public settings excluded in supported forms. Unknown masking, dynamic object mutation, aliases/wrappers and actual client bundles are not proven | TT/deno-exposure.test.mjs, TT/next.test.mjs, TT/exposure.test.mjs; Echoverse candidate retained; Next fixture is not general Next runtime proof | F |
| Supabase RLS/GRANT: PARTIAL | `SUPABASE_BROAD_WRITE_DECLARATION`, T/rls.mjs, T/supabase.mjs, T/supabase-evidence.mjs | Ordered selected SQL; row USING/WITH CHECK, supported roles, permissive/restrictive policies, explicit grants and Client/table association | Public SELECT is not broad-write vulnerability. Missing SQL propagates UNKNOWN; user functions, dynamic SQL, owner/BYPASSRLS and actual deployment unknown | TT/authorization-update.test.mjs, TT/supabase.test.mjs, TT/column-update.test.mjs; fixed 15 input observations; historical PostgreSQL oracle not re-executed | F/E |

`ENV_SECRET` is an internal regex in R/HardcodedFrontendSecretRule.java, not a
separate Rule ID. Its result uses `HARDCODED_FRONTEND_SECRET`.

## P1

| Area / status | Actual rule ID and implementation | Supported contract | Normal / UNKNOWN / unsupported boundary | Tests and real-app evidence | Guide |
| --- | --- | --- | --- | --- | --- |
| SQL Injection: PARTIAL | `DANGEROUS_SQL`, R/DangerousSqlRule.java; `JAVA_SQL_INPUT_FLOW`, J/JavaSqlAnalyzer.java; `PY_SQL_INPUT_FLOW`, P/worker.py; `TS_SQL_INPUT_FLOW`, T/analyzer.mjs; `JS_SEQUELIZE_SQL_INPUT_FLOW`, T/sequelize.mjs | Servlet/Spring -> JDBC/JdbcTemplate bounded DI; Django -> cursor/raw subset; Cloudflare D1; verified Sequelize raw query | Static SQL and real supported binding distinct from interpolated SQL. JPA/MyBatis declarations not general ORM execution; unknown type/helper/branch retained | ST/analysis/javaflow/JavaSqlCorpusTest.java and JavaSqlCastEvidenceTest.java; P/test_worker.py; TT/sequelize.test.mjs. DVNA SQL and prior OWASP/Grade B are regression, not new blind success | F |
| NoSQL Injection: PARTIAL | `JS_MONGOOSE_SELECTOR_INPUT_FLOW`, T/mongoose.mjs, T/field-validation.mjs; `JS_MONGO_WHERE_INPUT_FLOW`, T/node-server.mjs | Verified model/driver origin, request input and consumed query; Mongoose v4-v6 callback contract, supported await/exec; Mongo $where execution | Fixed/string filter, supported sanitizeFilter distinct; validation field-local. Query creation alone not execution. v7/v8 callbacks unsupported; dynamic schema/hooks unknown | TT/mongoose.test.mjs, mongoose-callback.test.mjs, field-validation.test.mjs; Goof documented login path static candidate, runtime NOT_VERIFIED. Flint class/event gap remains | F |
| XSS / HTML: PARTIAL | `REACT_DANGEROUS_HTML`, R/ReactDangerousHtmlRule.java; T/static-display-context.mjs; FPR | JS/TS dangerous HTML syntax and bounded passive static HTML / translation context | Static passive markup differs from active/dynamic HTML. This is NOT general DOM taint or sanitizer/browser execution analysis. Stored/reflected XSS across arbitrary stacks unsupported | TT/html-context.test.mjs, display-context.test.mjs; ST/rule/rules/ScannerGeneralizationTest.java; prior CopyMonster HTML FP observations, no new XSS TP | F |
| SSRF: PARTIAL | `TS_SSRF_INPUT_FLOW`, T/analyzer.mjs, T/destination.mjs; `INSECURE_API_URL` / `UNVALIDATED_REDIRECT` are separate pattern rules, not SSRF proof | Supported request URL -> fetch/HTTP destination and relative helper flows | Fixed URL construction / bounded allowlist separated; unresolved transform, DNS, redirects, network reachability and many HTTP libraries unknown | TT/ssrf.test.mjs, ssrf-quality.test.mjs, next.test.mjs; prior controlled Deno/Next/Cloudflare paths, new independent SSRF TP NOT_VERIFIED | F |
| File upload: NOT_IMPLEMENTED | No end-to-end target upload detector found | No complete MIME/content/storage/permission/download contract | Python request.FILES as input does not imply upload security coverage; no execution of uploaded code | No upload-security ground-truth suite. SecureDeploy's own ZipUploadSafetyTest protects product intake, not target upload endpoints | N |
| Path Traversal: PARTIAL | `PY_FILE_PATH_INPUT_FLOW`, P/worker.py resource sinks | Django request input -> supported open/pathlib/file-response access; limited path guard evidence | Fixed paths and supported resolved containment differ; string prefix alone insufficient; symlinks/FS permissions unknown. General Java/Node file access unsupported | P/test_resources.py and resource variations (see inventory); no new independent real-app TP in #21 | F |
| CORS: PARTIAL | `CORS_WILDCARD`, R/CorsWildcardRule.java | Java @CrossOrigin wildcard annotation pattern | Wildcard alone is a configuration review, not credentialed cross-origin exploit. Dynamic Express/Deno CORS middleware and deployed headers unsupported | ST/rule/rules/ScannerGeneralizationTest.java; actual cross-origin request test NOT_VERIFIED | F |
| CSRF: NOT_IMPLEMENTED | No end-to-end anti-CSRF enforcement detector found | Cookie security settings do not establish CSRF token/origin defense | Missing token name is not a Finding; SameSite/session/proxy/browser behavior unknown | Product's own API security tests are not target CSRF detection validation | N |
| Cookie/session: PARTIAL | `INSECURE_COOKIE`, R/InsecureCookieRule.java; `DJANGO_SECURE_COOKIE`, P/worker.py and D/DeploymentGuidance.java; `LOCAL_STORAGE_TOKEN`, R/LocalStorageTokenRule.java | Supported .properties/YAML cookie flags, Django literal settings, browser token storage pattern | Missing flags do not infer runtime defaults; secure context, session fixation/rotation and framework middleware unknown | ST/analysis/deployment/DeploymentAnalyzerTest.java; ST/rule/rules/ScannerGeneralizationTest.java; P/test_settings.py. Runtime cookie behavior NOT_VERIFIED | F |

## P2

| Area / status | Actual rule ID and implementation | Supported contract | Normal / UNKNOWN / unsupported boundary | Tests and real-app evidence | Guide |
| --- | --- | --- | --- | --- | --- |
| Rate limiting: NOT_IMPLEMENTED | No target-route rate-limiting detector found | Analysis worker budgets and own AI request limits are not target protections | Library name or middleware name does not prove enforcement. PY_HTTP_TIMEOUT_REVIEW is timeout, not rate limiting | No target abuse/rate ground truth; no load tests performed | N |
| Docker/Compose: PARTIAL | `DOCKER_ROOT_USER`, `DOCKER_LATEST_TAG`, `DOCKER_SECRET_ENV`, `OUTDATED_DOCKER_BASE_IMAGE`; R/DockerRuntimeUser.java and corresponding rules; `DOCKER_PRIVILEGED`, `DOCKER_HOST_NETWORK`, `COMPOSE_*`, D/ComposeInspector.java | Docker final-stage USER; literal image/env; Compose supported socket, capabilities, mounts, ports, user/security flags | Final declared user is not image runtime proof; dynamic substitutions/extends/override, image layers and FS permissions unknown | ST/rule/rules/ScannerGeneralizationTest.java; ST/analysis/deployment/DeploymentAnalyzerTest.java; fixed apps preserve raw rules; no container startup | F |
| CI/CD: PARTIAL | `GITHUB_ACTIONS_SECRET_ECHO`, `GITHUB_ACTIONS_CURL_PIPE`, `GITHUB_ACTIONS_UNPINNED`, R/GitHubActionsSecurityRule.java | Supported workflow paths and literal action refs / shell patterns | YAML text is not executed workflow DAG; reusable actions, permissions inheritance and runtime secret values unknown | ST/rule/rules/ScannerGeneralizationTest.java; Goof preserved Actions observations; no CI execution | F |
| SCA: PARTIAL | `VULNERABLE_NPM_DEPENDENCY`, `VULNERABLE_MAVEN_DEPENDENCY`, `VULNERABLE_GRADLE_DEPENDENCY` catalog rules; `sca/service/ScaService.java`, `sca/parser/*ManifestParser.java` | Static npm/Maven/Gradle/PyPI exact package+version -> OSV; declaration provenance retained | Ranges/unresolved versions and OSV failure not safe. PyPI tool-specific locks/groups not silently supported; no install/build/runtime reachability | ST/sca/ScaParserTest.java, PythonScaParserTest.java, ScaServiceTest.java; app evaluation external lookups OFF, so not a fresh live advisory check | F |
| Deployment: PARTIAL | `DEBUG_ENABLED`, `STACKTRACE_EXPOSURE`, `EXPOSED_ACTUATOR`; `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`, `DJANGO_HTTPS`, `DJANGO_SECRET_LITERAL`; `NGINX_DIRECTORY_LISTING`, `NGINX_SERVER_TOKENS`, `NGINX_HTTP_ONLY`; `K8S_PRIVILEGED_CONTAINER`, `K8S_LATEST_IMAGE`, `K8S_NODEPORT_EXPOSURE`, `K8S_SECRET_PLAIN_TEXT`; R/* and D/* | Supported config keys, Django literal module declarations, Nginx/K8s patterns, bounded Wrangler context | Effective profiles, TLS termination, includes/rendering, activated settings and live platform values unknown. No general infrastructure runtime audit | ST/analysis/deployment/DeploymentIntegrationTest.java; TT/deno-exposure.test.mjs; fixed apps declaration observations only | F |

## Adjacent existing capabilities

- `JS_SHELL_COMMAND_INPUT_FLOW` / `JS_EVAL_INPUT_FLOW`:
  T/node-server.mjs, TT/shell-flow.test.mjs, TT/regex-flow.test.mjs.
  Verified Express registrations and supported shell/code sinks; execFile argv,
  fixed strings and unknown APIs are separate. DVNA/Goof retained static paths;
  no command execution. PARTIAL, guidance F.
- `PY_UNSAFE_DESERIALIZATION_INPUT_FLOW`: P/worker.py, Python resource tests.
  Supported pickle/unsafe YAML with input provenance, not ordinary JSON.
  Library versions/dynamic input remain unknown. PARTIAL, guidance F.
- `PY_JWT_UNVERIFIED_ACCESS_DECISION`, `PY_JWT_FIXED_SIGNING_KEY`:
  P/token_security.py and P/test_token_security.py. PyJWT-2-compatible API shape,
  explicit disabled verification reaching denial/access logic or fixed signing
  key; display-only decode and examples differ. Library version/runtime verifier
  unknown. JS/Java broad JWT semantics NOT_IMPLEMENTED here. PARTIAL, guidance F.
- `TS_ERROR_DETAIL_EXPOSURE`, `PY_ERROR_DETAIL_EXPOSURE`,
  `PY_HTTP_TIMEOUT_REVIEW`: T/analyzer.mjs, P/exposure.py, P/service_security.py;
  TT/error-security.test.mjs, Python error/service tests. Known error/response or
  explicit request timeout context; arbitrary catch or fetch-without-signal is
  not automatically a service vulnerability. PARTIAL, guidance F.

## #21 exact addition and limits

The bounded local filter-evidence subset is FULLY_VERIFIED **only in the nine
complete authored positive controls and 16 rejection controls**. Overall access
control is still PARTIAL. Existing same-function awaited getUser/getClaims plus
absence-exit proof is reused for immutable ID aliases/destructuring and inline
static match objects. There is a known incomplete two-filter control.

The [official match contract](https://supabase.com/docs/reference/javascript/match)
describes equality conditions for the object's columns, while
[eq](https://supabase.com/docs/reference/javascript/eq) compares one column/value.
These API facts do not identify an owner column. Reading the
[getUser contract](https://supabase.com/docs/reference/javascript/auth-getuser)
does not prove a call in unexecuted source succeeded. Explicit JWT arguments,
React.cache/Proxy, arbitrary middleware and role RPC semantics were not added.

No missing-auth/admin/IDOR Finding was invented. Existing API shape, RLS/column
semantics, Intent oracle, Risk, Score, comparison and repair allowlists unchanged.
Existing authorizationEvidence and Coverage counters carry the additional
locations; successful auth, effective role and deployed authorization stay unknown.

## P0 priorities still open

1. Independently reviewed two-user authorization ground truth on a supported
   request path; current observed apps have no new runtime IDOR TP.
2. Bounded explicit-token getUser and failure-branch context, supported by actual
   Edge code and positive/negative controls, before any success claim.
3. Schema/owner and intent evidence are separate. Keep the #13 pilot unchanged;
   do not classify protected names or intended sharing automatically.
4. External middleware/role helpers and ORM wrappers require their own reviewed
   contracts. Do not replace UNKNOWN with a generic absent-check warning.

For #22, first reproduce known environment object mutation/return and nested
response gaps, distinguish public keys from server credentials, and verify the
whole response path. A helper returning environment-backed data is a candidate
for investigation, not evidence of client exposure by itself. No #22 code here.
