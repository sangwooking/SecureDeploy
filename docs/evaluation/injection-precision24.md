# SQL / NoSQL injection precision #24

## Baseline and bounded decision

Baseline `cd2361dce096c01b0657ec4bd440e0d4ccbbd05f`: Worker v34, RLS v4,
column-update-v1. Product commit `e7b0a4b`: Worker v35. Original local main stays
`15070416`, backend v28/PID 99387 on port 8080 stays running. No user DB, Review,
Workspace, stored Snapshot, deployment or paid AI call is involved.

Retained actual app paths were reviewed before expanding a library contract.
DVNA's existing raw string SQL path and Goof's login selector path already have
source-reviewed static candidates. This milestone does NOT discover new original
application TP. Three narrower gaps were reproduced in authored controls:

1. Sequelize query-object arguments lose SQL-field provenance because the old
   handler looked at the aggregate argument trace rather than its query member.
2. Mongoose filter scanning confuses repeated symbolic values with ancestor
   cycles, losing unsafe shared-object paths and normal constant-alias evidence.
3. An input-free trusted branch can contaminate the aggregate trusted flag and
   incorrectly invalidate a sibling field's declared sanitizeFilter protection.

These changes reuse existing AST/library/value contracts, not a new ORM engine.
No Prisma/node-postgres expansion or generic branch/heap rewrite was attempted.

## Coverage matrix and official evidence

| Rule / module | Actual support | Boundary / validation |
| --- | --- | --- |
| DANGEROUS_SQL, DangerousSqlRule.java | Java lexical warning for native/Statement/concatenated SQL patterns | Not source-to-execution proof; existing Java structural suppression/FPR unchanged. |
| JAVA_SQL_INPUT_FLOW, analysis/javaflow | Parse-only Java Servlet/Spring -> supported JDBC/JdbcTemplate and bounded helper/DI paths; static Mapper declarations separately | Existing Java SQL v4 and binding tests retained in Backend suite. Not arbitrary ORM/SpEL execution. |
| PY_SQL_INPUT_FLOW, analyzers/python/worker.py | Supported Django/DRF request -> raw SQL calls and parameter separation | Python v8; existing AST/flow limitations apply; 117 Python tests rerun. |
| TS_SQL_INPUT_FLOW, analyzer.mjs | Supported Worker/Pages -> D1 prepare/bind/execute contract | Not generic Node pg or Prisma merely because a method is named query. Existing tests retained. |
| JS_SEQUELIZE_SQL_INPUT_FLOW, sequelize.mjs | Proven Sequelize instance, declared major 4-6, raw query call, bounded imports/initialization summary | Strings plus this milestone's static query/values/bind objects. Tests at 4.44.4, 5.22.5, 6.37.5; installed versions/dialects/hooks not verified. |
| JS_MONGOOSE_SELECTOR_INPUT_FLOW, mongoose.mjs | Declared Mongoose 4-8, bounded direct model/schema registration, find/findOne, await/exec and versioned callbacks | Callbacks 4-6, unsupported 7/8 callbacks remain abstentions. Flat scalar schemas only; not arbitrary middleware/plugins/aggregation/update APIs. |
| JS_MONGO_WHERE_INPUT_FLOW, node-server.mjs | Proven official-driver collection, request -> $where and supported consuming call | Not complete object-selector injection support for every MongoDB driver API. |
| Prisma raw queries / node-postgres | Official contracts reviewed, no new product API provenance/sink support | NOT_SUPPORTED by these TypeScript structural adapters. No success counted for a method name or an unrelated warning. |

[OWASP Top 10:2025 A05 Injection](https://top10.owasp.org/2025/A05_2025-Injection/)
and the [SQL prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
provide taxonomy and parameterization/allow-list guidance, not an accuracy oracle.
[ASVS 5.0.0 V1 1.2.4](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x10-V1-Encoding-and-Sanitization.md)
addresses database injection protection; [V2 2.2.1/2.2.2](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md)
addresses structured input validation at a trusted layer. Input format checks
are not thereby SQL grammar separation or authorization proof. No ASVS compliance
claim is made. Existing candidates use [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
and [CWE-943](https://cwe.mitre.org/data/definitions/943.html), MITRE 4.20 pages;
the labels are not a substitute for source/API/execution-request evidence.

API source review, without executing the libraries:

- Sequelize [4.44.4](https://github.com/sequelize/sequelize/blob/v4.44.4/lib/sequelize.js),
  [5.22.5](https://github.com/sequelize/sequelize/blob/v5.22.5/lib/sequelize.js),
  [6.37.5](https://github.com/sequelize/sequelize/blob/v6.37.5/src/sequelize.js):
  object query field selection, values/replacements and bind handling, conflicting
  settings and eventual raw query execution. The [v6 guide](https://sequelize.org/docs/v6/core-concepts/raw-queries/)
  explains replacements versus binds. Representative pinned versions were read;
  this is not an exhaustive assertion about every release within each major.
  An initial v4.13.10 raw fetch/archived guide was unavailable; v4.44.4 source was
  verified instead. DVNA's declared older v4 remains a declared-version contract,
  not proof of its installed package bytes.
- [Mongoose 6.13.11 queries](https://mongoosejs.com/docs/6.x/docs/queries.html)
  and [sanitizeFilter/trusted API](https://mongoosejs.com/docs/6.x/docs/api/mongoose.html):
  query construction versus consuming operations, and the given object's trusted
  exception. Default Mongoose documentation now describes v9; it was not used
  to claim v9 support. Existing versioned callback/validation contracts remain.
- [Prisma raw documentation](https://www.prisma.io/docs/orm/v7/prisma-client/using-raw-sql/raw-queries)
  redirected to v7: safe tagged APIs, raw strings and unsafe helpers have distinct
  contracts. Neither queryRaw nor queryRawUnsafe names alone establish a verdict.
- [node-postgres queries](https://node-postgres.com/features/queries) and
  [PostgreSQL 16 PREPARE](https://www.postgresql.org/docs/16/sql-prepare.html):
  values and query syntax/identifiers are different, and preparing is not the
  same as execution. No pg adapter or database execution was added here.

## Implementation details

Sequelize recognizes a closed, known object with query plus optional values/bind
own fields; the existing symbolic reference and current-field state are reused.
Only query contributes SQL provenance; data arrays do not become query syntax.
Unknown object state/keys and conflicting bind/replacement declarations remain
unresolved. Adding bind beside already interpolated SQL is not a sanitizer.
No arbitrary getter, wrapper, configuration or template tag is executed.

Mongoose scans ancestor reference identity, not a shared global visited set.
Sibling aliases can be read independently; a true cycle/depth/unknown mutation
remains unresolved. A 1024 filter-scan work budget supplements existing global
limits. Trusted markers with no remaining input trace do not disable a sibling's
protection; trusted tainted/unknown inputs still do not become declared safe.
Existing field-scoped guards, format-only uncertainty, schema/version checks,
query mutation checks and callback execution rules remain in force.

Finding source/sink positions, model/instance origin and execution-request
locations use the existing Evidence structure. New independent candidates stay
REVIEW_REQUIRED/NOT_COMPARED. MEDIUM/unresolved worker observations are not counted
as a confirmed target TP or promoted by this change. No automatic repair allowlist
is expanded. FalsePositiveAnalyzer and all Risk/Score algorithms are unchanged.

## Same-input controlled differential

Final authored population: **67** cases, each on v34/v35 twice. SQL 51 cases are
17 structures across three declared versions: 18 risk, 15 normal, 18 uncertain.
NoSQL 16 cases: five risk, six normal, five uncertain. Every before/after pair
uses the same final input hash and truth. v5/v6 SQL cases are labeled same-author
validation, not an external holdout. Nothing here establishes web-wide accuracy.

| Outcome | SQL v34 -> v35 | NoSQL v34 -> v35 |
| --- | --- | --- |
| TP static risk contracts | 3 -> 18 | 1 -> 5 |
| FN including deferred risk | 15 -> 0 | 4 -> 0 |
| FP static normal contracts | 0 -> 0 | 1 -> 0 |
| TN reviewed static controls | 12 -> 12 | 3 -> 6 |
| Normal deferred, not TN | 3 -> 3 | 2 -> 0 |
| UNKNOWN observations | 3 -> 15 | 4 -> 4 |
| NOT_INSPECTED | 3 -> 3 | 1 -> 1 |
| Safe-like observation on uncertain truth | 12 -> 0 | 0 -> 0 |

The last row means the old internal STATIC_OR_DATA_ONLY observation was
inappropriate for those uncertain query-object contracts. It is NOT twelve
confirmed normal FP removals, twelve new vulnerabilities, or proof that the old
UI explicitly labeled an application safe. These cases remain uncertain and
are not detection successes. Dynamic wrappers and unconsumed queries are
NOT_INSPECTED, not normal. Three constant identifier allow-list controls retain
normal truth but lose the SQL execution connection after a conditional; they
remain normal-deferred, never TN. This known gap was not hidden by relabeling.

The NoSQL normal trusted control has an input-free static branch outside the
declared fields, explicit strictQuery:true and a separate sanitized input field.
It tests injection-contract protection only; no query result, live casting,
database content or authentication behavior was verified.

During preparation a binding-after-concatenation control was strengthened to
include an actual separate $1 placeholder, retaining its RISK truth. Draft
receipts remain outside Git. Final metrics use both engines on that final source,
not a mixture of preliminary and final inputs. The evaluator was also hardened
after non-blind technical review: safe-like observations cannot be hidden under
UNKNOWN (even mixed observations), normal TN requires a parsed target entry,
and output paths reject absolute/traversal/encoded/symlink components. Regression
tests verify original bytes are not overwritten. The reviewer did not run an
independent oracle or approve project requirements.

## Original sources and full-app differential

Retained DVNA, MIT, vulnerable SHA `9ba473add536f66ac9007966acb2a775dd31277a`:
`core/appHandler.js` SHA-256
`0fc237589d5a9e73450d089f97124fb943d68222f70df0e973a8b9acfe2ebb6b`.
Request login is concatenated in SQL at line 10 and sent to Sequelize at line 11.
That original route already has a candidate before and after this milestone.

Retained remediated SHA `4b16c488839ac5428b9c2573c96d886bee885b02`, same file hash
`05446d6f7bbf2beb6ddb5db1070c14d6472d6118b1ce35c2b63ad975819dd9f3`,
replaces this raw path with a validation helper and model lookup. The raw target
is gone, but this does not establish full support/safety for its wrapper and ORM
query builder, nor a new verified CVE patch pair or whole-project TN.

All **127** retained vulnerable input hashes were verified before making disjoint
private control copies; originals are unmodified. One changes only query(query,
options) to the official query({query},options) form, preserving routing/model/
helper context and the unsafe SQL. Another uses a fixed SQL string and separate
bind value. These are Grade B authored transformations, NOT upstream patches.
No original code or copied source is committed.

Both complete inputs were evaluated through real analysis services with isolated
H2, no Review storage, twice per engine. Same plan SHA-256:
`5b928de2e7589a5b74cc53239bf7d71a9bb527b900de117f61f22f3a58d7eed2`.

| Target result | v34 | v35 |
| --- | --- | --- |
| Query-object risky SQL at core/appHandler.js:11 | No target Finding | One final JS_SEQUELIZE_SQL_INPUT_FLOW |
| Bound-query-object counterpart | No target Finding | No target Finding |
| Existing shell candidate, both inputs | One | One, unchanged |
| Legacy score / Risk / Coverage, both | 79 / BLOCKED / PARTIAL | unchanged |

The raw SQL call is an execution request, not proof that a database accepted an
attack. The fixed control preserves non-target source bytes and handler/result
structure, but no installed Sequelize/dialect, functional query result or external
application runtime was executed. Existing recommendations remain conditional on
version, schema and query semantics; no runtime functionality guarantee.

Goof original SHA `add14ba59e98240d9e00a235dd7d42cd61ae9912` retains its separate
password source at routes/index.js:52 despite the other field's format check.
Route hash `a13d03f614346d07173ca0a4bb0917c35c8690ba5e14cdd3d091aa3810ea6d22`.
Its shell and login candidates remain regression, not new independent successes.
FlintCMS CVE-2018-3783 still lacks the prior end-to-end request/model execution
connection; no new full-CVE TP is claimed and that runtime model was not expanded.
New independently verified original-app TP = **0**. Real-app FP/FN/TN rates cannot
be computed from unlabeled whole projects or an absent raw-call warning.

## Guidance and correction contract

Existing user-facing guides are reused, not replaced with generic escaping:

1. Open the displayed SQL/selector call and its source location. Confirm the
   receiver/library/version and the actual query field, not just method spelling.
2. Keep SQL syntax fixed and place values in supported bind/replacements slots;
   parameter values are not dynamic table/column identifiers. Adding bindings
   after concatenation does not remove the already embedded input.
3. For selectors, fix operator keys on the server and reject invalid primitive
   types independently for each accepted field, with appropriate length/format.
   One field's validator and another input-free trusted object do not protect
   every field. trusted is not a general sanitizer. Check its supported version.
4. Do not claim String conversion fixes password storage/authentication, SQL
   grammar, authorization or every NoSQL API. Review hashing and access checks
   separately. Preserve normal fields and review input/API compatibility changes.
5. Reinspect the corrected same-source pair; test normal and object/invalid input
   in an owned local environment with the actual supported dependency/dialect.
   No customer DB patch, automatic application, paid AI or deployment occurred.

The corresponding controlled SQL concatenation/binding and NoSQL primitive/
sanitization cases are tested. Runtime query compatibility remains unverified.

## Regression, safety and resources

- Fixed 15 original inputs, unchanged SHA/plan, two runs each: all existing
  structural identities, RLS candidate/table metadata, legacy raw/filtered rules,
  Score/Risk/SCA and Client evidence retained. No new original-app candidates.
  Baseline #23 receipts use product commit 32d12bd, whose product code is the
  same as cd2361d (later evaluator/report-only changes).
- #18 35 / #19 53 / #20 36 states unchanged; #21 26 identity/role contracts
  unchanged. #22 90 outcomes unchanged: TP32/FN1/FP0/TN30/UNKNOWN27. #23 static
  contracts still 14/14 under RLS v4. Historical controlled PostgreSQL results
  are preserved, not rerun or added to this milestone's new execution count.
  In particular, #20's RISK-labeled nondominating-type case still has its known
  UNKNOWN outcome after branch/heap merging; it was not relabeled or counted as
  a new success. Zero FN in the new 67-case population is not zero remaining
  FN across the older corpus or the product.
- RLS, column-update-v1, Intent, exposure/FPR and Risk code untouched. Intent #13
  hash `93fe972e3b9177c01317a815607679cf270e91405859e9ca8d21f979bacc3c2e`;
  #23 result hash `992d6b9dc4d5eb0bd9ff7774763baf39ddcad1a7283057f2e76f5ba67ea104b8`.
- Worker **766 pass**; Backend **704 tests, 0 failures/errors, 9 existing skips**;
  Python analyzer **117 pass**; evaluation tools **249 pass**; Frontend **165 pass**.
  No frontend source change; no new frontend build/browser or live GitHub E2E
  is claimed. Existing ZIP/mocked public/private GitHub, user isolation, Workspace,
  repair, revision, rescan/History and Snapshot/Before-After tests pass.
- App observations **211-845 ms**, maximum sampled parent JVM heap
  **163005280 bytes**, not Worker peak RSS. Full controlled DVNA: risky v34
  613/514 ms -> v35 779/626 ms; bound 487/484 -> 599/621 ms. No speedup claim.
- Isolated Worker sample twice: SQL RSS v34 132022272/129253376 -> v35
  128581632/131858432; NoSQL 131022848/130809856 -> 131661824/128286720 bytes.
  About 0.17 seconds. Work steps unchanged at 284 (SQL) / 385 (NoSQL). These
  are small local measurements, not a hard RSS bound or production benchmark.
- Existing file100 / file100000 chars / total1000000 chars / depth3 /
  steps100000 / AST200000 limits remain. Worker old-space192 MiB, backend timeout
  and process isolation unchanged. Filter fanout regression verifies explicit
  MONGOOSE_FILTER_SCAN_LIMIT/UNKNOWN rather than expanding work or false safety.
- No external source installation/build/execution, remote attacks, user DB SQL,
  original downloads, actual credentials, paid AI, server restart or deployment.
  Only official documentation/source was read online. Three private untracked
  documents remain excluded. Gradle's existing deprecation warning remains.

## Next XSS/SSRF boundary

Keep argument/member selection and alias identity corrections library-scoped.
Next investigate conditional fixed-value/receiver merging with risk/normal/
uncertain controls before claiming allow-list support. XSS needs actual HTML
context/sanitizer origin and response linkage; SSRF needs destination components,
redirect/DNS and fetch/SDK provenance. Neither SQL type validation nor RLS proves
these properties. Prisma tagged templates, arbitrary pg clients, complex ORM
wrappers, dynamic filters, advanced schemas/hooks and new query operators remain
separate unsupported/unknown contracts until evidence and bounded tests exist.
