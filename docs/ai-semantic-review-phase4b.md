# Phase 4B: AI-assisted Semantic Security Review

## Purpose and boundaries

Semantic Review proposes security concerns that need human verification. It is not zero-day detection, exploit confirmation, taint analysis or deployment approval. Candidates are `AI_SECURITY_CANDIDATE` / `REVIEW_REQUIRED`. Their `semanticAnalysisConfidence` is independent of existing finding confidence.

Rule Engine, FalsePositiveAnalyzer, SCA, threat intelligence and RiskPrioritization remain authoritative for the existing findings, counts, score and deployment assessment. Semantic candidates never modify those values. This phase helps a developer identify what to investigate before deployment without turning uncertain AI output into a blocking fact.

## Request and execution flow

Existing ZIP and GitHub endpoints, including project-scoped endpoints, accept an optional `scanMode`:

- ZIP multipart: `scanMode=STANDARD` or `AI_ENHANCED` alongside `file`.
- GitHub JSON: `{"repositoryUrl":"https://github.com/owner/repository.git","scanMode":"AI_ENHANCED"}`.
- Omission defaults to `STANDARD`; invalid values return HTTP 400.

`SecurityReviewFacade` runs the existing deterministic pipeline, collects bounded Security Slices only for Enhanced scans, commits the Review with its mode, and then generates remediation and Semantic Review snapshots. Temporary source files are cleaned using the existing flow. Slice/provider/validation failures do not roll back the deterministic Review.

`STANDARD` never resolves an external AI provider, including later manual review, summary, audit, priorities, roadmap and AI PDF requests for that Review. Those requests use existing templates, and legacy snippet context is omitted. Comparison requests use templates when either Review is Standard. This protects the choice after upload, not just during the initial request.

`AI_ENHANCED` permits bounded external contextual remediation and Semantic Review when the configured provider is available. Template mode does not invent semantic candidates: its semantic status is `NOT_REQUESTED`. A missing key/provider gives `UNAVAILABLE`; no supported Java endpoints gives `NO_SUPPORTED_CONTEXT`. None of these states means safe.

Historical Reviews with NULL mode/snapshot remain readable without backfill or automatic AI calls. Their existing, explicitly requested legacy AI actions retain the pre-mode provider behavior. Rescan with `STANDARD` to record a no-external-AI choice; this phase does not retroactively alter consent on old data.

## Security Slice construction

`SecuritySliceCollector` uses JDK 17 `JavacTask.parse()` with `-proc:none`. It never calls `analyze()` or `generate()`, runs uploaded builds, loads uploaded classes or executes annotation processors. No Java parser dependency was added. The runtime needs a full JDK with `jdk.compiler`; unavailable parsing is reported, not interpreted as safe.

Each slice contains a stable slice ID, entry function, literal endpoint/HTTP method, relevant parameter names, authorization-declaration metadata, limited method excerpts and exact original line ranges. Direct syntactic receiver calls connect up to two hops and four methods, with up to two additional security configuration/filter/interceptor methods. Explicit imports and package-qualified names prevent connecting unrelated same-name classes. Ambiguous overloads are not linked.

Selection priority is authentication/session/security, admin, file/command/HTTP/serialization, sensitive resource naming, then other endpoints. The Java file index itself is bounded. Complete lines only are retained; a candidate cannot cite a truncated tail. Stored slice metadata excludes source content.

Limitations include interfaces/dynamic dispatch, wildcard imports, nested/local classes, inherited/array/dynamic request mappings and security checks outside selected methods. These are not a complete call graph. The eight-second indexing deadline is checked between files, not an interruptible per-file parser timeout. Files above 100,000 characters are skipped. All coverage omissions remain uncertainty.

## Outbound privacy and prompt isolation

Only selected Java method excerpts are eligible; no whole archive, repository, `.env` or raw configuration file is sent by Semantic Review. AST string and character literal spans are redacted before slicing, including Unicode-escaped quote delimiters. Redaction preserves line counts. Phase 4A sanitization additionally masks credentials, bearer values, private-key material and opaque strings in source, comments and metadata. Paths are checked segment by segment so normal long package paths are not mistaken for base64 secrets.

This deliberately removes safe string constants too, reducing semantic detail in exchange for conservative privacy. Literal endpoint metadata is separately validated. Masking is defense in depth, not a guarantee that arbitrary secrets hidden in unusual source encodings or identifiers can always be recognized.

Privileged instructions, task constraints and untrusted structured slice JSON are separated in the OpenAI Responses request. Source comments are never promoted to instructions. The request exposes no tools and uses `store: false`. Prompt/response bodies and credentials are not logged. Unit tests verify request isolation; they cannot prove that a live model will always resist prompt injection.

## Provider, output and validation

`AiProvider.generateSemanticReview(...)` is separate from remediation. `RealOpenAiProvider` requests strict JSON Schema output and requires a completed response. Template produces no semantic findings. Provider failure, invalid JSON, refusal/incomplete output or exhausted budget produces an explicit status, without synthetic template candidates or retries.

The untrusted proposal contains slice ID, candidate type, title, semantic confidence, reason, `verificationRequired=true`, evidence, verification steps and optional existing finding IDs. The server owns candidate ID, source/type, review status, provider/model, timestamp and prompt version. Severity, score and deployment fields are not accepted in this schema.

Validation requires exact supplied context ID, file path, function and line range. Blank/oversized text and unprovided finding IDs are rejected. Explicit CVE/GHSA, version-like, qualified-package and endpoint-like claims must occur in the supplied context. This mechanical check does not prove free-prose truth, ownership semantics or exploitability; human verification is mandatory. Partial item rejection remains visible.

Access-control proposals are reduced to LOW confidence when the slice contains an authorization declaration, and always ask the developer to inspect shared authorization and ownership constraints. An annotation is evidence to review, not proof of protection.

Deduplication uses candidate type, primary file/function, endpoint and primary evidence range, never similar prose. Same-family existing findings in a cited method are linked independently of model claims. Initially this recognizes missing authentication / `PERMIT_ALL_USAGE` and sensitive data exposure / selected hardcoded-secret rules. Such results become `existingFindingEvidence`, excluded from new candidate counts. Cross-method equivalence and all possible rule families are not claimed.

## Limits and cost metadata

Settings are centralized under `securedeploy.ai.semantic` and clamped:

| Setting | Default | Hard cap |
| --- | ---: | ---: |
| max-slices | 4 | 8 |
| max-context-chars (instructions + data) | 24,000 | 32,000 |
| max-snippet-chars (per method) | 1,800 | 2,400 |
| max-output-tokens | 4,000 | 6,000 |
| max-candidates | 12 | 20 |
| max-indexed-files | 200 | 300 |
| max-indexed-chars | 2,000,000 | 3,000,000 |
| max-requests | 1 | 1; zero disables requests |

Lowest-priority slices are removed until the full prompt fits. Input is character-bounded, not tokenizer-exact. These limits apply to Semantic Review; Enhanced remediation retains its separate Phase 4A budget. There is no unlimited per-controller call loop.

Snapshot usage records the provider-reported tokens when available. A successfully billed HTTP response may still fail semantic validation; this does not erase token usage. Missing usage is not estimated as a real provider bill. Cost estimation remains unimplemented. `semanticSlicesAnalyzed` records the slices submitted for the attempt, not proof that every slice was fully reasoned about; status and validation state must be read together.

## Snapshot, API and UI

`reviews.semantic_snapshot_json` is nullable TEXT; `scan_mode` is nullable varchar. Run `src/main/resources/db/postgresql/add-review-semantic-snapshot.sql` before a production deployment; it is additive and repeatable, not an automatically managed Flyway migration. Existing rows stay NULL.

The snapshot stores status, accepted candidates, supporting evidence, sanitized location metadata, provider/model/prompt version, validation status, omissions/rejections/duplicates, timestamp and usage. Conditional update saves it once. New scans create new snapshots; historical GET requests never regenerate it. Persistence failure returns the already saved deterministic Review without claiming an unsaved snapshot exists.

The additive `semanticReview` and `scanMode` fields are returned by upload/GitHub and Review detail APIs. Existing authorization and deletion apply because the snapshot belongs to Review. The frontend opt-in defaults off and resets on logout. A small separate "AI security additional review" section displays candidates, uncertainty, exact locations and verification steps. Correlated evidence, coverage and usage have separate details. React renders text, not model HTML.

## Verification recorded 2026-10-12

- Backend: 196 tests discovered, 193 passed, zero failures, three opt-in external smoke tests skipped (OpenAI, OSV, threat intelligence).
- Phase 4B coverage: 16 unit tests, seven integration tests and one mock HTTP transport test. Includes A-K requirements, qualified type collision, Unicode literal masking, bounded context, malformed scan mode, completed empty output and DB/API date representation compatibility.
- Frontend: 23 tests passed, including four semantic UI tests; production build passed.
- Mock OpenAI integration: ZIP/GitHub code paths, separate IDOR/path candidates, exact evidence rejection, usage parsing, failure isolation, immutable history, Standard privacy for manual AI/PDF routes, ownership checks and deletion. A mock HTTP 200 verifies transport/schema/usage handling, not a real OpenAI success.
- Browser with mocked API fixture: Standard/Enhanced upload and candidate rendering passed at desktop 1440px and mobile 390px; no page errors or horizontal overflow. No real API calls from this browser check.
- Development PostgreSQL migration applied twice. Content/count fingerprints of existing users, projects, reviews, vulnerabilities, review snippets and SCA reports were unchanged before/after migration and after fixture cleanup.
- Development backend restarted successfully with `AI_PROVIDER=template`. Real local HTTP signup/login, Standard/Enhanced ZIP uploads, snapshot DB save/detail/history, summary and PDF passed. Template correctly generated zero semantic candidates and zero semantic requests. Synthetic account/project data was removed.
- The initial verification did not make a paid call. The user subsequently confirmed Dashboard attribution and authorized the single live attempt documented below.

## Single live OpenAI attempt, 2026-10-12

The user explicitly authorized one paid Semantic request after confirming prior Dashboard usage. The parse-only `src/test/resources/semantic-live` fixture contains no credentials or personal records. A STANDARD preflight found no code/dependency findings eligible for paid remediation and made no Semantic request. The identical fixture was then uploaded once in AI_ENHANCED mode to an isolated local instance of the same backend, with the existing limits unchanged. The regular development server remained in template mode.

| Measurement | Observed result |
| --- | --- |
| Provider / configured model | OpenAI / gpt-5.4-mini |
| Semantic requests / submitted slices | 1 / 2 |
| Input / output / total tokens | 1,272 / 1,013 / 2,285 |
| Provider-reported billable usage | true |
| Snapshot status | COMPLETED |
| Generated / accepted / rejected candidates | 2 / 2 / 0 |
| Validation | LOCATION_VALIDATED_NOT_SECURITY_PROVEN |
| Additional paid remediation / retries | 0 / 0 |

The accepted candidates were `UNSAFE_FILE_ACCESS` (MEDIUM semantic confidence) in `FileController.download(String)` lines 12-17, and `IDOR` (HIGH semantic confidence) citing the account controller/service/repository. Both remained `AI_SECURITY_CANDIDATE` / `REVIEW_REQUIRED`, with nonempty reasoning, evidence and verification steps. These are suspicions about limited context, not confirmed vulnerabilities. No live hallucinated location was observed; invalid-location rejection remains covered by mock tests.

Compared with STANDARD, the score, vulnerability count, deployment status, priority summaries, assessment coverage and deterministic findings were unchanged. Two subsequent real detail API reads returned the same saved Semantic snapshot without regeneration.

The live verification harness then compared the raw DB JSON directly with API JSON and stopped because the JPA converter writes numeric/array timestamps while the API writes ISO timestamps. This is a representation difference, not evidence of lost candidate data. The integration suite now explicitly decodes the DB snapshot through its converter before comparison and covers a completed zero-candidate snapshot too. The script's finally block removed the synthetic account/project and stopped the temporary server; content/count fingerprints confirmed pre-existing data was unchanged.

Consequently, the full original live result was not opened in the browser before cleanup. Do not describe this as a completely verified live UI E2E. UI rendering is independently covered by component tests and desktop/mobile mock-API browser tests. No additional paid request was made to repeat the browser step. The one-attempt record contains only safe counts and candidate location/title metadata; raw provider output, prompts, source bodies and login credentials are not retained in logs or Git.

## Follow-up and milestone readiness

The implementation has one successful live provider/validation/persistence/detail-API observation plus local/mock UI coverage, not a production semantic accuracy evaluation. The live-browser verification gap above must accompany any milestone report. Additional paid calls require fresh authorization. Larger precision/recall and false-positive evaluations remain future work.

The user accepted this live-browser gap on 2026-10-12 and authorized closing Phase 4B as a Git milestone after final regression and credential/artifact checks. Phase 4A and Phase 4B are complete within these documented boundaries. The next activity is the user's own browser workflow review, not automatic work on another phase; no further paid call is authorized by this milestone closeout.

Future data-flow/taint/reachability can attach independently verified source, propagation, sanitizer and sink evidence to the slice/candidate identity. Only a versioned deterministic policy should promote such verified evidence into risk decisions. Full repository upload, automatic blocking, code patches, PR creation and all-language semantic parsing are out of scope.

References: [JDK JavacTask](https://docs.oracle.com/en/java/javase/17/docs/api/jdk.compiler/com/sun/source/util/JavacTask.html), [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs).
