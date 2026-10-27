# Context-aware XSS / SSRF precision #25

## Baseline and scope

Start: `885366254efcf73fcfd2dbfd9bb612c78060ebf0`, origin/main, Worker v35.
Product commit: `87c7f59d4c946c08198cb0a7757febc8735334b1`, Worker v36,
string-context-v7. RLS v4, column-update-v1 and Authorization Intent #13 are
unchanged. Work is isolated on `codex/xss-ssrf25`; protected local main stays
`15070416`, localhost:8080 stays v28/PID 99387. No server/JAR replacement.

Three bounded changes were justified, not a new general browser/HTTP engine:

1. Closed passive HTML conditional alternatives can now disprove a lexical JSX
   warning. This is NOT an external-input-to-DOM XSS flow implementation.
2. Proven Node built-in http/https.get with exactly one URL argument reuses the
   existing request-source, destination and TS_SSRF_INPUT_FLOW adapter.
3. Literal or already-bound identifier arms of a conditional do not clone and
   invalidate unrelated heap receivers. The condition is evaluated first. Calls,
   property access, allocation and mutation retain conservative branch handling.

No new rule ID, DB/API/UI schema, automatic repair contract or Risk formula was
introduced. No original application's new XSS/SSRF TP was established: **0**.
No new official vulnerable/patched pair or independent holdout was acquired.

## Existing contracts and official mapping

| Contract | Evidence and remaining boundary |
| --- | --- |
| REACT_DANGEROUS_HTML | ReactDangerousHtmlRule.java lexical JSX warning, reconciled by InsecureApiUrlContext and url-context/static-display-context. HIGH describes sink-pattern confidence, not attacker control or exploitability. |
| HTML negative proof | Exact intrinsic passive container, closed __html object, bounded static text and passive markup. No custom component, spread, event/style/raw-text/foreign markup proof. |
| TS_SSRF_INPUT_FLOW | analyzer.mjs observeHttp + destination.mjs, ServerFlowFinding.java corroborates source/flow/sink before producing REVIEW_REQUIRED/NOT_COMPARED. Existing fetch/URL/Request paths retained. |
| Node GET addition | node-server.mjs uses proven built-in import/require identity, bounded aliases/helpers and actual supported request registration. A same-named method is insufficient. |
| Java/Python SSRF and XSS | Existing adapters/patterns and their tests retained; no new language/library support claimed. |

[OWASP Top 10:2025 A05](https://top10.owasp.org/2025/A05_2025-Injection/),
[XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
and [DOM XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
require context-appropriate output handling, not universal escaping.
[ASVS 5.0.0 V1](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x10-V1-Encoding-and-Sanitization.md)
1.2.1/1.2.2/1.2.3 distinguish HTML/attribute, URL and JavaScript contexts;
1.3.1 addresses untrusted HTML sanitization; 1.3.6 addresses SSRF allowlisting;
1.5.3 addresses consistent parser behavior. These are mappings, not ASVS
compliance or full implementation claims. Taxonomy:
[CWE-79](https://cwe.mitre.org/data/definitions/79.html) and
[CWE-918](https://cwe.mitre.org/data/definitions/918.html), reviewed MITRE 4.20 pages.

[React common components](https://react.dev/reference/react-dom/components/common)
(documentation displayed v19.3) distinguishes normal text children and raw HTML.
[MDN innerHTML](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML),
[textContent](https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent)
and [insertAdjacentHTML](https://developer.mozilla.org/en-US/docs/Web/API/Element/insertAdjacentHTML)
were reviewed. No React-version-wide URL scheme protection or script-element
textContent safety is inferred. No new DOM API flow or encoding contract exists.

[DOMPurify official README](https://github.com/cure53/DOMPurify) reported v3.4.17;
the pinned tag page was unavailable to the browsing tool. Import provenance,
secure installed version, configuration/hooks and post-sanitization changes
are NOT verified by the product here. A normal sanitizer control is explicitly
conditional on those facts; its retained warning is counted as FP under those
assumptions, not silently removed or counted as a successful sanitizer proof.

[SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html),
[Node HTTP](https://nodejs.org/api/http.html#httpgeturl-options-callback),
[HTTPS](https://nodejs.org/api/https.html#httpsgeturl-options-callback),
[URL](https://nodejs.org/api/url.html#new-urlinput-base) and
[fetch](https://nodejs.org/api/globals.html#fetch) were reviewed.
The GET auto-end contract was also checked in pinned Node
[22.14.0 HTTP](https://github.com/nodejs/node/blob/v22.14.0/doc/api/http.md) and
[HTTPS](https://github.com/nodejs/node/blob/v22.14.0/doc/api/https.md) documentation;
current Node docs displayed v26.12.1, owned canaries ran on v26.0.0.
No npm HTTP dependency was installed. This is a built-in API contract, not an
exhaustive certification of every Node release or runtime configuration.

## Reproduced causes and changes

Before: static conditional HTML was unresolved even when every alternative was
passive. closedChoices now accepts at most 8 alternatives, depth 12 and bounded
combined text, through existing lexical const/write checks. Both alternatives
must be proven; literal true/false selects only the reachable expression.
Mixed input, unknown sanitizer, custom container, dynamic HTML, mutation and
parse/budget failure do not acquire an exclusion. This is not an HTML sanitizer.

Before: http/https had a proven module identity for server registration, but no
outbound GET sink. The new contract recognizes URL/string abstract values and
their joined destination facts, not arbitrary option objects. Only one argument
is accepted. Options, callback overloads, request/end wrappers, altered method
identity and unresolved origins remain unsupported/unresolved. Built-in module
identity is shared consistently across imports; relevant writes invalidate it.

Before: ternary heap forks invalidated an unchanged Sequelize/native receiver.
Inert arms can now be joined without heap mutation. The #24 frozen 67 input
cases, labels and published result bytes are unchanged; only its regression
assertion for the now-resolved normal cases was updated. Object/mutating branches,
arbitrary guards and unknown calls have not been generalized.
The #24 evaluator's expectation gate is versioned: v35 retains the historical
normal deferral, v36 must provide the reviewed normal observation. Ground truth,
input code and frozen #24 result bytes are unchanged.

## Same-input Grade B differential

43 same-author, nonblind controls, twice per engine, stable non-timing outputs.
Controls were authored during development, not prospectively preregistered.
No separate external requirements reviewer or unobserved validation set exists.
Public source-free receipt: `scripts/evaluation/context-xss-ssrf25-results.json`.

A corrective ground-truth review found four initial UNKNOWN labels conflated
analyzer limitations with source semantics. The original fixture/receipt hash and
initial aggregate are preserved in the receipt's curationReview (original fixture
is also in product commit 87c7f59). No input code or engine changed in this review.
Simple hostname options, an inert response callback, an insufficient string prefix
guard and changing href after validation are RISK, even though not detected.
This correction worsens the reported result; it is not an independent review or
a post-hoc rule to make a test pass. The first eight-of-eight risk figure omitted
these known risks and must not be used as the full target-set recall.

| Population | v35 | v36 |
| --- | --- | --- |
| XSS JSX pattern reconciliation, 21 | TP-pattern 5, FP 7, FN 0, TN 3, UNKNOWN 6 | TP-pattern 5, FP 1, FN 0, TN 9, UNKNOWN 6 |
| SSRF GET target set, 22 | TP 0, target misses 12, TN 1, normal-deferred 5, UNKNOWN 4 | TP-static 8, FP 0, FN 4, TN 5, normal-deferred 1, UNKNOWN 4 |
| #24 SQL controls, 51 | TP 18, TN 12, normal-deferred 3, UNKNOWN 15, NOT_INSPECTED 3 | TP 18, TN 15, UNKNOWN 15, NOT_INSPECTED 3 |
| #24 NoSQL controls, 16 | TP 5, TN 6, UNKNOWN 4, NOT_INSPECTED 1 | unchanged |

XSS TP-pattern is warning retention at the labeled JSX site, NOT proof of a
rendered attack path. Its conditional warning precision is 5/6 after, not a
product-wide detection metric. Source-to-DOM support remains incomplete.
The baseline's twelve GET misses are all outside its API contract, not twelve
failures within v35's supported HTTP APIs. After's target-set recall is 8/12
(66.7%), candidate precision 8/8. Two misses are unsupported options/callback
overloads; two are flow/guard gaps in the one-argument API (8/10 recall there).
These apply only to authored static controls. Fixed/allowlisted observations
are URL-shape facts, not complete network safety; a no-sink lookalike contributes
one reviewed normal control. UNKNOWN and normal deferral are not TN or TP.

Remaining normal-deferred: a protocol/hostname guard joined with logical OR still
conservatively loses the native GET receiver. The equivalent sequential guards
produce allowlist evidence. Its NORMAL truth was retained, not relabeled UNKNOWN.
The four risk misses remain FN, not UNKNOWN/TN, and produce no false-safe fact.
Unknown controls produce neither a confirmed candidate nor a false-safe fact.
The older 18 HTML controls already give TP-pattern 5 / FP 0 / TN 7 / UNKNOWN 6
on both frozen v35 and v36. Their tool/test still expected the old fixed-HTTPS-link
FP; only that stale expectation was corrected, with no input/truth or archived
result rewrite. This is evaluation maintenance, not a new #25 detection success.
Unsupported HTTP overloads, unsafe prefix checks and changes after validation
remain risk misses with unresolved/no target observation. Partial hostname guards
and externally mutated APIs/options remain UNKNOWN. No IP-range, metadata,
IPv6 reachability, DNS rebinding, proxy or final redirect safety is established.
Built-in GET itself does not automatically follow redirects, but surrounding
application redirection and subsequent network behavior are not verified.

## Actual retained applications

All 15 fixed inputs across 9 existing plans were re-evaluated twice through the
real Backend/H2 application evaluator. Full SHAs and plan hashes are in the
public receipt. This is regression, not 15 new independent project families.
Source file byte counts/hashes are verified by the existing evaluator.

Raw/filtered Rule findings, final structural finding identities, score, Risk and
SCA receipts are exactly unchanged. RLS clients/tables/findings are unchanged.
Selection, parsed files and registered requests are unchanged; no original new
XSS/SSRF candidate was established. Original vulnerable/remediated DVNA inputs
and Goof retain their existing target findings; no new official XSS/SSRF patch
pair was analyzed. Lack of a warning in any general app is not a TN label.

CopyMonster's Auth.tsx:241 custom Label/translation and dynamic partner values
remain review warnings. chart/style HTML warnings remain. No repository-name
exception or forced suppression was added. Existing HTTP observations in
chatbot-ui, Echoverse and CopyMonster do not establish a new high-confidence
target SSRF. Unseen wrappers/client boundaries remain limited.

App duration snapshots: v35 min/median/max 211/519.5/845 ms, v36 217/510/822 ms.
These are separate local runs, not causal speedup evidence. Parent JVM used-heap
snapshots range 56.4-163.0 MB before and 56.1-205.6 MB after; these are neither peak
RSS nor memory guarantees and depend on GC timing. No OOM/worker timeout occurred
in this replay. chatbot-ui steps 70145->70126; CopyMonster 90442->90081.

An owned 43-control process profile, two iterations each, with 192 MiB old-space:
172.1->183.7 ms, peak RSS 148193280->145735680 bytes. Single noisy samples, not
production throughput. Existing server file/character/node/step/function/depth/
timeout limits remain unchanged. String-context retains its separate 250000
per-file / 1000000 total character limits. No limit was raised to improve counts.

## Remediation and owned runtime evidence

Existing XSS guidance first asks for source/defense review. Use ordinary JSX
text, or textContent on a normal text element when HTML is unnecessary. When HTML
is required, verify a maintained sanitizer's actual import/version/options,
post-processing and the final context. HTML encoding is not JavaScript-context
protection, URL encoding is not a scheme allowlist, and CSP is not root-cause repair.

Existing SSRF guidance asks users to select fixed server destinations instead of
accepting whole URLs, or validate parsed protocol/hostname/port against exact
allowlists and separately handle redirects, DNS/connection IP and network policy.
Do not use a URL prefix as a host check or assume fixedBase prevents replacement.

Owned canaries only: a Chromium data document showed a controlled button handler
executing after innerHTML; replacing insertion with textContent preserved literal
content without a button/handler. This is not React, DOMPurify or target-app runtime
validation. Two ephemeral 127.0.0.1 HTTP servers demonstrated an absolute input
replacing a base; the fixed-token implementation rejected the other target while
preserving the approved response. No external host, cloud metadata, production
service or user backend was contacted. Sources were authored, not acquired apps.

Source/sink/trace, execution location, defenses and existing uncertainty remain
available through existing Evidence. No unsupported AI/automatic fix button was
enabled. Static candidate removal is not runtime compatibility or attack proof.

## Regression, safety and release boundary

- Worker: 811 tests passed; focused #25 45 passed.
- Backend: 706 tests, 0 failures/errors, 9 explicit skips (697 executed); new GET
  final Finding and closed-HTML Rule integration passed, as did old snapshot tests.
- Python: 117 passed; evaluation Python tools: 250 passed; JS receipt/HTML tests: 3 passed.
- Frontend: 165 passed and production build passed. No UI source changed; generated
  tracked tsbuildinfo was restored to its pre-build state.
- ZIP/GitHub adapters, user isolation, Workspace patch/revision, Risk, comparison
  and export contracts passed their non-live Backend tests. Live GitHub App,
  paid OpenAI, real OSV/EPSS/KEV and a fresh whole-product browser E2E were not run.
  Existing opt-in corpus/workspace smoke tests account for other explicit skips.
- User DB/Review/Workspace/Snapshot unchanged; no migration or server restart.
  Snapshot v35 and earlier are retained without recalculation; NOT_COMPARED stays.
- #13 result hash remains `93fe972e3b9177c01317a815607679cf270e91405859e9ca8d21f979bacc3c2e`.
  #23 result hash remains `992d6b9dc4d5eb0bd9ff7774763baf39ddcad1a7283057f2e76f5ba67ea104b8`.
  #24 result hash remains `a3bd2ccb72e201822765cd536eceb33667571d2e329f94cd6e2138d21a044a80`.

The legacy Risk/Score formula and FPR policy were not changed. Proven HTML warning
exclusion can legitimately reduce that existing rule's score penalty in new
reviews; retained original apps showed no score delta. New structural GET
candidates stay REVIEW_REQUIRED/NOT_COMPARED and do not enter legacy score/blocking
or resolved counts. No source is auto-patched and no past result is rewritten.

Only own code/tests/tools and source-free public metadata are committed. External
originals, three protected private evaluation documents, logs and build outputs
are excluded; staged files undergo credential-pattern and path/diff checks.

Next: retain the logical-OR receiver gap as a separately bounded failure case.
For file-upload/Path Traversal, reuse proven module provenance, request/argument
traces, inert conditional joins, mutation invalidation and per-request state
isolation. A path-prefix or normalization call must not become containment,
symlink, filesystem permission or deployment proof. No next analyzer was started.
