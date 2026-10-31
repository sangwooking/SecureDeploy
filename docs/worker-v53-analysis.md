# Worker v53 — bounded structural improvements

Start: b7189c7f9d405dd303760d5e92ae684d8d9d1c06 (HOTFIX-01, containing EPIC-01 D+).
Operating Frontend-only HOTFIX was applied first. Operating Backend/Worker remain b2fd658 / v52.
No operating database/key changes, paid calls, remote pushes or private project source acquisition.

## Frozen baseline and first-cause audit

The original 33 inputs and evaluator are unchanged. v52 replay: TP12 FP0 TN5 FN4 UNKNOWN12.
The original five Python oracles are unchanged: TP2 FP0 TN2 FN1. These are synthetic
code-review/owner-policy oracles, not real-project accuracy. The seven missing real inputs remain unavailable.

| case | first missing link | bounded change |
| --- | --- | --- |
| Router plus middleware | AST/module parsed; `.use` admitted only one Router or path+Router; child never became reachable | explicit prefix plans and literal arrays, heap-identity parent edges |
| Pages API | path recognized only as unsupported; default callback never entered | manifest/convention-bound default function and static export graph, Pages request/response tags |
| computed environment key | array `.join` became unresolved call, so secret identity unknown | closed constant string/key AST evaluator, no target execution |
| HTML response | HTTP body taint was not a modeled output obligation; JSON/environment exposure is a different pass | retain review observations with source/sink and explicit output context; do not create a new Finding Rule ID |
| Django ownership | authenticated unscoped object write recorded `NOT_ESTABLISHED`; absence of local guard does not prove external policy | strengthen bounded ownership/query/write observations, retain policy uncertainty |

## Current contracts

- Router prefix control uses only summarized synchronous callbacks. Names such as `auth` are not protection.
  Unmounted routers stay unregistered. Dynamic/opaque prefixes stay unresolved. A `next('route')` inside
  `.use` is not used as a definite exit proof. Literal callback arrays are flattened with depth/length bounds;
  mutable array bindings are not trusted. CJS returned routers use the same heap identity across wrappers.
- Pages API supports selected manifest versions and `pages/api` / `src/pages/api` JS/JSX/TS/TSX default
  functions, arrows, async callbacks and closed static import/re-export links. UI pages and dynamic wrappers
  do not become entries. Dynamic route parameters are read from Pages `req.query`; `req.params` is not
  invented as a native Pages source. Registration convention is not deployed endpoint or authorization proof.
- Computed environment names support string concatenation, static templates, closed const references and
  bounded literal-string array join. Writes, array escape/mutation, cycles, shadowing, eval and budgets reject
  the static-name proof. The analyzer never reads environment values or executes target code. Reading a key
  without a response/log sink is not an exposure Finding.
- No Risk/Score/Coverage policy, legacy Rule ID or existing Review is rewritten. New observation kinds
  must not be represented as new confirmed vulnerabilities. The old HTML/owner evaluation obligations
  remain FN if the existing Finding contract is not met, even when richer review evidence exists.

## Framework references

- [Next.js Pages API default handler convention](https://nextjs.org/learn/pages-router/api-routes-creating-api-routes)
- [Express middleware order and control](https://expressjs.com/en/guide/using-middleware/)
- [Express 4 API](https://expressjs.com/en/4x/api/)
- [DRF object permissions and explicit object checks](https://www.django-rest-framework.org/api-guide/permissions/#object-level-permissions)

## Review evidence boundaries

HTML response observations reuse JS_SERVER_ENTRY_CONTEXT; they are not a new XSS Rule.
Known string construction passed to Express send (its default string response is HTML), explicit
HTML Content-Type on send/write/end, and explicit HTML headers on new Response preserve request
source and output locations. Plain-text/JSON responses and constants have no HTML input candidate.
Unknown values/sanitizers, render templates and conditional output context remain unresolved.
Output encoding is **not** certified: a function named escape/sanitize, or a partial replace chain,
is not proof of encoding for attributes, scripts, URLs or a template engine. These observations do
not add Risk/Score and do not satisfy the frozen HTTP_HTML_INPUT_FLOW Finding oracle.

Python v9 retains authentication separate from object policy. Known user-FK models changed using
request-derived identifiers without local owner/role evidence get an owner-policy review status.
An unknown helper/custom manager/partial path stays unresolved. Scoped queries/owner rejection
remain protection evidence, never a whole-policy safety assertion. No missing-guard IDOR Rule is
added. The frozen owner-policy oracle remains FN; external policy/RLS is not disproved by silence.

Live worker version validation requires matching candidate Backend (TS53/Python9). Saved older
Review/Snapshot JSON is still hydrated without rewriting or re-analysis. Pages evidence is not
coerced into the Express deterministic automatic-patch contract.

## PostgreSQL regression isolation

Only test endpoint allowlists were extended with exact `127.0.0.1:58450/v53_fixture`.
Ledger concurrency/restart/uncertain settlement and restricted metadata-role behavior retain their
original assertions. Production port 5432, arbitrary hosts and arbitrary database names remain
excluded. Runtime preview uses separate v53_trial; the five destructive conditional tests use only
v53_fixture. No operating schema, key or account is touched.
