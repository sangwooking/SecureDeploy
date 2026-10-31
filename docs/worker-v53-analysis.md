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
