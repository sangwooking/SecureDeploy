# Secret exposure and response-object hardening #22

## Baseline and scope

Frozen baseline: `8f932ad987cdf9c17a6c34d3a85813b179fcfc37`, Worker v32.
Product changes: `3dddc814e9e60f2d29b6fbd55fcef86b737f09f4` and
`60c953cb3f4080a141dbf2b84fa3cf9d481e90c9`, Worker v33.
Development uses an isolated branch/worktree. The original local main remains
`15070416`; the v28 backend on port 8080, PID 99387, is not restarted.
No user PostgreSQL, Review, Workspace or stored Snapshot was changed.

This is bounded server-response analysis, not a complete client bundle analyzer,
an independent accuracy audit or proof of valid credentials/exploitation.

## Existing engine and selected failure

Existing `TS_SENSITIVE_DATA_EXPOSURE` uses the TypeScript AST, environment-source
metadata and supported HTTP return/log contracts. `TS_ERROR_DETAIL_EXPOSURE`
handles error details separately. `HARDCODED_FRONTEND_SECRET` and `ENV_SECRET`
are legacy literal/configuration rules, not proof of an HTTP or bundle path.
FalsePositiveAnalyzer, Evidence masking, Snapshot serialization and remediation
sanitization remain separate from static data-flow inference and Risk formulas.
HIGH confidence describes available static evidence, not attack success.

Retained Echoverse's dynamic environment selector already reaches a returned
response in v32. There was no new confirmed original-app miss here. Inspection
of object writes showed a narrower reproducible gap: adding a secret field to
an existing object lost the value at serialization; old spread/overwrite state
could also retain a secret no longer present in the returned object. This was
reproduced in authored controls and a separate full-app differential, without
altering the original application's files or labels.

## Implementation boundary

- `analyzers/typescript/object-data.mjs` reuses existing references for plain
  literal objects. Static property write/delete updates preserve aliases only
  for the bounded exposure-data case; generic SQL/request heap inference is not
  replaced. No getters, prototype-sensitive properties, arbitrary class model
  or external code execution is added.
- `analyzer.mjs` follows static own fields, object aliases, nested fields and
  shallow object spreads in evaluation order. Explicit later fields override
  earlier copied fields; shallow copies retain nested reference identity.
  A proven unconditional delete/constant overwrite differs from an unknown
  conditional/dynamic mutation. Unknown spreads retain residual uncertainty.
- Existing depth/AST/file/time/global work limits stay in force. Objects have
  at most 32 tracked properties. Response serialization additionally charges
  the existing work budget and stops after 4096 visits. Ancestor reference
  identity distinguishes cycles from shared sibling references. Cycles,
  serialization hooks and unsupported structure are unresolved, not safe.
- Supported existing request contexts include direct Next Route Handlers,
  confirmed Deno registrations and connected Express callbacks. Existing
  Response.json, NextResponse.json, returned new Response(JSON.stringify(...)),
  res.json/send and supported status chaining are reused, not identified by
  method spelling alone. Ordinary same-named objects are negative controls.
- JSON serialization/URL encoding do not sanitize secrets. Unmodeled encoding
  such as a complex base64 expression remains UNKNOWN, not a safe transform.
- New traces include `OBJECT_DATA_PROPERTY_WRITE` / `OBJECT_DATA_SPREAD` and
  preserve source/response file, line, function and existing limitations. Same
  old Finding identities remain on the 15 original inputs; no duplicate/new
  original-app candidates were introduced.

## Sensitivity and client boundary

Static source names and literal formats are evidence, not actual key validity.
Known Supabase anon/publishable/URL environment declarations remain public
declarations. Arbitrary PUBLIC_* is only a hint, not proof of harmless content.
Unknown environment selection or sensitivity remains unresolved.

The explicit sb_publishable format is excluded from the existing frontend
secret rule; sb_secret format is included in credential/FPR/masking handling.
Tests use fabricated strings, never live keys. Legacy anon JWTs under arbitrary
names/context are NOT fully classified by decoding claims in this change.
Public key use does not establish correct RLS or resource authorization.
These distinctions follow the [Supabase API key documentation](https://supabase.com/docs/guides/getting-started/api-keys).

Next public prefixes describe intended build-time exposure, not necessarily a
live credential. Static and dynamic access differ; see the
[Next environment contract](https://nextjs.org/docs/app/guides/environment-variables).
Vite's default public prefix and customizable envPrefix have distinct semantics;
see [Vite environment handling](https://vite.dev/guide/env-and-mode).
This milestone does not interpret arbitrary Vite config/envPrefix or complete
client import graphs. No target build, output bundle or deployment was examined.
Existing framework guards, client-boundary observations and literal rules are
retained; unsupported custom configuration is not claimed supported.

## Controlled differential: 90 cases

Authored development controls, three framework structures; not an independent
holdout, actual CVE count or product-wide precision/recall estimate. Same inputs
and labels, both frozen v32/current v33, each twice. Exact locations must match
the target response, not a log or unrelated warning.

| Static contract outcome | v32 | v33 |
| --- | ---: | ---: |
| Risk controls / 33: TP | 15 | 32 |
| Risk controls: FN including deferred | 18 | 1 |
| Normal controls / 30: reviewed TN | 16 | 30 |
| Normal controls: FP | 4 | 0 |
| Normal controls: deferred, not TN | 10 | 0 |
| Uncertain controls / 27: UNKNOWN | 22 | 27 |
| Uncertain controls: unexpected candidate | 5 | 0 |

The five uncertain candidates moved to UNKNOWN are NOT counted as confirmed FP
reductions. The remaining risk miss is Express request.url-based environment
selection, outside the current selector Source contract. Its original risk
label is retained. Dynamic keys/calls, conditional mutation, source sensitivity
and unverified boundaries are not promoted to confirmed vulnerability/safety.

## Real source and full-app Grade B differential

Echoverse (MIT), original SHA `549568d6f58609b0a650c10292ac0dd1f9fddf7e`:
`supabase/functions/get-secret/index.ts`, original SHA-256
`e9768ed9d66967cf04f75556689f0f207bc7f2a22a8411fcca9a30a7b6f65016`.
Original request-selected environment -> response candidate already exists on
both engines. Whether the selected live value is sensitive/deployed is unknown.
New original-app TP = **0**. Original-app FP/FN/TN cannot be inferred without an
independent oracle; absence of warnings is not a safe label.

All 83 retained source hashes were checked before producing isolated Grade B
copies. The original is unmodified. In one copy the existing environment value
is assigned to a response object property; another deletes that property before
returning the same object. These are authored controls, NOT upstream patches.
Both engines analyze the same complete retained input through actual backend
analysis services in isolated H2, twice, with no Review persistence.

Plan SHA-256:
`6bd47db46df3e33d5256d671a44aba6eb9b3e96f5404a77131553f81a9e96865`.

| Full-app control | v32 | v33 |
| --- | --- | --- |
| Property write, target structural candidate | 0 | 1 |
| Property removed, target structural candidate | 0 | 0 |
| Legacy rule count, both controls | 1 | 1 |
| Score / Risk / Coverage, both controls | 86 / REVIEW_REQUIRED / PARTIAL | unchanged |

This demonstrates a real-app-structure analysis improvement, not a new verified
upstream vulnerability. CopyMonster's unresolved SDK/branch paths and Chatbot's
loop/helper-selected environment context were not guessed into new Findings.

## Local HTTP and final user-facing results

The committed secret-lab is solely authored code using standard Web Response
handlers under a loopback node:http harness. A fabricated local canary is present
in the before response and absent after deletion; HTTP 200 and status='ok' are
preserved. Static candidates are 1 -> 0; metadata contains no canary value.
This is NOT an executed external app, real Next server/bundle, operating service
attack or API compatibility proof. Cleanup removes the temporary environment
entry and closes connections/server.

Four authored H2 controls, plan hash
`539e58d3cb8d2558f05c97e469a81f58273f33d597fa2434eff792a21d4cfbd6`:

- Object-write risk: structural candidate 0 -> 1; score 100 unchanged.
- Removed field: 0 -> 0; score 100 unchanged.
- Public publishable literal: legacy rule 1 -> 0, score 86 -> 100,
  BLOCKED -> REVIEW_REQUIRED. This is a justified rule-output change under the
  unchanged formula, NOT assurance of deployment readiness; SCA is UNKNOWN.
- Private literal: legacy rule 1 -> 1, score 86/BLOCKED unchanged.

Structural candidates stay REVIEW_REQUIRED/NOT_COMPARED, separate from legacy
score. No old Review was recalculated or structural disappearance called
RESOLVED. API/schema/UI, auto/AI repair allowlists and approval flows do not
expand. Masked source metadata, not secret values, enters Finding/Snapshot/AI
guide paths. Existing generic guidance is supplemented with response-field
removal, preserving normal fields, public-key distinction, separate rotation
when actual exposure occurred, and local canary/reinspection instructions.

## Regression, resource and safety evidence

- Original 15 inputs, identical plan/source/SHA, twice: all structural Finding
  identities, Client/table/policy metadata, legacy raw/filtered rules, SCA,
  scores and Risk retained. DVNA SQL/shell, Goof shell/login, Deno/Next/Express
  exposure and four AI-assisted app families remain observed regressions.
- #18 35, #19 53, #20 36 cases preserve state counts. #21 retains 25/26
  complete evidence contracts; the existing conservative partial case remains.
  These are not independently discovered security vulnerabilities.
- RLS v3 and column-update-v1 code unchanged. Intent #13 result SHA-256:
  `93fe972e3b9177c01317a815607679cf270e91405859e9ca8d21f979bacc3c2e`.
- Worker 693 pass. Backend 701 tests, zero failures/errors, nine existing skips.
  Python analyzer 117 pass; evaluation tools 241 pass. Frontend 165 pass and
  production build passes. No UI edits; generated metadata is excluded.
- Original 15 current analysis timings: 238-836 ms; largest sampled parent JVM
  used heap 176113336 bytes, NOT peak Worker RSS. Full Echo control current
  times: write 869/637 ms, removed 541/538 ms; baseline write 783/562 ms,
  removed 617/590 ms. Small local measurements do not prove speed improvement.
- Single authored property-write Worker sample, twice: v32 steps 82 and RSS
  130301952/130416640 bytes; v33 steps 85 and RSS 127959040/127188992 bytes.
  Both about 0.16 seconds. Existing 192 MiB old-space is not a hard RSS cap.
  Shared-reference fanout/cycle/property-cap tests verify incomplete analysis
  instead of unbounded traversal or false safety. No resource limits were raised.
- Existing ZIP/mocked public/private GitHub, ownership/revision, Workspace,
  repair/rejection/stale, rescan/history/Before-After tests pass in full suites.
  No new live GitHub App or browser E2E, external independent review, target
  bundle build, production secret test or PostgreSQL oracle rerun is claimed.
- Gradle deprecation and pre-existing ANTLR version warnings occur on both
  engines' successful builds. Dependency cleanup is outside this milestone.
- No external downloads, target installs/builds/execution, credential checks,
  paid AI, key rotation, deployment or backend restart. Three private untracked
  documents remain excluded; source copies/raw receipts stay outside Git.

## Next boundary and #23 recommendation

Retain the known Express selector miss, complex hooks/prototypes/dynamic heap,
deep serialization, legacy anonymous JWT classification and actual bundle
reachability as explicit gaps. Do not advertise complete sensitive-data coverage.

For #23, prioritize independent, reviewed two-user RLS/write controls with fixed
schema/owner semantics, explicit role and column privileges, USING/WITH CHECK,
and missing-migration provenance. Keep request evidence, policy declarations,
owner intent and runtime authorization as separate facts. Do not infer ownership
from column names or integrate Intent #13 without separate approval. The #22
lab can support a graduation demonstration of secret-field removal, but does not
replace that authorization oracle or certify an entire application as safe.
