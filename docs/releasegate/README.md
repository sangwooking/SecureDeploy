# RELEASE-GATE-01 candidate runbook

This is an isolated release preparation, not an operating deployment. Baseline is
34ac256de5520127b7767f39e0541680150db07b. New rules/model calls/pushes are absent.

## Snapshot compatibility and recovery

Original UX-03 uses a strict ObjectMapper in ComparisonContextConverter and
ReviewProgressSnapshotConverter. PATCH-02+ WorkspaceScanSnapshot.File adds
`provenance`; the enclosing records also add export approvals/provenanceHash.
Old records reject the additive fields during JPA hydration, so an entire
project/review list fails before response projection. Added tables alone do not
cause the failure. Original UX-03 JAR remains unchanged and is NOT an acceptable
rollback binary after these writes.

Use the **same release binary + bundled v52**, profile `release-recovery`, as the
verified recovery option. It is deliberately read-only, not a recreation of
UX-03's full editing behavior. Login/result reads work; every editing-workspace
route and non-read API except login returns 503 RECOVERY_READ_ONLY. Provider,
npm generation and persistence default off. UI capabilities and result/editor
banners expose the limitation. Never override the recovery profile flags or
point a v51 live analyzer at a v52-validating Backend.

| Backend | old v51 Review read | new v52/provenance Review read | new analysis/write | durable Workspace |
|---|---|---|---|---|
| original UX-03 | supported old data | list 500 reproduced | v51 only; do not use on new records | unsupported |
| candidate default | retained without reanalysis | supported known schema | v52, existing approval contracts | explicit migration/key/flag required |
| same candidate release-recovery | supported | supported | blocked, no data rewrite | API 503; stored ciphertext retained |

Unknown/malformed comparison metadata degrades to UNSUPPORTED_SNAPSHOT_REVIEW_REQUIRED
and UNAVAILABLE comparison, with no baseline/complete coverage assertion. Risk,
Score, Source/Evidence and raw stored JSON are unchanged. This does not make every
future Risk/analysis enum compatible, and is not permission to rewrite an unknown
Snapshot. Old data can be queried, not silently reinterpreted under v52.

## Workspace key and restoration

Retain existing AES-256-GCM envelope, random nonce and authenticated owner,
project/review, store version, expiry and key ID. Stored original hash, edits,
Revision, attribution and approved exports retain their existing format.
Memory expiry remains 30 minutes; persistent default remains 24 hours. Whether
24 hours is sufficient is a product-policy decision, not resolved by these tests.

Production key generation/change is outside this task. Persistence defaults OFF.
A provisioned secret can be supplied by the existing protected environment, or
`securedeploy.editing.persistence.key-file` (mutually exclusive with inline key).
Key file: absolute regular file, no symlink/hardlink, service-account ownership,
0600 in a 0700 directory, base64 encoding of 32 bytes, separate validated key ID.
An OS secret manager may materialize that file; Keychain integration is NOT
implemented or tested here. Never pass key bytes on a command line, to the
Frontend, Git, exports, prompt, DB dump or logs. DB dumps and key backups require
separate storage/access paths. Record only key ID and recovery custody, not key.

Isolated backup verification distinguished archive consistency from restoration:
pg_dump custom archive, restore into a separate DB, correct-key HTTP restoration,
exact file hash/Revision/ownership/provenance/export approvals, wrong/missing key,
GCM tampering, CAS across two running Backends, stale original hash, expiry and
deleted rows. Do not restore any test dump over an operating database.

Online key rotation is not implemented. Rotation needs a maintenance window:
stop writes, consistent DB backup and independently tested old-key restore;
retain old key, decrypt and validate every live row, re-encrypt into a separate
candidate DB with new key ID/AAD, verify hashes/Revision/ownership/exports and CAS,
then approve a matched DB/key switch. No in-place key replacement, no automatic
fallback to plaintext or a fresh Workspace on decryption failure. Destroy old
keys only after retention/recovery obligations expire.

## Unified real-provider admission

Every actual HTTP send in RealOpenAiProvider crosses DurableAiLedger. There is no
production/test-client bypass. Existing format tests supply an explicit mock
meter and MockRestServiceServer; they are not live metering/provider evidence.
The ledger flag defaults false; a configured API key alone cannot make the real
provider available. Startup with ledger enabled requires explicit V002 migration.

| feature/path | outbound policy |
|---|---|
| Workspace code Patch/structured plan | owned/revision-bound proposal, one-use consent, explicit context in executor, durable reservation |
| Workspace Semantic Review | owned unchanged Snapshot, one-use consent, exact prepared prompt context, durable reservation |
| SCA dependency advice | owned Review, saved evidence/plan identity, explicit metadata consent, durable reservation |
| automatic enhanced-scan Semantic Review | no explicit admission scope: real send denied |
| Korean Finding remediation/explanation generation | template remains available; legacy batch has no separate consent contract: real send denied |
| project summary/audit/comparison/priority/roadmap/PDF helpers | legacy no-consent transport denied; legacy AI PDF capability false |
| Template/Mock/deterministic AST edits | no real provider/billing admission; origin remains distinct |

The typed request scope stores identifiers and hashes only; JDBC never stores
prompt/source, secrets or credentials. Source-transmission consent and later
code-application approval remain separate. Real legacy explanation/report features
are **not implemented as consented paid features** merely because their transport
is now guarded. No supported UI is activated just by setting the ledger flag.

V002 adds only ai_usage_gate_v1 and ai_usage_request_v1, never auto-runs. Metadata:
user/project/feature, stable unique request ID, provider/model, consent-context
hash and exact instructions+data transmission hash, times, reserved input/output
and cost, API usage/cached tokens/model, estimated cost and state/cost status.
Stable audit IDs deliberately do not block existing project deletion; authority
is established by the service's ReviewAccess/workspace owner checks before a call.
No raw code or request/response body is stored. Old/mixed generator provenance is
not promoted to OPENAI.

States: PREPARED -> RESERVED -> SENDING -> COMPLETED or REVIEW_REQUIRED.
Quota failure before sending becomes PRE_SEND_FAILED. Network/provider/settlement
uncertainty after SENDING becomes PROVIDER_UNKNOWN; DB failure can leave SENDING
for explicit recovery. `reconcile()` marks only reservations/sends older than
five minutes as uncertain; it never contacts the provider. It is an operator
reconciliation method, not an implemented admin dashboard/background scheduler.
An immediate process restart must not steal an active peer's in-flight request.
Do not retry an uncertain request. Same request ID remains rejected across restarts;
a new ID requires a fresh service consent transition, not an automatic retry.
Exactly-once external delivery is NOT guaranteed.

A PostgreSQL transaction locks the singleton gate row before checking all rolling
24-hour budgets and one-hour counts. Defaults: user USD0.10/6 per hour, project
USD0.20/12 per hour, service USD1.00/60 per hour. The cost limits are daily;
the stated counts are hourly. Reserved worst-case cost is not refunded on unknown
usage or timeout. Admission accounts for the greater of reserved and API-estimated
cost. Completion means transport usage settlement, not safe code or a valid Patch.
Only the existing reviewed/fresh model-price policy is allowed. Real production
pricing/configuration must be rechecked before activation. Invoice cost is unknown;
only usage-derived estimates are recorded. Ledger retention/privacy cleanup and
administrator reconciliation UI need an operating policy; never purge unsettled
requests merely to reset a quota.

## v52 contract and known gaps

Backend live analysis validates v52. Historic v51 persisted results remain readable.
No Rule IDs, Risk/Score, Coverage policy, RLS v4, Deployment v2 or Python Worker
logic changed in this release-gate task. Remaining v53 evaluation targets:
1. Next Pages API: registered endpoint/request/response evidence and safe negatives.
2. HTML responses: actual input/output context and context-appropriate encoding.
3. Computed environment keys: bounded known values, uncertain aliases stay UNKNOWN.
4. Middleware-bearing Router mounts: registration and bounded callback link evidence;
   presence of middleware is not proof of authorization.
Python owner-only policy omission remains a separate false negative; authentication
is not object ownership. Remote Supabase RLS stays UNKNOWN. Keep D+ labeled cases,
normal controls, exact locations, Coverage/limits and no unauthorized real inputs.

## Approved future cutover sequence (NOT executed)

1. Obtain an explicit operating deployment approval. Reconfirm serving hashes/PIDs,
   running analyses, active Workspaces and unsaved tabs; export drafts/ZIP/Patch.
2. Take consistent operating PostgreSQL and binary/configuration backups; restore
   into a separate authorized database and compare row/file hashes. Never overwrite
   the operating DB as an automatic rollback.
3. Provision service credentials/recovery access and, separately, a persistent key
   only if approved. Validate permissions, missing/wrong-key behavior and key custody.
4. Review/apply additive V001/V002 only with operating migration approval. Validate
   existing users/Reviews/DB schema using candidate in isolation first. No DDL-auto
   update/create, no automatic schema init.
5. Switch matched Backend+Worker v52 then compatible Frontend. Paid provider stays
   TEMPLATE/OFF; persistence stays OFF unless key/restore policy is ready. Recheck
   existing login, A/B authority, list/details, manual edits, Diff/export and rescan.
6. If necessary enable SAME-VERSION release-recovery for read-only service. Stop
   jobs/writes safely first; retain all encrypted rows and original Snapshots.
   Do not run original UX-03 on a database containing new provenance.
7. Return to normal candidate with the same DB/key; confirm resumed IDs/Revision/
   approvals. Paid AI activation is a separate approval, not part of this cutover.

Safari is a user verification step, not automated evidence here: login with the
existing controlled test account, choose a problem, inspect exact file/line, open
Workspace, resume in another tab, inspect Diff and download, then rescan/history.
For recovery profile expect banners and no usable editor; no generation or paid
call. Do not enter operating credentials in the isolated test service.

## Reproduction assets and evidence

`scripts/releasegate/` contains the exact test-only Java/CJS harnesses. They are
pinned to `/private/tmp/securedeploy-release-gate01`, ports 5219/58160/58162-66,
role ai05_fixture, databases release_gate01/release_gate01_restore on 58057.
They are not migration/deployment scripts and must never be repointed to 5432,
5173 or 8080. Provider keys are removed before each test JVM. Test-only meter
endpoints are separate fixture classes, absent from the shipped JAR.

Build tests/classpath with `gradle --offline --no-daemon testClasses -I
scripts/releasegate/classpath.gradle releaseGateClasspath`. Copy harnesses to the
recorded runtime directory and compile Java fixture classes against that classpath.
The captured fixture feed/source root and the separately protected test-key file
must be available; do not synthesize missing inputs. Use the independent test DB
backup, never an operating dump. `gate-e2e.cjs` refuses a missing active source
contract by assertion; restore and browser cases assert exact hashes and status.

External evidence contains ROLLBACK_E2E.json, RESTORE_E2E.json,
MULTI_BACKEND_LEDGER.json, RECOVERY_UI.json, full JUnit results and UI PNGs.
Known harness corrections were missing FileInfo.currentHash (use originalHash),
scan status SUCCEEDED (not COMPLETED), local dependency symlink rejection (copy
pinned installed dependencies), and intercepting UI requests before they reach
the default operating API URL. Interrupted background lookups during an intentional
restart are aborted by the test adapter, not retried. The adapter is not evidence
of production CORS configuration. Real provider calls/cost remain zero.
