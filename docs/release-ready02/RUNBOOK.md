# RELEASE-READY-02: matched release and functional fallback

Baseline: 5146ded08eb2a06d06a92d55e7e732b7c1e91df0. Operating deployment,
operating migration/key generation, paid calls and push are NOT performed.

## Recovery choice and limits

Choose strategy B, `release-compatible`, on the SAME validated candidate binary
and Worker v52. This is a functional fallback, not a return to the original UX-03
binary or Worker v51. The new Snapshot and encrypted-storage readers stay active
so newer records remain usable. Existing analysis, login, project/result/history
reads, manual file edits, Diff, approval, ZIP/Patch and rescan remain available.
Deterministic/AI proposal preparation/application, external AI and npm generation
are disabled. Non-legacy writes outside the explicit allowlist are unavailable;
this is not a claim that every administration/integration workflow is restored.

The original UX-03 JAR still rejects PATCH-02+ `provenance` during comparison
Snapshot hydration and gives project/review list 500. It remains unchanged and
must not be selected as a rollback binary against the newer database. Do not strip
or rewrite provenance to make that JAR work. Unknown comparison fields/versions
remain UNAVAILABLE/REVIEW_REQUIRED; the original JSON and risk evidence remain.

| mode | reads old/new results | new analysis | manual edits/export/rescan | automation | encrypted Workspace |
|---|---|---|---|---|---|
| candidate normal | yes, supported schemas | v52 | yes | supported scopes + approval | opt-in key/migration |
| release-compatible | yes | v52 | yes | disabled | same key/rows retained |
| release-recovery | yes | blocked | blocked | disabled | explicitly unavailable, ciphertext retained |
| original UX-03 | old only; new provenance 500 | v51 | not a safe new-DB rollback | legacy only | unsupported |

A startup guard rejects paid/automation flag overrides in compatible mode. If
persistent rows exist, disabling persistence is rejected; those rows cannot be
hidden behind a fresh memory Workspace. The original key is required. A fault
shared by the normal and compatible binary cannot be repaired by changing this
profile; use the read-only emergency mode or separately approved recovery. A DB
outage itself needs DB recovery, not just a profile change.

## Isolation and evidence

Dedicated cluster: 127.0.0.1:58220, data directory
/private/tmp/securedeploy-ready02-pg. It is independent of operating 5432 and the
older test cluster 58057. `ready02_fixture` contains synthetic accounts and allowed
captured input replay; `ready02_oper_copy` was restored from a consistent exported
operating snapshot, with V001/V002 applied ONLY to the copy. Every original table
row count/hash matched the exported source snapshot; source rows were unchanged
by migration and compatibility reads. Old account authorization was exercised
with a dedicated isolated signing key, not users' passwords or operating tokens.
This is not evidence of password login with operating credentials.

The preview at http://127.0.0.1:5222 uses a preview-only API base pointing to the
same origin and a fixed proxy to 58230. CSP connect-src self prevents an accidental
request to operating localhost:8080. Browser tests without request interception
verify this transport. Do not publish the preview bundle as the operating bundle.
The preview Backend uses candidate main classes and a test-only captured-source
adapter so synthetic GitHub identities can supply source without remote access.
The shipping JAR was separately tested without that adapter: persisted source,
real JAR restart, deterministic Patch, approval/download and v52 rescan. SCA was
disabled for that no-network JAR rehearsal; SCA regression and saved-result reads
were separately exercised. No claim of full real-app compatibility follows.

Normal fallback roundtrip includes original v51 data, new v52 result/provenance,
persistent Workspace, old-JAR 500 reproduction, compatible analysis/manual edits/
Diff/approved exports/rescan, and normal-mode return with the original Workspace
ciphertext and saved Review preserved. Writing new controlled results is distinct
from preserving original rows.

## Key custody and encrypted recovery

Do NOT generate an operating key in this task. Before enabling persistence, the
user must approve the actual service-account-owned key directory and independent
backup custody. Use 32 CSPRNG bytes encoded as base64, a non-secret versioned key
ID, a 0600 regular single-link file in a 0700 directory. Verify owner/permissions
before starting. Existing `key-file` and inline key are mutually exclusive.
Never echo key bytes, pass them on command lines, put them in Git/Frontend/export,
or include them in PostgreSQL dumps/source bundles. A protected OS/secret manager
can provision the file; Keychain integration is not implemented here.

Back up PostgreSQL consistently and retain a separately access-controlled key
backup. Restore into a separate database and prove correct-key decryption, full
file hashes, owner/project/Review binding, Revision, provenance and approvals.
An SQL restore without its key does NOT restore the Workspace. Missing key fails
startup; wrong key/GCM corruption rejects reads. Keep the old key until all data
and backup retention obligations are satisfied. There is no online rotation:
stop writes, back up DB/old key, validate old-key restore, decrypt/validate and
re-encrypt into a separate candidate with new ID/AAD, verify and approve the DB/key
switch. Do not simply replace the active key. Permanent loss of all original key
copies makes encrypted source unrecoverable; exported ZIP/Patch may be the only
remaining independent source. This is a deployment gate, not an automatic repair.

Memory retention remains 30 minutes; persistent default is 24 hours (policy still
open). Current limits: 5,000 archive entries, combined source/edits 32MiB,
individual text edit 256KiB, encrypted envelope 48MiB, provenance history 1,024
entries and export approval history 128. Preserve existing CAS/expiry/delete
behavior and test backup retention separately from live Workspace retention.
Unsent browser text and unapplied proposal sessions are not server-persisted.

## Failure handling verified in controlled inputs

| injected fault | observed result / operator action |
|---|---|
| normal Backend stop/start | encrypted draft/Revision/provenance/approval restored |
| kill while save waits on DB lock | client loses acknowledgment; complete new commit can still succeed; restart and inspect Revision/full hash before retry |
| isolated DB stop/start | AUTH_STORE_UNAVAILABLE 503; draft guidance and same-token recovery; no authentication downgrade/plaintext fallback |
| wrong/missing key | reject read/startup; restore original key; emergency reads cannot recover encrypted source without it |
| ciphertext tamper | GCM rejects; exact controlled backup restores; never overwrite operating DB automatically |
| two Backends save one revision | one 200, one 409; stale original hash/revision rejected |
| download cut mid-stream | transfer fails; source/Revision remain; approval may already be recorded; explicitly retry download and verify archive hash |
| Worker exits during analysis | UNAVAILABLE and Coverage PARTIAL; no whole-application safety claim; old saved result is not overwritten |
| restart after AI reservation | unique ID remains reserved, duplicate rejected; stale reservation becomes PROVIDER_UNKNOWN, cost reservation retained; no retry |
| unsupported comparison Snapshot | list reads survive, comparison UNAVAILABLE, risk/evidence/raw JSON preserved |

The save interruption trial observed COMMITTED_WITHOUT_ACK, not a partially
written file. PostgreSQL can finish an already waiting command after client
process death. Do not assume a failed HTTP save means the DB stayed at the old
Revision. Export local text before refresh; load and compare the latest Revision.
The minimal auth fix separates a temporary auth-store outage from invalid/expired
JWTs and does not expose driver details. Data-loss-free recovery is bounded by
available committed data, keys and independently verified backups.

## AI admission and engine scope

Reuse DurableAiLedger. Explicit consent and owned Review/Workspace are still
required before any real send; user/project/service limits, unique request IDs,
DB failures, restart, two real Backend instances and uncertain settlement were
retested with no provider transmission. The test-only meter endpoint is absent
from the JAR. User-visible ledger history/admin reconciliation UI is not added;
internal records are owner/project keyed and no cross-user read endpoint is
exposed. API usage-derived estimates are not invoices. Keep TEMPLATE, real key
unset and paid policy/ledger off during initial operating cutover. A future paid
activation needs separate explicit approval, current pricing/limits and retention/
reconciliation policy. Mock successes are not live model quality evidence.

Worker v52 and Backend live result validation are a matched pair. Persisted v51
records remain immutable/readable. Repeat the 33 D+ synthetic inputs unchanged:
v51 TP7/FP0/TN3/FN9/UNKNOWN14; v52 TP12/FP0/TN5/FN4/UNKNOWN12. Both have 31 PARTIAL.
This is a labeled synthetic regression, not real-project accuracy or full graph
coverage. Timings are one-run observations, not an operating performance promise.
Keep real inputs7 INPUT_UNAVAILABLE. Do not start v53 or add Rule IDs here.
Retain Pages API, HTML response, computed environment key, middleware Router mount
and Python owner-policy omission as the next independent evaluation targets.
72 Rules, Risk/Score/Coverage policy, RLS v4 and Deployment v2 remain unchanged.

## Future operating cutover — requires a new explicit approval

1. Re-inventory actual hashes/PIDs/config/PG connections, running analyses and
   every active Workspace; do not rely on this task's earlier PID list.
2. Ask users to stop edits/analyses, export unsaved text and approved ZIP/Patch,
   verify the latest stored Revision and unresolved saves/downloads.
3. Take an operating consistent PostgreSQL backup and previous binaries/config
   hashes; keep credential/key material outside source archives.
4. Restore into a separate approved DB; verify original rows, Snapshot/SCA/owner
   access and, when enabled, the existing key's Workspace recovery.
5. Confirm the approved key directory, custody and restore proof. Keep persistence
   OFF if no operating key exists; never turn it off to hide existing encrypted rows.
6. Review additive V001/V002; only then approve operating migration. Snapshot before/
   after old-table hashes, validate schema/constraints and preserve originals. No
   ddl-auto update/create or automatic script startup.
7. Stage the matched Backend JAR, external v52 worker/dependencies and rollback
   profile files with hashes; do not pair v51 live Worker with this Backend.
8. Switch Backend safely, then the compatible Frontend (operating API base), verify
   the actually served artifacts. Do not install preview API/CSP settings as prod.
9. Test existing login, projects, Review/Snapshot, Finding/SCA details, owner A/B and
   manual flows non-destructively; synthetic writes belong to the isolated service.
10. Enable persistent storage only with its approved key/restore proof. Verify saved
    Workspace, restart/resume, Diff, separate application/export approval and rescan.
11. On feature regression stop active jobs safely, preserve drafts/data and restart
    SAME validated binary with release-compatible. Retain DB/key, verify analysis
    and manual repair. Do not launch original UX-03 on newer provenance data.
12. If functional fallback cannot operate, use release-recovery, keep data intact,
    investigate DB/key/binary causes and restore only into a separate recovery DB.
13. Preserve every new Review/Snapshot/Workspace/approval; no provenance stripping,
    no automatic operating-DB overwrite and no implicit restoration of uncommitted
    browser edits.
14. Return to normal only after candidate/key/DB checks and resumed Revision proof.
15. Initial flags: Provider TEMPLATE, external AI OFF, ledger admission OFF, npm
    generation OFF; deterministic fixes require normal approval flow. In compatible
    mode automation OFF; in emergency mode writes OFF. Paid AI is a later approval.

## Safari user trial (not automatically passed)

Use the exact URL http://127.0.0.1:5222 and the controlled account reported in the
completion message, never an operating account. Open the pinned baseline Finding
URL from PREVIEW.json, choose the environment response issue, open repair and
resume the saved Workspace, select gateway.js, inspect evidence, create the free
deterministic proposal, review Diff/limitations and explicitly approve. Inspect
ZIP/Patch then rescan/history. New tabs/refresh should offer the same Workspace;
backend restart recovery was automated in Chromium, not verified in native Safari.
Capture the relevant tab/error and URL if a step fails; exclude passwords/tokens.
The test key expires no data by magic: 24h live retention still applies. Expired or
deleted work must be identified accurately, not claimed restored. No Safari/macOS
permission bypass is performed.
