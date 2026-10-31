# V53 release gate — comparison and recovery contract

Start: 9e4dee41add743c0f06276a178f788c2a9050f17. Operating 5173/8080, TS52,
PostgreSQL and TEMPLATE are not replaced by this task. No paid provider request or push.

## Audit and invariants

The existing progress comparison already excludes structural server Finding IDs from Risk
resolved/new counts. Catalog matching uses Rule/path/evidence, with an analyzer class fingerprint.
Missing facts were exact analyzed-input hashes, external worker identities/configuration and a
separate cross-version structural observation mapping. No stored ID or Snapshot is rewritten.

ComparisonContext schema1 gets optional `evidence`: SHA256_BYTES_V1, per-file byte digests,
source/sink/entry line digests, completeness and recorded backend/worker/artifact/parser/config IDs.
Bytes are hashed only if decoded lines match the analyzed ProjectFile lines. Failed reads, duplicate
paths, source races or budgets do not establish complete input identity. No code/key bytes persist
in this metadata. Input scope is collected analysis files, not every file or executed endpoint.

Progress schema1 gets optional `basis`. It reports source and engine state, bounded file digest
pairs, original before/after IDs and separate TS/Python validated-flow observations. Matching
requires unique Rule + Source/Sink file/position/function/kind anchors and unchanged file/line
proof. Version and Finding ID alone are not equivalence. Ambiguous/missing/truncated evidence
stays unavailable. Structural flow records stay outside legacy Risk/Score and resolved/new totals.

- Same code, changed engine: link verified existing flow; added evidence is not code-introduced risk.
- Edited code, recorded engine same: preserve entry/parse/budget checks; disappearance is limited
  NOT_REOBSERVED_AFTER_EDIT, not confirmed remediation or runtime compatibility.
- Code and engine changed: unobserved flow stays unavailable; no automatic three-way attribution.
- Legacy catalog negative evidence additionally needs changed file bytes, matching engines and
  complete comparable scope. SCA needs a changed version matching the old known fixed version;
  external notice disappearance alone is insufficient. Full advisory dataset identity is not stored.
- Missing old comparison evidence: preserve archive, hide confirmed remediation/new cards and
  suppress current dashboard comparison summaries. GET Review still preserves the original record.

Flow records are bounded at 200 / 256KB; digest display is bounded at 200 with explicit limitations.
HTML observations are not XSS Findings. OWNER_POLICY_REVIEW_REQUIRED is not confirmed IDOR.
Same-version repeatability does not promise version-independent original Finding IDs.

## API and storage compatibility

No new SQL table/column/migration. Optional JSON fields retain schema1; old records deserialize
with missing evidence. Unknown evidence formats fail closed without changing stored JSON.
Old strict readers may treat new comparison JSON as unavailable. Do not use an old UX03 JAR as
rollback. Deploy the new Frontend to display basis, file hashes and nonzero-only categories.
The exact HOTFIX Frontend is tested through an API transport bridge to the isolated candidate;
no production API request or DTO/DOM replacement is used. That UI cannot render new basis fields.

## Rehearsal and future deployment

Dedicated PG58550: operating read-only dump restored to v53_gate_copy; a synthetic fixture copy
supplies v53_gate_trial; five destructive conditional tests use only v53_gate_fixture. Original
service/key/data are untouched. Protected key restore copies are outside source bundles. A valid
copied Workspace is decrypted and ownership/file hashes checked, without changing the original.

Actual JAR/React tests cover saved v52 -> v53 same-source, same-v53 edited ZIPs, and original-v52
Workspace edit/rescan. Existing hongik_bot89 remains a stored v51 result; copied operating control
reviews and synthetic120 exercise stored v52. No existing Review is automatically reanalyzed.

release-compatible uses the SAME matched candidate and TS53/Python9: disable automation/paid
providers, retain encrypted persistence/key and manual editing/analysis/export. release-recovery
uses the same candidate and denies writes/Workspace while allowing login/result reads. Missing-key
compatible startup must fail, never fall back to memory. Modes are exercised on isolated copies.

Future operating deployment requires explicit approval, fresh consistent operating dump and
restore/decryption, original key recovery/permissions, saved work/job check, matched FE/BE/TS53/
Python9 hashes and unchanged ownership/Revision controls. Use compatible/recovery for failure;
never overwrite the operating DB from backup automatically. Safari validation remains separate
from Chromium E2E; no operating tab is force-refreshed.
