# EPIC-01 isolated release and rollback checklist

No operating deployment, remote push, paid model request or operating DB mutation
is authorized in this release. Operating UX-03 remains in place. Candidate can be
user-tested only on its separately bound ports and synthetic PostgreSQL database.

## Candidate preparation

- Verify Git history/bundle, clean worktree, JAR/frontend/Worker hashes and source list.
- Preserve existing backend JAR/runtime settings and frontend assets, without copying
  secrets into source backup or browser bundle. Keep Provider TEMPLATE/live calls OFF.
- Inventory active scans, in-memory Workspaces and browser drafts; users must export
  required text/Patch/ZIP before any future operating restart. No automatic recovery
  of historical memory sessions is possible.
- Obtain explicit rollout permission separately. A new table migration is NOT run by
  startup. Backup operating PostgreSQL consistently and validate isolated restore,
  schemas and ownership before the explicit SQL. Set Hibernate ddl-auto=validate.
- Keep persistence OFF until a distinct protected key and key ID, backup recovery,
  capacity/retention policy and controlled restart drill are verified. API keys and
  GitHub token encryption keys must not be reused. No plaintext fallback.
- One process only: distributed project deletion leases and durable AI attempt/cost
  budgets are not implemented. Do not activate operating OpenAI based on Mock tests.

## Verified and blocked rollback paths

The additive table does not prevent the immediate baseline PATCH-03 (94dad33) JAR
from starting with ddl-auto=validate and reading test Review/Snapshot records.
It cannot resume encrypted Workspaces; the table remains intact. Export before
rollback, or restore the EPIC-01 reader with the matching key to access saved drafts.
Turning persistence OFF also leaves rows intact but does not display them as resumed.
Never overwrite production DB with its backup as an automatic rollback step.

A direct rollback to the currently operating UX-03 (7d24de8) is NOT fully compatible
with newer rescans. Isolated test: startup/login pass, Review/project list returns500
because its ComparisonContext/ReviewProgressSnapshot readers reject `provenance`
introduced before EPIC-01 by PATCH-02. No source/Review rows were rewritten to hide
this result. A tested forward-compatible rollback binary or independently verified
read-only compatibility adapter is required before operating rollout. Merely retaining
the old JAR is insufficient. Existing old operating data was never modified.

Frontend-only rollback and complete old-frontend/new-backend compatibility are not
fully browser-validated. Do not infer successful operating rollback from the isolated
API smoke tests. Native Safari remains manual verification; Chromium results are
separate. Key loss intentionally blocks recovery, and is not fixed by disabling AEAD.

## Measured stabilization

A 40-file/4800-occurrence synthetic input caused HTTP500 and Java heap exhaustion
with -Xmx512m while fetching a Review joined with all Findings: parent JSON snapshots
were repeated per row. Candidate loads parent and collection separately in one
transaction, keeping detached collection access and ownership checks. Identical ZIP
then returns all4800 Findings with PARTIAL coverage; repeated saved edits and a
120k-character Diff complete. No Rule/Risk/Score expectation was weakened. These
single local measurements are not production throughput or runtime security proof.

## Remaining release blockers

1. Forward-compatible operating rollback reader + full frontend rollback/Safari drill.
2. Operator key provisioning/rotation, production backup restore, retention/capacity.
3. Durable shared AI admission/usage ledger across all AI features before paid activation.
4. Larger source archives, interrupted process/DB outage and multi-instance soak tests.
5. Real authorized project inputs and independent oracles for computed env keys,
   complex authentication/authorization and cross-file modifications.
