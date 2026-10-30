# EPIC-01 Workspace storage contract

Status: isolated candidate, default OFF. No operating DB migration or key provisioning.

## Threat model and retained data

Sources can contain credentials. Database dumps, copied rows, tampered ciphertext,
row substitution, cross-owner access, concurrent writers and restart interruptions
are in scope. A compromised application process or stolen encryption key is outside
at-rest protection. TLS/database access control and protected backups remain required.

The existing Review contains snippets rather than a complete immutable source tree.
Consequently a bounded source archive is necessary for restart-safe Diff and ZIP;
only the existing selected archive is retained, never .git history or an extra repository.
Originals, edits, file identities/hashes, provenance and export approvals are encrypted.
Owner/project/Review, opaque ID, storage CAS version, expiry and key ID are metadata.
No pending provider job is restarted. Unapproved proposal sessions and browser unsaved
text are not durable; applied changes retain their exact generator and approval history.

## Storage and key controls

Explicit additive SQL: `src/main/resources/db/epic01/V001__encrypted_workspaces.sql`.
The application does not execute DDL. Set JPA `ddl-auto=validate` during deployment.
`securedeploy.editing.persistence.enabled=false` is the default. When enabled, both
schema and a separate 32-byte Base64 AES key are required at startup. Key must come
from protected server configuration, never DB/Git/frontend/export; do not reuse the
GitHub token or OpenAI key. `key-id` is a non-secret version identifier. AES-256-GCM,
96-bit fresh random nonce and 128-bit authentication tag protect each snapshot.
AAD binds format, owner/project/Review/ID, storage version, expiry and key ID.
Wrong key, tampering or unknown key ID fails closed; plaintext fallback is forbidden.
Initial implementation supports one active key ID; online rotation/keyring is not
implemented. Retain old key securely with protected backup until offline re-encryption
and verified restore can be performed. Losing the key means losing recoverability.

Archive+edits <=32MiB, file count<=5000, individual editable text<=256KiB,
encrypted JSON envelope<=48MiB, provenance<=1024, export approvals<=128.
Source text/serialized payload/key must not be logged. Do not enable JDBC parameter
logging. JVM-managed text cannot provide guaranteed memory erasure.

## Lifecycle and concurrency

Memory mode remains 30 minutes. Persistent expiry is fixed at creation, configurable
1800..2592000 seconds (default one day); saves never silently renew it. Expired rows
are inaccessible before bounded cleanup, explicit owner deletion removes only that
Workspace, project/Review deletion cascades only to its Workspace. Read authorization
is rechecked against the original Review/project. Unique owner enforces one active
Workspace; storage version CAS protects atomic payload/revision/provenance writes.
HTTP conflict preserves the browser draft. DB errors invalidate cache; no successful
save response is returned before durable commit. Independent writer CAS and stale
browser revision are separate checks. Cluster-wide project lifecycle reservations
and distributed AI quotas remain deployment blockers for multi-instance operation.

## Rollback and backup

Turn persistence OFF to return to memory behavior without modifying stored rows.
Older binaries ignore the additive table, but cannot resume its stored Workspaces.
Do not drop the table or restore a DB over production automatically. Export saved
work before rollback; never claim the old memory sessions were recovered. Back up
DB and keys separately with restricted access and validate an isolated restore with
matching keys and hash checks. Production rollout remains blocked until operator
key provisioning, backup restore and interruption handling are verified.
