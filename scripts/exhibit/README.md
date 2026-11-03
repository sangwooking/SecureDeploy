The exhibition process uses a separate PostgreSQL database, user accounts and
loopback ports. Do not point it at the production DB or the existing demo.
Provision the schema with the existing isolated release SQL, including the
ai_usage_gate_v1 row. Never truncate or replace its ledger during an exhibition.

The Backend's optional securedeploy.ai.exhibit.control-file setting requires
jdbc:postgresql://127.0.0.1:58850/securedeploy_exhibit_step2 and an enabled ledger.
Set the two scopes as userId:projectId:manifestSha256:fileSha256:ruleId. Derive
the manifest from verified fixture files sorted by path, joining records with
LF and fields path, boolean directory, original SHA-256 with NUL. Configure
only the approved fixtures, never derive an allowlist from visitor uploads.

Place the control path in an operator-only directory (0700). Every startup
writes a new adjacent .challenge value and starts closed. After separate live
approval, an operator may atomically install the current challenge as the
control file. Remove that file to stop new calls. Previously admitted or
transmitted calls may still complete. Restart requires a new enable operation;
the dedicated ledger retains its reservations and one-per-case policy.
A reservation consumed before a transport failure is never refunded. Keep the
same DB and do not restore an older ledger snapshot as a restart procedure.

Use only a server environment key and the pinned gpt-5.4-mini-2026-03-17 model.
The live provider requires separate approval. To demo without live AI, keep
the control file absent and show the deterministic Express fix through Diff,
approval, export and rescan. Identify historical live results as historical.
