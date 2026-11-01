-- Explicit isolated/release migration after V003; never automatic startup DDL.
-- Existing events retain UNKNOWN actor identity. Do not invent historic execution instances.
ALTER TABLE editing_workspace_event_v1 ADD COLUMN actor_type varchar(16) NOT NULL DEFAULT 'LEGACY_UNKNOWN';
ALTER TABLE editing_workspace_event_v1 ADD COLUMN instance_id varchar(36);
-- New app events distinguish OWNER requests from SYSTEM expiry and identify the vault instance.
-- No credentials, host paths or process environment are stored.
-- Rollback only after writers stopped and audit history exported: drop these two columns.
