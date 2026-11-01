-- Explicit opt-in only. No startup DDL and no changes to existing source envelopes.
-- No source text, paths, credentials, ciphertext, keys or environment values.
-- No cascading FK: expiry/deletion evidence must survive the workspace row.
CREATE TABLE editing_workspace_event_v1 (
 event_id varchar(36) PRIMARY KEY, workspace_id varchar(36) NOT NULL,
 owner_id bigint NOT NULL, project_id bigint NOT NULL, review_id bigint NOT NULL,
 event_type varchar(32) NOT NULL, occurred_at timestamp with time zone NOT NULL,
 expires_at timestamp with time zone NOT NULL, before_revision bigint, after_revision bigint,
 store_version bigint NOT NULL, request_id varchar(36), file_id varchar(36), current_hash varchar(64),
 outcome varchar(32) NOT NULL, execution_path varchar(32) NOT NULL
);
CREATE INDEX editing_workspace_event_owner ON editing_workspace_event_v1(owner_id,workspace_id,occurred_at);
CREATE INDEX editing_workspace_event_retention ON editing_workspace_event_v1(occurred_at);
CREATE UNIQUE INDEX editing_workspace_event_request ON editing_workspace_event_v1(owner_id,workspace_id,request_id) WHERE request_id IS NOT NULL;
-- Retention: 30 days, bounded scheduled deletion. Read through owner+Review authorization only.
-- Service role needs SELECT/INSERT/DELETE; no sequence or UPDATE permission required.
-- Rollback after disabling audit and stopping writers: DROP TABLE editing_workspace_event_v1;
