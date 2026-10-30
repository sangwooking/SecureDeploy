-- Explicit opt-in migration. NOT automatically run by application startup.
-- Run only after backup/restore validation. No existing table/column is altered.
CREATE TABLE editing_workspace_v1 (
    id varchar(36) PRIMARY KEY,
    owner_id bigint NOT NULL REFERENCES users(id),
    project_id bigint NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    review_id bigint NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    store_version bigint NOT NULL CHECK (store_version > 0),
    expires_at timestamp with time zone NOT NULL,
    key_id varchar(64) NOT NULL,
    payload bytea NOT NULL,
    UNIQUE(owner_id),
    CHECK (octet_length(payload) <= 50331648)
);
CREATE INDEX editing_workspace_v1_expiry ON editing_workspace_v1(expires_at);
