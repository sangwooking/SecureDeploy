-- Additive and repeatable. No existing reviews, snapshots, or ownership are rewritten.
BEGIN;
CREATE TABLE IF NOT EXISTS github_connections (
    user_id BIGINT PRIMARY KEY REFERENCES users(id),
    github_user_id BIGINT NOT NULL,
    github_login VARCHAR(100) NOT NULL,
    encrypted_access_token TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    connected_at TIMESTAMP WITH TIME ZONE NOT NULL
);
ALTER TABLE projects ADD COLUMN IF NOT EXISTS github_repository_id BIGINT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS github_installation_id BIGINT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS private_repository BOOLEAN;
CREATE UNIQUE INDEX IF NOT EXISTS projects_user_github_repository_uq
    ON projects(user_id, github_repository_id) WHERE github_repository_id IS NOT NULL;
COMMIT;
