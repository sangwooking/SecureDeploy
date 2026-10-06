-- SecureDeploy development migration helper
-- Convert long body/evidence/snippet columns from varchar to TEXT for real GitHub repositories.
-- Hibernate ddl-auto=update may not change existing varchar columns to TEXT automatically.

ALTER TABLE review_snippets
    ALTER COLUMN content TYPE TEXT;

ALTER TABLE vulnerabilities
    ALTER COLUMN message TYPE TEXT,
    ALTER COLUMN recommendation TYPE TEXT,
    ALTER COLUMN evidence TYPE TEXT,
    ALTER COLUMN status_comment TYPE TEXT;
