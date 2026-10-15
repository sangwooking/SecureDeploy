-- Additive and repeatable. Legacy and ZIP reviews keep NULL metadata; do not invent commits.
BEGIN;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS source_metadata_json TEXT;
COMMIT;
