-- Additive and repeatable. Historical reviews stay NULL; never trigger an AI backfill.
BEGIN;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS semantic_snapshot_json TEXT;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS scan_mode varchar(20);
COMMIT;
