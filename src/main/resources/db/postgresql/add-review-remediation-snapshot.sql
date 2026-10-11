-- Additive, repeatable migration. Historical reviews remain NULL; no AI backfill.
BEGIN;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS remediation_snapshot_json TEXT;
COMMIT;
