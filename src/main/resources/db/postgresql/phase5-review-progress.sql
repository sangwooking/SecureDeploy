-- Additive, repeatable migration. Existing reviews remain unchanged (NULL snapshots).
BEGIN;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS comparison_context_json TEXT;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS comparison_snapshot_json TEXT;
COMMIT;
