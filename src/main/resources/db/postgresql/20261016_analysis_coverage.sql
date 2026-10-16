-- Additive, repeatable. Past reviews remain NULL; never infer past coverage.
BEGIN;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS coverage_ledger_json TEXT;
COMMIT;
