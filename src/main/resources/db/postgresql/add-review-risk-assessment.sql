-- Additive, nullable snapshot: historical reviews are intentionally not reassessed.
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS risk_assessment_json TEXT;
