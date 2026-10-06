-- SecureDeploy development migration helper
-- Add false positive reduction metadata to existing vulnerability rows.

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS false_positive_risk varchar(20),
    ADD COLUMN IF NOT EXISTS confidence varchar(20),
    ADD COLUMN IF NOT EXISTS analysis_note TEXT;

UPDATE vulnerabilities
SET false_positive_risk = COALESCE(false_positive_risk, 'LOW'),
    confidence = COALESCE(confidence, 'HIGH');
