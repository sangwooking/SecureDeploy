-- SecureDeploy development migration helper
-- Hibernate 6 may create enum check constraints for @Enumerated(EnumType.STRING) columns.
-- After frontend/security enum expansion, existing PostgreSQL constraints can reject new enum values.
-- Run this once on existing development databases. New schemas use explicit varchar enum mappings.

ALTER TABLE review_snippets DROP CONSTRAINT IF EXISTS review_snippets_type_check;
ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_category_check;
ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_severity_check;
ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_status_check;
ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_source_type_check;
ALTER TABLE reviews DROP CONSTRAINT IF EXISTS reviews_source_type_check;
