-- Run only against a disposable schema supplied by the caller. Never uses public tables.
\set ON_ERROR_STOP on
CREATE SCHEMA :"schema";
SET search_path TO :"schema";
CREATE TABLE users (id BIGINT PRIMARY KEY);
CREATE TABLE projects (id BIGINT PRIMARY KEY, user_id BIGINT, name TEXT);
CREATE TABLE reviews (id BIGINT PRIMARY KEY, project_id BIGINT, source_metadata_json TEXT);
CREATE TABLE vulnerabilities (id BIGINT PRIMARY KEY, review_id BIGINT, evidence TEXT);
INSERT INTO users VALUES (1);
INSERT INTO projects VALUES (1, 1, 'offline-migration-fixture');
INSERT INTO reviews VALUES (1, 1, '{"commitSha":"legacy-fixture"}');
INSERT INTO vulnerabilities VALUES (1, 1, '<redacted>');
\ir ../../../main/resources/db/postgresql/20261016_github_app_read_only.sql
\ir ../../../main/resources/db/postgresql/20261016_github_app_read_only.sql
DO $$
BEGIN
    IF (SELECT name FROM projects WHERE id = 1) <> 'offline-migration-fixture'
        OR (SELECT source_metadata_json FROM reviews WHERE id = 1) <> '{"commitSha":"legacy-fixture"}'
        OR (SELECT evidence FROM vulnerabilities WHERE id = 1) <> '<redacted>'
        OR (SELECT COUNT(*) FROM projects) <> 1 OR (SELECT COUNT(*) FROM reviews) <> 1
        OR (SELECT COUNT(*) FROM vulnerabilities) <> 1 THEN
        RAISE EXCEPTION 'Legacy fixture data changed';
    END IF;
    IF (SELECT COUNT(*) FROM github_connections) <> 0 THEN RAISE EXCEPTION 'Unexpected connection'; END IF;
END $$;
INSERT INTO github_connections VALUES (1, 101, 'fixture', 'encrypted-fixture-not-a-token', now(), now());
UPDATE projects SET github_repository_id=20, github_installation_id=10, private_repository=true WHERE id=1;
SELECT 'migration applied twice; legacy fixture rows preserved' AS result;
DROP SCHEMA :"schema" CASCADE;
