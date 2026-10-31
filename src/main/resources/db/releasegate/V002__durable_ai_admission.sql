-- Explicit isolated/approved migration only. Application startup never runs this file.
CREATE TABLE ai_usage_gate_v1 (id integer PRIMARY KEY CHECK(id=1));
INSERT INTO ai_usage_gate_v1 VALUES(1);
CREATE TABLE ai_usage_request_v1 (
 request_id varchar(128) PRIMARY KEY,
 -- Stable audit identifiers survive explicit project deletion; authorization is checked before admission.
 user_id bigint NOT NULL CHECK(user_id>0), project_id bigint NOT NULL CHECK(project_id>0),
 feature varchar(64) NOT NULL, provider varchar(16) NOT NULL CHECK(provider='OPENAI'), model varchar(128) NOT NULL,
 consent_hash varchar(64) NOT NULL, transmission_hash varchar(64) NOT NULL,
 state varchar(32) NOT NULL CHECK(state IN ('PREPARED','RESERVED','SENDING','COMPLETED','PRE_SEND_FAILED','PROVIDER_UNKNOWN','REVIEW_REQUIRED')),
 created_at timestamp NOT NULL DEFAULT current_timestamp, updated_at timestamp NOT NULL DEFAULT current_timestamp,
 reserved_input integer NOT NULL CHECK(reserved_input>0), reserved_output integer NOT NULL CHECK(reserved_output>0),
 reserved_usd numeric(18,9) NOT NULL CHECK(reserved_usd>=0),
 actual_input integer, actual_output integer, cached_input integer, usage_model varchar(128), estimated_usd numeric(18,9),
 cost_status varchar(40) NOT NULL DEFAULT 'RESERVED_ESTIMATE_NOT_INVOICE'
);
CREATE INDEX ai_usage_window_v1 ON ai_usage_request_v1(created_at,user_id,project_id);
