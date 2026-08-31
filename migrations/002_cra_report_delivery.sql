BEGIN;
CREATE TABLE IF NOT EXISTS sentrycode_cra_report_delivery(
 report_id text PRIMARY KEY,
 tenant text NOT NULL,
 project text NOT NULL,
 finding_id text NOT NULL,
 run_id text NOT NULL,
 payload jsonb NOT NULL,
 status text NOT NULL CHECK(status IN ('pending','delivered','failed')),
 attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
 response_status integer NULL,
 last_attempt_at timestamptz NULL,
 next_attempt_at timestamptz NULL,
 last_error text NULL,
 delivered_at timestamptz NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sentrycode_cra_report_delivery_scope_idx
 ON sentrycode_cra_report_delivery(tenant, project, status, next_attempt_at, created_at);
INSERT INTO sentrycode_schema_migrations(version) VALUES (2) ON CONFLICT(version) DO NOTHING;
COMMIT;
