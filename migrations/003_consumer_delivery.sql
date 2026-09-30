BEGIN;
CREATE TABLE IF NOT EXISTS sentrycode_consumer_delivery(
 consumer_id text NOT NULL,
 adapter_id text NOT NULL,
 message_id text NOT NULL,
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
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(consumer_id, message_id)
);
CREATE INDEX IF NOT EXISTS sentrycode_consumer_delivery_scope_idx
 ON sentrycode_consumer_delivery(consumer_id, tenant, project, status, next_attempt_at, created_at);

-- Preserve already queued/delivered CRA state when upgrading an existing installation.
INSERT INTO sentrycode_consumer_delivery(
 consumer_id, adapter_id, message_id, tenant, project, finding_id, run_id, payload,
 status, attempt_count, response_status, last_attempt_at, next_attempt_at, last_error,
 delivered_at, created_at, updated_at
)
SELECT
 'cra', 'cra', report_id, tenant, project, finding_id, run_id, payload,
 status, attempt_count, response_status, last_attempt_at, next_attempt_at, last_error,
 delivered_at, created_at, updated_at
FROM sentrycode_cra_report_delivery
WHERE true
ON CONFLICT(consumer_id, message_id) DO NOTHING;

INSERT INTO sentrycode_schema_migrations(version) VALUES (3) ON CONFLICT(version) DO NOTHING;
COMMIT;
