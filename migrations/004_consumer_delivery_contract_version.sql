BEGIN;

ALTER TABLE sentrycode_consumer_delivery
  ADD COLUMN IF NOT EXISTS adapter_contract_version text;

UPDATE sentrycode_consumer_delivery
SET adapter_contract_version = CASE
  WHEN adapter_id = 'cra' THEN '1.0.0'
  WHEN adapter_id = 'cyber' THEN 'cyber.security-evidence.v1'
  ELSE 'legacy-unversioned'
END
WHERE adapter_contract_version IS NULL OR btrim(adapter_contract_version) = '';

ALTER TABLE sentrycode_consumer_delivery
  ALTER COLUMN adapter_contract_version SET NOT NULL;

INSERT INTO sentrycode_schema_migrations(version) VALUES (4)
ON CONFLICT(version) DO NOTHING;

COMMIT;
