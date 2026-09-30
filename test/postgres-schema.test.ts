import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('PostgreSQL migration defines isolated application-state tables and constraints', async()=>{
  const sql=await readFile('migrations/001_application_state.sql','utf8');
  for(const table of ['sentrycode_repositories','sentrycode_scanner_settings','sentrycode_policy_assignments','sentrycode_waiver_workflow','sentrycode_integrations','sentrycode_principals','sentrycode_application_audit']) assert.match(sql,new RegExp(`CREATE TABLE IF NOT EXISTS ${table}`));
  assert.match(sql,/CHECK\(failure_mode IN \('fail','warn','ignore'\)\)/); assert.match(sql,/tenant text NOT NULL, project text NOT NULL/); assert.match(sql,/INSERT INTO sentrycode_schema_migrations\(version\) VALUES \(1\)/);
});


test('PostgreSQL migration defines durable CRA report delivery state without duplicating evidence', async()=>{
  const sql=await readFile('migrations/002_cra_report_delivery.sql','utf8');
  assert.match(sql,/CREATE TABLE IF NOT EXISTS sentrycode_cra_report_delivery/);
  assert.match(sql,/report_id text PRIMARY KEY/);
  assert.match(sql,/payload jsonb NOT NULL/);
  assert.match(sql,/CHECK\(status IN \('pending','delivered','failed'\)\)/);
  assert.match(sql,/attempt_count integer NOT NULL DEFAULT 0/);
  assert.match(sql,/INSERT INTO sentrycode_schema_migrations\(version\) VALUES \(2\)/);
  assert.doesNotMatch(sql,/evidence jsonb/i);
});


test('PostgreSQL migration defines generic durable multi-consumer delivery state and migrates CRA queue', async()=>{
  const sql=await readFile('migrations/003_consumer_delivery.sql','utf8');
  assert.match(sql,/CREATE TABLE IF NOT EXISTS sentrycode_consumer_delivery/);
  assert.match(sql,/consumer_id text NOT NULL/);
  assert.match(sql,/adapter_id text NOT NULL/);
  assert.match(sql,/PRIMARY KEY\(consumer_id, message_id\)/);
  assert.match(sql,/FROM sentrycode_cra_report_delivery/);
  assert.match(sql,/ON CONFLICT\(consumer_id, message_id\) DO NOTHING/);
  assert.match(sql,/INSERT INTO sentrycode_schema_migrations\(version\) VALUES \(3\)/);
  assert.doesNotMatch(sql,/evidence jsonb/i);
});


test('PostgreSQL migration binds each generic delivery to an adapter contract version', async()=>{
  const sql=await readFile('migrations/004_consumer_delivery_contract_version.sql','utf8');
  assert.match(sql,/ADD COLUMN IF NOT EXISTS adapter_contract_version text/);
  assert.match(sql,/WHEN adapter_id = 'cra' THEN '1\.0\.0'/);
  assert.match(sql,/WHEN adapter_id = 'cyber' THEN 'cyber\.security-evidence\.v1'/);
  assert.match(sql,/ALTER COLUMN adapter_contract_version SET NOT NULL/);
  assert.match(sql,/INSERT INTO sentrycode_schema_migrations\(version\) VALUES \(4\)/);
});
