import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('PostgreSQL migration defines isolated application-state tables and constraints', async()=>{
  const sql=await readFile('migrations/001_application_state.sql','utf8');
  for(const table of ['sentrycode_repositories','sentrycode_scanner_settings','sentrycode_policy_assignments','sentrycode_waiver_workflow','sentrycode_integrations','sentrycode_principals','sentrycode_application_audit']) assert.match(sql,new RegExp(`CREATE TABLE IF NOT EXISTS ${table}`));
  assert.match(sql,/CHECK\(failure_mode IN \('fail','warn','ignore'\)\)/); assert.match(sql,/tenant text NOT NULL, project text NOT NULL/); assert.match(sql,/INSERT INTO sentrycode_schema_migrations\(version\) VALUES \(1\)/);
});
