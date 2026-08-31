import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

test('standalone Docker acceptance harness is isolated and covers restart persistence', async()=>{
  const script=await readFile(resolve('scripts/acceptance/standalone-docker.mjs'),'utf8');
  assert.match(script,/randomBytes\(32\)/);
  assert.match(script,/sentrycode-acceptance-/);
  assert.match(script,/\/api\/v1\/ready/);
  assert.match(script,/restart', 'sentrycode'/);
  assert.match(script,/restart', 'sentrycode-postgres', 'sentrycode'/);
  assert.match(script,/down', '-v', '--remove-orphans'/);
  assert.match(script,/admin\/operations\/backup/);
  assert.match(script,/admin\/operations\/retention/);
  assert.match(script,/admin\/automotive/);
  assert.match(script,/admin\/audit/);
  assert.match(script,/SENTRYCODE_UI_ADMIN_TOKEN: adminToken/);
  assert.match(script,/SENTRYCODE_UI_TOKEN: viewerToken/);
  assert.match(script,/SENTRYCODE_OIDC_ISSUER: ''/);
  assert.match(script,/expectedSchemaVersion/);
  assert.match(script,/migrations/);
  assert.doesNotMatch(script,/schemaVersion\) !== 1/);
});

test('production Compose applies defense-in-depth runtime hardening', async()=>{
  const compose=await readFile(resolve('deploy/docker-compose.yml'),'utf8');
  assert.match(compose,/read_only: true/);
  assert.match(compose,/no-new-privileges:true/);
  assert.match(compose,/cap_drop:\s*\n\s*- ALL/);
  assert.match(compose,/init: true/);
  assert.match(compose,/stop_grace_period: 20s/);
});

test('PostgreSQL application pool fails promptly when the database is unreachable', async()=>{
  const source=await readFile(resolve('src/application/postgres.ts'),'utf8');
  assert.match(source,/connectionTimeoutMillis: 5_000/);
});
