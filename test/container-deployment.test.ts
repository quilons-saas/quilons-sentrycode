import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

test('production container deployment separates SentryCode and PostgreSQL', async()=>{
  const dockerfile=await readFile(resolve('Dockerfile'),'utf8');
  const compose=await readFile(resolve('deploy/docker-compose.yml'),'utf8');
  assert.match(dockerfile,/USER sentrycode/);
  assert.match(dockerfile,/HEALTHCHECK/);
  assert.match(compose,/sentrycode-postgres:/);
  assert.match(compose,/\n  sentrycode:/);
  assert.match(compose,/sentrycode-postgres-data:/);
  assert.match(compose,/SENTRYCODE_DATABASE_URL/);
  assert.match(compose,/SENTRYCODE_UI_ADMIN_TOKEN/);
});
