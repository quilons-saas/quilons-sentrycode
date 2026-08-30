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

test('standalone container commands are resolved before Git repository discovery', async()=>{
  const cli=await readFile(resolve('src/cli/main.ts'),'utf8');
  const standalone=cli.indexOf("if (options.command === 'database-migrate' || options.command === 'database-status')");
  const web=cli.indexOf("if (options.command === 'ui' || options.command === 'serve')");
  const repository=cli.indexOf('const repository = await resolveRepository(options.path);');
  assert.ok(standalone >= 0 && web >= 0 && repository >= 0);
  assert.ok(standalone < repository, 'database lifecycle must not require a Git checkout');
  assert.ok(web < repository, 'standalone web server must not require a Git checkout');
});
