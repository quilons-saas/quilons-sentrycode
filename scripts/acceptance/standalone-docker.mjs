import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const root = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const composeFile = resolve(root, 'deploy', 'docker-compose.yml');
const keep = process.argv.includes('--keep');
const project = `sentrycode-acceptance-${Date.now().toString(36)}`.toLowerCase();
const temp = await mkdtemp(join(tmpdir(), 'sentrycode-acceptance-'));
const envFile = join(temp, '.env');
const viewerToken = randomBytes(32).toString('hex');
const adminToken = randomBytes(32).toString('hex');
const postgresPassword = randomBytes(32).toString('base64url');
let composeUp = false;
let baseUrl = '';

async function expectedSchemaVersion() {
  const migrationsDir = resolve(root, 'migrations');
  const files = await readdir(migrationsDir);
  return files.filter((name) => /^\d+_.*\.sql$/.test(name)).length;
}

function pass(message) { process.stdout.write(`PASS ${message}\n`); }
function info(message) { process.stdout.write(`INFO ${message}\n`); }
function fail(message) { throw new Error(message); }

async function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') { server.close(); reject(new Error('could not allocate acceptance port')); return; }
      const port = address.port;
      server.close((error) => error ? reject(error) : resolvePort(port));
    });
  });
}

async function docker(args, options = {}) {
  return execFileAsync('docker', args, { cwd: root, windowsHide: true, maxBuffer: 20 * 1024 * 1024, ...options });
}

function composeArgs(extra) {
  return ['compose', '-p', project, '--env-file', envFile, '-f', composeFile, ...extra];
}

function acceptanceEnvironment() {
  return {
    ...process.env,
    SENTRYCODE_POSTGRES_PASSWORD: postgresPassword,
    SENTRYCODE_UI_TOKEN: viewerToken,
    SENTRYCODE_UI_ADMIN_TOKEN: adminToken,
    SENTRYCODE_TENANT: 'acceptance',
    SENTRYCODE_PROJECT: 'standalone',
    SENTRYCODE_BIND_ADDRESS: '127.0.0.1',
    SENTRYCODE_PORT: baseUrl ? new URL(baseUrl).port : process.env.SENTRYCODE_PORT,
    SENTRYCODE_IMAGE_TAG: 'acceptance',
    // Keep enterprise auth disabled for the local-token acceptance path even if
    // the parent shell has OIDC configuration from another SentryCode session.
    SENTRYCODE_OIDC_ISSUER: '',
    SENTRYCODE_OIDC_AUDIENCE: '',
    SENTRYCODE_OIDC_JWKS_URI: '',
  };
}

async function compose(extra, options = {}) {
  return docker(composeArgs(extra), { ...options, env: { ...acceptanceEnvironment(), ...(options.env ?? {}) } });
}

async function request(path, { token, method = 'GET', body, expected = 200 } = {}) {
  const headers = { accept: 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const response = await fetch(`${baseUrl}${path}`, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  let payload = null;
  const text = await response.text();
  if (text) { try { payload = JSON.parse(text); } catch { payload = text; } }
  if (response.status !== expected) fail(`${method} ${path}: expected ${expected}, received ${response.status}: ${typeof payload === 'string' ? payload : JSON.stringify(payload)}`);
  return payload;
}

async function waitReady(timeoutMs = 120_000) {
  const deadline = Date.now() + timeoutMs;
  let last = '';
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/api/v1/ready`);
      last = await response.text();
      if (response.status === 200) return JSON.parse(last);
    } catch (error) { last = error instanceof Error ? error.message : String(error); }
    await new Promise((r) => setTimeout(r, 1_000));
  }
  fail(`readiness timeout: ${last}`);
}

async function logs() {
  try {
    const result = await compose(['logs', '--no-color', '--tail', '250']);
    process.stderr.write(`\n--- acceptance container logs ---\n${result.stdout}${result.stderr}\n`);
  } catch {}
}

async function main() {
  await docker(['version']);
  await docker(['compose', 'version']);
  pass('Docker Engine and Docker Compose are available');

  const port = await freePort();
  baseUrl = `http://127.0.0.1:${port}`;
  await writeFile(envFile, [
    `SENTRYCODE_POSTGRES_PASSWORD=${postgresPassword}`,
    `SENTRYCODE_UI_TOKEN=${viewerToken}`,
    `SENTRYCODE_UI_ADMIN_TOKEN=${adminToken}`,
    'SENTRYCODE_TENANT=acceptance',
    'SENTRYCODE_PROJECT=standalone',
    'SENTRYCODE_BIND_ADDRESS=127.0.0.1',
    `SENTRYCODE_PORT=${port}`,
    'SENTRYCODE_IMAGE_TAG=acceptance',
    '',
  ].join('\n'), { mode: 0o600 });

  info(`isolated Compose project: ${project}`);
  info(`acceptance endpoint: ${baseUrl}`);
  await compose(['up', '-d', '--build']);
  composeUp = true;
  const expectedSchema = await expectedSchemaVersion();
  const ready = await waitReady();
  if (!ready.ready || !ready.databaseReady || Number(ready.schemaVersion) !== expectedSchema) fail(`unexpected readiness payload: ${JSON.stringify(ready)}; expected schema ${expectedSchema}`);
  pass(`clean Docker deployment is ready with PostgreSQL schema ${expectedSchema}`);

  await request('/api/v1/health', { expected: 200 });
  await request('/api/v1/status', { expected: 401 });
  await request('/api/v1/status', { token: viewerToken, expected: 200 });
  pass('public liveness and protected API boundary are enforced');

  const viewerSession = await request('/api/v1/admin/session', { token: viewerToken, method: 'POST', expected: 200 });
  if (viewerSession.role !== 'viewer') fail(`viewer token resolved to ${viewerSession.role}`);
  await request('/api/v1/admin/principals', { token: viewerToken, method: 'PUT', body: { subject: 'forbidden', displayName: 'Forbidden', role: 'administrator' }, expected: 403 });
  const adminSession = await request('/api/v1/admin/session', { token: adminToken, method: 'POST', expected: 200 });
  if (adminSession.role !== 'administrator') fail(`admin token resolved to ${adminSession.role}`);
  pass('viewer/admin RBAC is enforced by the server');

  const state = await request('/api/v1/admin/state', { expected: 200 });
  if (!state.database?.connected || Number(state.database?.schemaVersion) !== expectedSchema) fail(`application state unavailable: ${JSON.stringify(state)}; expected schema ${expectedSchema}`);
  const repository = await request('/api/v1/admin/repositories', {
    token: adminToken,
    method: 'POST',
    expected: 201,
    body: { name: 'Acceptance Repository', rootPath: '/app', defaultBranch: 'main', enabled: true },
  });
  if (!repository.id) fail('repository registration returned no ID');
  pass('PostgreSQL-backed administrative write succeeded');

  const integration = await request('/api/v1/admin/integrations', {
    token: adminToken,
    method: 'PUT',
    expected: 200,
    body: { kind: 'acceptance', name: 'Acceptance Integration', enabled: true, configuration: { endpoint: 'https://example.invalid/acceptance' }, secretReference: 'acceptance-secret-ref', status: 'configured' },
  });
  if (!integration.id) fail('integration upsert returned no ID');
  pass('integration metadata write succeeded without storing a credential value');

  await compose(['restart', 'sentrycode']);
  await waitReady();
  let repositories = await request('/api/v1/admin/repositories', { token: adminToken, expected: 200 });
  if (!Array.isArray(repositories) || !repositories.some((item) => item.id === repository.id)) fail('repository state did not survive SentryCode restart');
  pass('application state survives SentryCode container restart');

  await compose(['restart', 'sentrycode-postgres', 'sentrycode']);
  await waitReady();
  repositories = await request('/api/v1/admin/repositories', { token: adminToken, expected: 200 });
  if (!repositories.some((item) => item.id === repository.id)) fail('repository state did not survive full service restart');
  pass('PostgreSQL state survives full service restart');

  const backup = await request('/api/v1/admin/operations/backup', { token: adminToken, method: 'POST', expected: 201 });
  if (!backup.path) fail('operational backup returned no path');
  const retention = await request('/api/v1/admin/operations/retention', { token: adminToken, method: 'POST', expected: 200 });
  if (typeof retention.retentionDays !== 'number') fail('retention endpoint returned invalid payload');
  pass('governed backup and retention operations execute');

  const enterprise = await request('/api/v1/admin/enterprise', { token: adminToken, expected: 200 });
  const automotive = await request('/api/v1/admin/automotive', { token: adminToken, expected: 200 });
  if (!enterprise.audit || !enterprise.storage || !automotive.findings) fail('enterprise/automotive operational state incomplete');
  pass('enterprise diagnostics and automotive operational views respond');

  const audit = await request('/api/v1/admin/audit', { token: adminToken, expected: 200 });
  if (!Array.isArray(audit) || audit.length < 2) fail('application audit trail did not capture acceptance writes');
  pass('application administration audit trail captured writes');

  process.stdout.write('\nSENTRYCODE STANDALONE DOCKER ACCEPTANCE: PASS\n');
}

try {
  await main();
} catch (error) {
  if (composeUp) await logs();
  process.stderr.write(`\nSENTRYCODE STANDALONE DOCKER ACCEPTANCE: FAIL\n${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
} finally {
  if (composeUp && !keep) {
    try { await compose(['down', '-v', '--remove-orphans']); pass('isolated acceptance containers and volumes removed'); }
    catch (error) { process.stderr.write(`WARN acceptance cleanup failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; }
  } else if (composeUp && keep) {
    info(`--keep specified; inspect with: docker compose -p ${project} --env-file ${envFile} -f ${composeFile} ps`);
    info(`temporary environment file retained at ${envFile}`);
  }
  if (!keep) await rm(temp, { recursive: true, force: true });
}
