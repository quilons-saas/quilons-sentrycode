import { execFile, spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const temp = await mkdtemp(join(tmpdir(), 'sentrycode-package-'));

async function runNpm(args, options = {}) {
  const npmExecPath = process.env.npm_execpath;
  if (npmExecPath) {
    return execFileAsync(process.execPath, [npmExecPath, ...args], {
      windowsHide: true,
      maxBuffer: 20 * 1024 * 1024,
      ...options,
    });
  }

  const executable = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  return execFileAsync(executable, args, {
    windowsHide: true,
    maxBuffer: 20 * 1024 * 1024,
    shell: process.platform === 'win32',
    ...options,
  });
}

try {
  const { stdout } = await runNpm(['pack', '--ignore-scripts', '--json'], { cwd: root });
  const packed = JSON.parse(stdout)[0];
  if (!packed?.filename) throw new Error('npm pack did not return a tarball filename');

  const tarball = join(root, packed.filename);
  await writeFile(
    join(temp, 'package.json'),
    JSON.stringify({ name: 'sentrycode-external-smoke', private: true, version: '1.0.0' }),
  );

  await runNpm(['install', '--ignore-scripts', tarball], { cwd: temp });

  const shim = process.platform === 'win32'
    ? join(temp, 'node_modules', '.bin', 'sentrycode.cmd')
    : join(temp, 'node_modules', '.bin', 'sentrycode');
  await access(shim);
  await access(join(temp, 'node_modules', '@quilons', 'sentrycode', 'ui', 'index.html'));
  await access(join(temp, 'node_modules', '@quilons', 'sentrycode', 'migrations', '001_application_state.sql'));
  await access(join(temp, 'node_modules', '@quilons', 'sentrycode', 'deploy', 'docker-compose.postgres.yml'));
  await access(join(temp, 'node_modules', '@quilons', 'sentrycode', 'deploy', 'docker-compose.yml'));
  await access(join(temp, 'node_modules', '@quilons', 'sentrycode', 'Dockerfile'));
  await access(join(temp, 'node_modules', '@quilons', 'sentrycode', 'docs', 'on-prem', 'DOCKER_DEPLOYMENT.md'));
  await access(join(temp, 'node_modules', '@quilons', 'sentrycode', 'docs', 'on-prem', 'STANDALONE_ACCEPTANCE.md'));
  await access(join(temp, 'node_modules', '@quilons', 'sentrycode', 'scripts', 'acceptance', 'standalone-docker.mjs'));
  await access(join(temp, 'node_modules', '@quilons', 'sentrycode', 'scripts', 'acceptance', 'market-readiness.mjs'));
  await access(join(temp, 'node_modules', '@quilons', 'sentrycode', 'docs', 'release', 'MARKET_READINESS_ACCEPTANCE.md'));

  const installedRoot = join(temp, 'node_modules', '@quilons', 'sentrycode');
  const installedCli = join(installedRoot, 'dist', 'cli', 'main.js');
  const result = await execFileAsync(process.execPath, [installedCli, '--help'], {
    cwd: temp,
    windowsHide: true,
  });

  if (!result.stdout.includes('QUILONS SentryCode')) {
    throw new Error('installed CLI help did not execute');
  }

  // The packaged production image intentionally has no .git directory and no Git
  // executable. Compliance runtime/read operations must therefore work from the
  // installed package root without a Git executable. Clear PATH for these
  // probes so package smoke proves Git is not a runtime requirement.
  const noGitEnv = { ...process.env, PATH: '' };
  const healthResult = await execFileAsync(process.execPath, [installedCli, 'compliance', 'health', installedRoot, '--format', 'json'], {
    cwd: temp,
    windowsHide: true,
    env: noGitEnv,
  });
  const health = JSON.parse(healthResult.stdout);
  if (health.status !== 'ok' || health.pluginId !== 'quilons.sentrycode') {
    throw new Error('installed compliance health did not report the SentryCode plugin as healthy');
  }

  const manifestResult = await execFileAsync(process.execPath, [installedCli, 'compliance', 'manifest', installedRoot, '--format', 'json'], {
    cwd: temp,
    windowsHide: true,
    env: noGitEnv,
  });
  const manifest = JSON.parse(manifestResult.stdout);
  if (manifest.pluginId !== 'quilons.sentrycode' || manifest.standalone !== true) {
    throw new Error('installed compliance manifest is not available from a repository-free package root');
  }

  const readyResult = await execFileAsync(process.execPath, [installedCli, 'compliance', 'ready', installedRoot, '--format', 'json'], {
    cwd: temp,
    windowsHide: true,
    env: noGitEnv,
  });
  const readiness = JSON.parse(readyResult.stdout);
  if (readiness.ready !== true || !Array.isArray(readiness.checks) || readiness.checks.some((item) => item.ok !== true)) {
    throw new Error('installed compliance readiness did not pass from a repository-free package root');
  }

  // Prove the retained governed read API can actually start from the packaged
  // runtime without a Git repository or Git executable. Port 0 asks Node to bind
  // an available loopback port, avoiding collisions in developer/CI environments.
  await mkdir(join(installedRoot, '.sentrycode'), { recursive: true });
  await writeFile(
    join(installedRoot, '.sentrycode', 'config.json'),
    JSON.stringify({ compliance: { listenHost: '127.0.0.1', listenPort: 0 } }),
  );

  const server = spawn(process.execPath, [installedCli, 'compliance', 'serve', installedRoot], {
    cwd: temp,
    windowsHide: true,
    env: noGitEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverStdout = '';
  let serverStderr = '';
  server.stdout.setEncoding('utf8');
  server.stderr.setEncoding('utf8');
  server.stdout.on('data', (chunk) => { serverStdout += chunk; });
  server.stderr.on('data', (chunk) => { serverStderr += chunk; });

  try {
    const listening = await new Promise((resolveListening, rejectListening) => {
      const timeout = setTimeout(() => rejectListening(new Error(`timed out waiting for packaged Compliance API startup; stdout=${serverStdout}; stderr=${serverStderr}`)), 15000);
      const inspectOutput = () => {
        const match = /SentryCode Compliance API listening on ([^:]+):(\d+)/.exec(serverStdout);
        if (!match) return;
        clearTimeout(timeout);
        resolveListening({ host: match[1], port: Number(match[2]) });
      };
      server.stdout.on('data', inspectOutput);
      server.once('exit', (code, signal) => {
        clearTimeout(timeout);
        rejectListening(new Error(`packaged Compliance API exited before startup (code=${code}, signal=${signal}); stdout=${serverStdout}; stderr=${serverStderr}`));
      });
      inspectOutput();
    });

    const baseUrl = `http://${listening.host}:${listening.port}`;
    const healthResponse = await fetch(`${baseUrl}/v1/health`);
    const healthBody = await healthResponse.json();
    if (!healthResponse.ok || healthBody.status !== 'ok' || healthBody.pluginId !== 'quilons.sentrycode') {
      throw new Error('packaged Compliance API health endpoint failed');
    }

    const readyResponse = await fetch(`${baseUrl}/v1/ready`);
    const readyBody = await readyResponse.json();
    if (!readyResponse.ok || readyBody.ready !== true) {
      throw new Error(`packaged Compliance API readiness endpoint failed: ${JSON.stringify(readyBody)}`);
    }

    const manifestResponse = await fetch(`${baseUrl}/v1/manifest`);
    const manifestBody = await manifestResponse.json();
    if (!manifestResponse.ok || manifestBody.pluginId !== 'quilons.sentrycode' || manifestBody.standalone !== true) {
      throw new Error('packaged Compliance API manifest endpoint failed');
    }
  } finally {
    if (server.exitCode === null && server.signalCode === null) {
      await new Promise((resolveExit, rejectExit) => {
        const timeout = setTimeout(() => rejectExit(new Error('timed out stopping packaged Compliance API smoke process')), 5000);
        server.once('exit', () => { clearTimeout(timeout); resolveExit(); });
        if (!server.kill()) {
          clearTimeout(timeout);
          rejectExit(new Error('failed to stop packaged Compliance API smoke process'));
        }
      });
    }
  }

  await rm(tarball, { force: true });
  process.stdout.write('PASS external package install and repository-free Compliance CLI/read-API smoke\n');
} finally {
  await rm(temp, { recursive: true, force: true });
}
