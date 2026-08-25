import { execFile } from 'node:child_process';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
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

  const installedCli = join(temp, 'node_modules', '@quilons', 'sentrycode', 'dist', 'cli', 'main.js');
  const result = await execFileAsync(process.execPath, [installedCli, '--help'], {
    cwd: temp,
    windowsHide: true,
  });

  if (!result.stdout.includes('QUILONS SentryCode')) {
    throw new Error('installed CLI help did not execute');
  }

  await rm(tarball, { force: true });
  process.stdout.write('PASS external package install and CLI smoke\n');
} finally {
  await rm(temp, { recursive: true, force: true });
}
