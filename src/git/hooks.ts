import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);

async function git(root: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync('git', args, { cwd: root, windowsHide: true });
  return stdout.trim();
}

export async function installGitHooks(root: string): Promise<string[]> {
  const gitDir = await git(root, ['rev-parse', '--git-dir']);
  const hooksDir = resolve(root, gitDir, 'hooks');
  await mkdir(hooksDir, { recursive: true });
  const preCommit = resolve(hooksDir, 'pre-commit');
  const prePush = resolve(hooksDir, 'pre-push');
  const header = '#!/bin/sh\n# Managed by QUILONS SentryCode. Re-run `sentrycode hooks install` after manual edits.\n';
  await writeFile(preCommit, `${header}npx --no-install sentrycode secrets staged .\n`, 'utf8');
  await writeFile(prePush, `${header}npx --no-install sentrycode check . --full\n`, 'utf8');
  try { await chmod(preCommit, 0o755); await chmod(prePush, 0o755); } catch { /* chmod is best-effort on Windows */ }
  return [preCommit, prePush];
}
