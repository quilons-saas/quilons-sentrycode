import { execFile } from 'node:child_process';
import { basename, resolve } from 'node:path';
import { promisify } from 'node:util';
import type { RepositoryContext } from './types.js';

const execFileAsync = promisify(execFile);

async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync('git', args, { cwd, windowsHide: true });
  return stdout.trim();
}

export async function resolveRepository(start = process.cwd()): Promise<RepositoryContext> {
  const cwd = resolve(start);
  let root: string;
  try {
    root = await git(cwd, ['rev-parse', '--show-toplevel']);
  } catch {
    throw new Error(`Not inside a Git repository: ${cwd}`);
  }

  const [commitSha, branch, status] = await Promise.all([
    git(root, ['rev-parse', 'HEAD']).catch(() => ''),
    git(root, ['branch', '--show-current']).catch(() => ''),
    git(root, ['status', '--porcelain']).catch(() => '')
  ]);

  let repository = basename(root);
  try {
    const remote = await git(root, ['remote', 'get-url', 'origin']);
    const match = remote.match(/([^/:]+?)(?:\.git)?$/);
    if (match?.[1]) repository = match[1];
  } catch {
    // A local repository without origin is valid.
  }

  return {
    root,
    repository,
    commitSha: commitSha || null,
    branch: branch || null,
    isDirty: status.length > 0
  };
}
