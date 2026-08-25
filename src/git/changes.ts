import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

async function diff(root: string, range: string): Promise<string[]> {
  const { stdout } = await execFileAsync('git', ['diff', '--name-only', '--diff-filter=ACMR', range], { cwd: root, windowsHide: true });
  return stdout.split(/\r?\n/).map((x: string) => x.trim().replace(/\\/g,'/')).filter(Boolean).sort();
}

export async function changedFilesBetween(root: string, baseRef: string, headRef = 'HEAD'): Promise<string[]> {
  try { return await diff(root, `${baseRef}...${headRef}`); }
  catch { return diff(root, `${baseRef}..${headRef}`); }
}

export async function refExists(root: string, ref: string): Promise<boolean> {
  try {
    await execFileAsync('git', ['rev-parse', '--verify', `${ref}^{commit}`], { cwd: root, windowsHide: true });
    return true;
  } catch { return false; }
}

export async function resolveAvailableRef(root: string, ref: string): Promise<string | null> {
  if (await refExists(root, ref)) return ref;
  const clean = ref.replace(/^refs\/heads\//,'').replace(/^origin\//,'');
  const candidates = [`origin/${clean}`, `refs/remotes/origin/${clean}`];
  for (const candidate of candidates) if (await refExists(root, candidate)) return candidate;
  return null;
}
