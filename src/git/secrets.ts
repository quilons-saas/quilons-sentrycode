import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Finding, SentryCodeConfig } from '../core/types.js';
import { scanSecretText } from '../scanners/secrets/scanner.js';

const execFileAsync = promisify(execFile);
async function git(root: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync('git', args, { cwd: root, windowsHide: true, maxBuffer: 20 * 1024 * 1024 });
  return stdout;
}

export async function scanStagedSecrets(root: string, config: SentryCodeConfig, detectedAt = new Date().toISOString()): Promise<Finding[]> {
  const names = (await git(root, ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'])).split('\0').filter(Boolean);
  const findings: Finding[] = [];
  for (const path of names) {
    try {
      const content = await git(root, ['show', `:${path}`]);
      findings.push(...scanSecretText({ path, content, config, detectedAt, scanner: 'secrets-staged', fingerprintSalt: 'INDEX' }));
    } catch {
      // Binary/unreadable staged entries are ignored by the text scanner.
    }
  }
  return findings;
}

export async function scanHistorySecrets(root: string, config: SentryCodeConfig, maxCommits = config.secrets.historyMaxCommits, detectedAt = new Date().toISOString()): Promise<Finding[]> {
  const commits = (await git(root, ['rev-list', `--max-count=${Math.max(1, maxCommits)}`, 'HEAD'])).split(/\r?\n/).filter(Boolean);
  const findings: Finding[] = [];
  for (const commit of commits) {
    const names = (await git(root, ['diff-tree', '--root', '--no-commit-id', '--name-only', '-r', '-z', commit])).split('\0').filter(Boolean);
    for (const path of names) {
      try {
        const content = await git(root, ['show', `${commit}:${path}`]);
        findings.push(...scanSecretText({ path, content, config, detectedAt, scanner: 'secrets-history', fingerprintSalt: commit }));
      } catch {
        // Deleted, binary, or otherwise unreadable historical entries are ignored.
      }
    }
  }
  return [...new Map(findings.map((finding) => [finding.fingerprint, finding])).values()];
}
