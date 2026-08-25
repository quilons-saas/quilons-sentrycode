import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { BranchGovernanceState, GitGovernanceProvider } from './provider.js';
const execFileAsync = promisify(execFile);

function parseGithubRemote(remote: string): { owner: string; repo: string } | null {
  const normalized = remote.trim().replace(/\.git$/, '');
  const ssh = normalized.match(/github\.com[:/]([^/]+)\/([^/]+)$/i);
  return ssh ? { owner: ssh[1]!, repo: ssh[2]! } : null;
}

export class GitHubGovernanceProvider implements GitGovernanceProvider {
  readonly id = 'github';
  constructor(private readonly options: { token: string; apiBaseUrl?: string; timeoutMs?: number }) {}

  async inspect(repositoryRoot: string, branch: string): Promise<BranchGovernanceState> {
    if (!this.options.token) throw new Error('GitHub governance token is required');
    const { stdout } = await execFileAsync('git', ['remote', 'get-url', 'origin'], { cwd: repositoryRoot, windowsHide: true });
    const repo = parseGithubRemote(stdout);
    if (!repo) return { provider: this.id, repository: '', branch, protected: null, requiredApprovals: null, statusChecksRequired: null, source: 'unavailable' };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 15000);
    try {
      const endpoint = `${(this.options.apiBaseUrl ?? 'https://api.github.com').replace(/\/$/, '')}/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}/branches/${encodeURIComponent(branch)}/protection`;
      const response = await fetch(endpoint, { headers: { accept: 'application/vnd.github+json', authorization: `Bearer ${this.options.token}`, 'x-github-api-version': '2026-03-10', 'user-agent': 'quilons-sentrycode' }, signal: controller.signal });
      if (response.status === 404) return { provider: this.id, repository: `${repo.owner}/${repo.repo}`, branch, protected: false, requiredApprovals: 0, statusChecksRequired: false, source: 'provider-api' };
      if (!response.ok) throw new Error(`GitHub branch protection query failed: HTTP ${response.status}`);
      const body = await response.json() as Record<string, unknown>;
      const reviews = body.required_pull_request_reviews && typeof body.required_pull_request_reviews === 'object' ? body.required_pull_request_reviews as Record<string, unknown> : null;
      const checks = body.required_status_checks && typeof body.required_status_checks === 'object' ? body.required_status_checks as Record<string, unknown> : null;
      const contexts = Array.isArray(checks?.contexts) ? checks.contexts : [];
      const checkEntries = Array.isArray(checks?.checks) ? checks.checks : [];
      return {
        provider: this.id,
        repository: `${repo.owner}/${repo.repo}`,
        branch,
        protected: true,
        requiredApprovals: typeof reviews?.required_approving_review_count === 'number' ? reviews.required_approving_review_count : 0,
        statusChecksRequired: Boolean(checks && (contexts.length > 0 || checkEntries.length > 0)),
        source: 'provider-api'
      };
    } finally { clearTimeout(timer); }
  }
}
