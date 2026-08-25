export interface BranchGovernanceState {
  provider: string;
  repository: string;
  branch: string;
  protected: boolean | null;
  requiredApprovals: number | null;
  statusChecksRequired: boolean | null;
  source: 'provider-api' | 'unavailable';
}

/** Provider-specific integrations implement this boundary; core SentryCode never depends on a Git host. */
export interface GitGovernanceProvider {
  readonly id: string;
  inspect(repositoryRoot: string, branch: string): Promise<BranchGovernanceState>;
}
