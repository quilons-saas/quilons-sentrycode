import type { Decision, EvidenceRecord, Finding, ScannerExecutionStatus, Severity } from '../core/types.js';
import type { StoredRunSummary } from '../compliance/contracts.js';

export const WEB_API_VERSION = '1.0.0' as const;

export interface WebScope { tenant: string; project: string; }
export interface WebStatus {
  apiVersion: typeof WEB_API_VERSION;
  product: 'QUILONS SentryCode';
  version: string;
  health: 'ok';
  ready: boolean;
  checks: Array<{ id: string; ok: boolean; detail: string }>;
  scope: WebScope | null;
  repositoryRoot: string;
  ui: { mode: 'standalone'; readOnly: true };
}
export interface RepositorySummary {
  repository: string;
  latestRunId: string;
  latestDecision: Decision;
  latestCommitSha: string | null;
  latestBranch: string | null;
  latestCompletedAt: string;
  runCount: number;
  findingCount: number;
}
export interface FindingView {
  runId: string;
  repository: string;
  commitSha: string | null;
  branch: string | null;
  decision: Decision;
  finding: Finding;
  waived: boolean;
  waiverId?: string;
}
export interface DashboardSummary {
  runs: number;
  repositories: number;
  decisions: Record<Decision, number>;
  findings: Record<Severity, number>;
  waived: number;
  scannerFailures: number;
  evidence: number;
  recentRuns: StoredRunSummary[];
}
export interface RunDetailView {
  summary: StoredRunSummary;
  report: {
    scanners: Array<{ scanner: string; status: ScannerExecutionStatus; durationMs: number; findingCount: number; error?: string }>;
    findings: FindingView[];
    reasons: string[];
    waivedCount: number;
    effectivePolicy: unknown;
    execution: unknown;
  };
  evidence: EvidenceRecord[];
  integrity: { verified: true; signedVerificationRequired: boolean };
}
