export const SCHEMA_VERSION = '1.0.0' as const;

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Decision = 'PASS' | 'WARN' | 'FAIL';
export type ScannerExecutionStatus = 'success' | 'failed' | 'skipped';
export type ScannerFailureMode = 'fail' | 'warn' | 'ignore';
export type PolicyLevel = 'organization' | 'tenant' | 'project' | 'repository' | 'service';
export type PolicyField = 'failOn' | 'warnOn' | 'requiredScanners' | 'scannerFailureModes';

export interface RepositoryContext {
  root: string;
  repository: string;
  commitSha: string | null;
  branch: string | null;
  isDirty: boolean;
}

export interface SourceLocation {
  path: string;
  line?: number;
  column?: number;
}

export interface Finding {
  schemaVersion: typeof SCHEMA_VERSION;
  id: string;
  type: string;
  scanner: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  location?: SourceLocation;
  fingerprint: string;
  remediation?: string;
  detectedAt: string;
  metadata?: Record<string, string | number | boolean | null>;
}

export interface EvidenceRecord {
  schemaVersion: typeof SCHEMA_VERSION;
  id: string;
  type: string;
  scanner: string;
  repository: string;
  commitSha: string | null;
  branch: string | null;
  generatedAt: string;
  findingIds: string[];
  metadata: Record<string, string | number | boolean | null>;
}

export interface ScannerResult {
  scanner: string;
  findings: Finding[];
  evidence: EvidenceRecord[];
  durationMs: number;
  status?: ScannerExecutionStatus;
  error?: string;
}

export interface ScannerContext {
  repository: RepositoryContext;
  config: SentryCodeConfig;
  now: () => Date;
}

export interface ScannerPlugin {
  readonly id: string;
  readonly version: string;
  scan(context: ScannerContext): Promise<ScannerResult>;
}

export interface Waiver {
  id: string;
  fingerprint?: string;
  ruleId?: string;
  path?: string;
  scanner?: string;
  repository?: string;
  service?: string;
  reason: string;
  ticket?: string;
  createdAt?: string;
  expiresAt: string;
  author?: string;
  approver?: string;
  approvedAt?: string;
}

export interface DependencyComponent {
  ecosystem: 'npm' | 'pypi';
  name: string;
  version: string;
  direct: boolean;
  dev: boolean;
  source: string;
  license?: string;
  purl: string;
  packagePath?: string;
}

export interface DependencySnapshot {
  generatedAt: string;
  components: DependencyComponent[];
}

export interface DependencyChange {
  kind: 'added' | 'removed' | 'upgraded' | 'downgraded' | 'changed';
  ecosystem: DependencyComponent['ecosystem'];
  name: string;
  before?: DependencyComponent;
  after?: DependencyComponent;
}

export interface VulnerabilityAdvisory {
  id: string;
  ecosystem: DependencyComponent['ecosystem'];
  package: string;
  affected: string;
  severity: Severity;
  title?: string;
  fixedVersion?: string;
  source?: string;
  url?: string;
  knownExploited?: boolean;
}

export interface PolicyScope {
  tenant?: string;
  project?: string;
  repository?: string;
  service?: string;
}

export interface PolicyEnforcement {
  failOn?: Severity[];
  warnOn?: Severity[];
  requiredScanners?: string[];
  scannerFailureModes?: Record<string, ScannerFailureMode>;
}

export interface PolicyDocument {
  schemaVersion: 1;
  id: string;
  version: string;
  level: PolicyLevel;
  scope?: PolicyScope;
  description?: string;
  effectiveFrom?: string;
  effectiveUntil?: string;
  enforcement?: PolicyEnforcement;
  lock?: PolicyField[];
}

export interface EffectivePolicy {
  sourceDocuments: Array<{
    id: string;
    version: string;
    level: PolicyLevel;
    path: string;
  }>;
  failOn: Severity[];
  warnOn: Severity[];
  requiredScanners: string[];
  scannerFailureModes: Record<string, ScannerFailureMode>;
  lockedFields: PolicyField[];
  fingerprint: string;
}

export interface PolicyContext {
  tenant?: string;
  project?: string;
  repository: string;
  service?: string;
}

export interface PolicyAuditRecord {
  event: 'policy.resolved' | 'waiver.applied' | 'waiver.rejected' | 'release.decision';
  at: string;
  policyFingerprint?: string;
  policySources?: string[];
  waiverId?: string;
  findingId?: string;
  decision?: Decision;
  reason?: string;
}

export interface SentryCodeConfig {
  schemaVersion: 1;
  scan: {
    include: string[];
    exclude: string[];
    maxFileBytes: number;
  };
  secrets: {
    enabled: boolean;
    highEntropy: boolean;
    minEntropyLength: number;
    customPatterns: Array<{
      id: string;
      pattern: string;
      severity: Severity;
      description?: string;
    }>;
  };
  dependencies: {
    enabled: boolean;
    includeDev: boolean;
    allowedRegistries: string[];
    deniedPackages: string[];
    allowedPackages: string[];
    versionRestrictions: Record<string, string>;
  };
  licenses: {
    enabled: boolean;
    allowed: string[];
    denied: string[];
    reviewRequired: string[];
    unknown: 'allow' | 'warn' | 'fail';
    overrides: Record<string, string>;
  };
  vulnerabilities: {
    enabled: boolean;
    databaseFile: string;
    failOnKnownExploited: boolean;
  };
  sbom: {
    defaultFormat: 'cyclonedx' | 'spdx';
  };
  policy: {
    failOn: Severity[];
    warnOn: Severity[];
    requiredScanners: string[];
    directory: string;
    scannerFailureModes: Record<string, ScannerFailureMode>;
    context: {
      tenant?: string;
      project?: string;
      service?: string;
    };
    opa: {
      enabled: boolean;
      binary: string;
      query: string;
      policyFiles: string[];
    };
  };
  waivers: {
    file: string;
    requireApproval: boolean;
    requireTicket: boolean;
    maxDurationDays: number;
  };
  /** @deprecated Use waivers.file. Retained for config compatibility. */
  waiversFile: string;
}

export interface AppliedFinding {
  finding: Finding;
  waived: boolean;
  waiverId?: string;
}

export interface PolicyResult {
  decision: Decision;
  findings: AppliedFinding[];
  counts: Record<Severity, number>;
  waivedCount: number;
  reasons: string[];
  effectivePolicy?: EffectivePolicy;
  audit: PolicyAuditRecord[];
}

export interface ScanReport {
  schemaVersion: typeof SCHEMA_VERSION;
  runId: string;
  startedAt: string;
  completedAt: string;
  repository: RepositoryContext;
  scanners: ScannerResult[];
  policy: PolicyResult;
  evidence: EvidenceRecord[];
}

export interface ReleaseDecision {
  schemaVersion: typeof SCHEMA_VERSION;
  releaseId: string;
  evaluatedAt: string;
  repository: RepositoryContext;
  decision: Decision;
  policyFingerprint: string;
  reasons: string[];
  evidenceIds: string[];
  scanRunId: string;
}
