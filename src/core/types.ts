export const SCHEMA_VERSION = '1.0.0' as const;

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Decision = 'PASS' | 'WARN' | 'FAIL';

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
  reason: string;
  expiresAt: string;
  author?: string;
  approver?: string;
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
  };
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
