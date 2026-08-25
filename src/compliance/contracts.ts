import type { Decision, EvidenceRecord, ScanReport } from '../core/types.js';

export const COMPLIANCE_API_VERSION = '1.0.0' as const;
export const SENTRYCODE_PLUGIN_ID = 'quilons.sentrycode' as const;

export interface ComplianceIdentity {
  tenant: string;
  project: string;
}

export interface CapabilityDescriptor {
  id: string;
  version: string;
  description: string;
  operations: string[];
}

export interface PluginManifest {
  schemaVersion: 1;
  pluginId: typeof SENTRYCODE_PLUGIN_ID;
  product: 'QUILONS SentryCode';
  productVersion: string;
  apiVersion: typeof COMPLIANCE_API_VERSION;
  standalone: true;
  capabilities: CapabilityDescriptor[];
  health: { command: string };
  readiness: { command: string };
  evidenceTypes: string[];
}

export interface ComplianceEvent<T = unknown> {
  schemaVersion: 1;
  id: string;
  type: string;
  source: typeof SENTRYCODE_PLUGIN_ID;
  occurredAt: string;
  tenant: string;
  project: string;
  repository: string;
  payload: T;
}

export interface EvidenceEnvelope {
  schemaVersion: 1;
  apiVersion: typeof COMPLIANCE_API_VERSION;
  producer: {
    pluginId: typeof SENTRYCODE_PLUGIN_ID;
    product: 'QUILONS SentryCode';
    version: string;
  };
  tenant: string;
  project: string;
  repository: string;
  runId: string;
  decision: Decision;
  policyFingerprint?: string;
  generatedAt: string;
  evidence: EvidenceRecord[];
}

export interface StoredRunSummary {
  runId: string;
  tenant: string;
  project: string;
  repository: string;
  commitSha: string | null;
  branch: string | null;
  decision: Decision;
  policyFingerprint?: string;
  startedAt: string;
  completedAt: string;
  evidenceCount: number;
  findingCount: number;
}

export interface CompliancePublication {
  summary: StoredRunSummary;
  evidence: EvidenceEnvelope;
  report: ScanReport;
  events: ComplianceEvent[];
}

export interface ComplianceHealth {
  status: 'ok';
  pluginId: typeof SENTRYCODE_PLUGIN_ID;
  apiVersion: typeof COMPLIANCE_API_VERSION;
}

export interface ComplianceReadiness extends ComplianceHealth {
  ready: boolean;
  checks: Array<{ id: string; ok: boolean; detail: string }>;
}
