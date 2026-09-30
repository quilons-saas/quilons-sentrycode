import type { Severity } from '../core/types.js';
import { COMPLIANCE_API_VERSION, SENTRYCODE_PLUGIN_ID } from '../compliance/contracts.js';

export const SENTRYCODE_CONSUMER_ENVELOPE_VERSION = '1.0.0' as const;

export interface TechnicalEvidenceReference {
  apiVersion: typeof COMPLIANCE_API_VERSION;
  runId: string;
  evidenceIds: string[];
  evidenceTypes: string[];
  resourcePath: string;
}

export interface TechnicalFindingEnvelope {
  schemaVersion: 1;
  contractVersion: typeof SENTRYCODE_CONSUMER_ENVELOPE_VERSION;
  messageId: string;
  source: {
    pluginId: typeof SENTRYCODE_PLUGIN_ID;
    product: 'QUILONS SentryCode';
    version: string;
  };
  tenant: string;
  project: string;
  repository: string;
  finding: {
    id: string;
    type: string;
    scanner: string;
    ruleId: string;
    title: string;
    description: string;
    severity: Severity;
    status: 'active' | 'waived';
    waiverId?: string;
  };
  sourceRevision: {
    commitSha: string | null;
    branch: string | null;
    buildId?: string;
    jobId?: string;
    changeNumber?: string;
    patchsetNumber?: string;
    revision?: string;
  };
  evidenceReference: TechnicalEvidenceReference;
  correlation: { runId: string };
  timestamps: {
    detectedAt: string;
    scanCompletedAt: string;
    producedAt: string;
  };
}
