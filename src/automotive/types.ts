import type { Severity } from '../core/types.js';

export type AutomotiveStandard = 'misra-c' | 'misra-cpp' | 'autosar-cpp';
export type AutomotiveEvidenceTarget = 'iso-sae-21434' | 'unece-r155' | 'unece-r156';

export interface AutomotiveImportedFinding {
  ruleId: string;
  message: string;
  severity?: Severity | 'error' | 'warning' | 'note';
  path?: string;
  line?: number;
  column?: number;
  tags?: string[];
  fingerprint?: string;
}

export interface AutomotiveImportDocument {
  schemaVersion: 1;
  standard: AutomotiveStandard;
  tool: { name: string; version?: string };
  generatedAt?: string;
  findings: AutomotiveImportedFinding[];
}

export interface AutomotiveDeviation {
  id: string;
  standard: AutomotiveStandard;
  ruleId?: string;
  fingerprint?: string;
  path?: string;
  reason: string;
  approver?: string;
  approvedAt?: string;
  ticket?: string;
  expiresAt?: string;
}
