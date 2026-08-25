import { createHash } from 'node:crypto';
import type {
  EffectivePolicy,
  PolicyDocument,
  PolicyField,
  ScannerFailureMode,
  SentryCodeConfig
} from '../core/types.js';

function fingerprint(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function sameArray(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((item, index) => item === b[index]);
}

function changesLockedField(
  field: PolicyField,
  document: PolicyDocument,
  current: EffectivePolicy
): boolean {
  const enforcement = document.enforcement;
  if (!enforcement) return false;
  if (field === 'failOn' && enforcement.failOn) return !sameArray(current.failOn, enforcement.failOn);
  if (field === 'warnOn' && enforcement.warnOn) return !sameArray(current.warnOn, enforcement.warnOn);
  if (field === 'requiredScanners' && enforcement.requiredScanners) return !sameArray(current.requiredScanners, enforcement.requiredScanners);
  if (field === 'scannerFailureModes' && enforcement.scannerFailureModes) {
    return JSON.stringify(current.scannerFailureModes) !== JSON.stringify({ ...current.scannerFailureModes, ...enforcement.scannerFailureModes });
  }
  return false;
}

export function resolvePolicy(
  config: SentryCodeConfig,
  documents: Array<{ path: string; document: PolicyDocument }>
): EffectivePolicy {
  const effective: EffectivePolicy = {
    sourceDocuments: [],
    failOn: [...config.policy.failOn],
    warnOn: [...config.policy.warnOn],
    requiredScanners: [...config.policy.requiredScanners],
    scannerFailureModes: { ...config.policy.scannerFailureModes },
    lockedFields: [],
    fingerprint: ''
  };

  for (const { path, document } of documents) {
    for (const field of effective.lockedFields) {
      if (changesLockedField(field, document, effective)) {
        throw new Error(`Policy ${document.id}@${document.version} cannot override locked field ${field}`);
      }
    }
    if (document.enforcement?.failOn) effective.failOn = [...document.enforcement.failOn];
    if (document.enforcement?.warnOn) effective.warnOn = [...document.enforcement.warnOn];
    if (document.enforcement?.requiredScanners) effective.requiredScanners = [...document.enforcement.requiredScanners];
    if (document.enforcement?.scannerFailureModes) {
      effective.scannerFailureModes = {
        ...effective.scannerFailureModes,
        ...document.enforcement.scannerFailureModes
      } as Record<string, ScannerFailureMode>;
    }
    for (const field of document.lock ?? []) {
      if (!effective.lockedFields.includes(field)) effective.lockedFields.push(field);
    }
    effective.sourceDocuments.push({
      id: document.id,
      version: document.version,
      level: document.level,
      path
    });
  }

  effective.fingerprint = fingerprint({
    sourceDocuments: effective.sourceDocuments,
    failOn: effective.failOn,
    warnOn: effective.warnOn,
    requiredScanners: effective.requiredScanners,
    scannerFailureModes: effective.scannerFailureModes,
    lockedFields: effective.lockedFields
  });
  return effective;
}
