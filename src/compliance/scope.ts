import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import type { ComplianceIdentity } from './contracts.js';

function clean(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`${label} is required for Compliance publication`);
  if (trimmed.length > 200) throw new Error(`${label} is too long`);
  return trimmed;
}

export function complianceIdentity(tenant: string, project: string): ComplianceIdentity {
  return { tenant: clean(tenant, 'tenant'), project: clean(project, 'project') };
}

export function scopeKey(identity: ComplianceIdentity): string {
  return createHash('sha256').update(`${identity.tenant}\u0000${identity.project}`, 'utf8').digest('hex').slice(0, 32);
}

export function tenantStoreRoot(repositoryRoot: string, storeDirectory: string, identity: ComplianceIdentity): string {
  return resolve(repositoryRoot, storeDirectory, scopeKey(identity));
}
