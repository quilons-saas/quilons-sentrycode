import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { Finding, PolicyAuditRecord, PolicyContext, SentryCodeConfig, Waiver } from '../core/types.js';

function parseWaiver(entry: unknown, index: number): Waiver {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error(`waiver[${index}] must be an object`);
  const value = entry as Record<string, unknown>;
  if (typeof value.id !== 'string' || !value.id.trim()) throw new Error(`waiver[${index}] requires id`);
  if (typeof value.reason !== 'string' || !value.reason.trim()) throw new Error(`waiver[${index}] requires reason`);
  if (typeof value.expiresAt !== 'string') throw new Error(`waiver[${index}] requires expiresAt`);
  const expires = new Date(value.expiresAt);
  if (Number.isNaN(expires.getTime())) throw new Error(`waiver[${index}] has invalid expiresAt`);
  if (!['fingerprint', 'ruleId', 'path', 'scanner'].some((key) => typeof value[key] === 'string')) {
    throw new Error(`waiver[${index}] must scope at least one of fingerprint, ruleId, path, or scanner`);
  }
  return {
    id: value.id,
    reason: value.reason,
    expiresAt: value.expiresAt,
    ...(typeof value.fingerprint === 'string' ? { fingerprint: value.fingerprint } : {}),
    ...(typeof value.ruleId === 'string' ? { ruleId: value.ruleId } : {}),
    ...(typeof value.path === 'string' ? { path: value.path } : {}),
    ...(typeof value.scanner === 'string' ? { scanner: value.scanner } : {}),
    ...(typeof value.repository === 'string' ? { repository: value.repository } : {}),
    ...(typeof value.service === 'string' ? { service: value.service } : {}),
    ...(typeof value.reason === 'string' ? { reason: value.reason } : {}),
    ...(typeof value.ticket === 'string' ? { ticket: value.ticket } : {}),
    ...(typeof value.createdAt === 'string' ? { createdAt: value.createdAt } : {}),
    ...(typeof value.author === 'string' ? { author: value.author } : {}),
    ...(typeof value.approver === 'string' ? { approver: value.approver } : {}),
    ...(typeof value.approvedAt === 'string' ? { approvedAt: value.approvedAt } : {})
  };
}

export async function loadWaivers(root: string, path: string): Promise<Waiver[]> {
  const absolute = resolve(root, path);
  try {
    const parsed = JSON.parse(await readFile(absolute, 'utf8')) as unknown;
    if (!Array.isArray(parsed)) throw new Error('waivers file must contain a JSON array');
    const waivers = parsed.map(parseWaiver);
    const ids = new Set<string>();
    for (const waiver of waivers) {
      if (ids.has(waiver.id)) throw new Error(`duplicate waiver id: ${waiver.id}`);
      ids.add(waiver.id);
    }
    return waivers;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    if (error instanceof SyntaxError) throw new Error(`Invalid JSON in waivers file: ${absolute}`);
    throw error;
  }
}

function scopeMatches(waiver: Waiver, finding: Finding, context: PolicyContext): boolean {
  if (waiver.fingerprint && waiver.fingerprint !== finding.fingerprint) return false;
  if (waiver.ruleId && waiver.ruleId !== finding.ruleId) return false;
  if (waiver.path && waiver.path !== finding.location?.path) return false;
  if (waiver.scanner && waiver.scanner !== finding.scanner) return false;
  if (waiver.repository && waiver.repository !== context.repository) return false;
  if (waiver.service && waiver.service !== context.service) return false;
  return true;
}

function waiverValidity(waiver: Waiver, config: SentryCodeConfig, now: Date): string | undefined {
  const expires = new Date(waiver.expiresAt);
  if (expires <= now) return 'expired';
  if (config.waivers.requireApproval && (!waiver.approver || !waiver.approvedAt)) return 'approval required';
  if (config.waivers.requireTicket && !waiver.ticket) return 'ticket required';
  if (waiver.createdAt) {
    const created = new Date(waiver.createdAt);
    if (Number.isNaN(created.getTime())) return 'invalid createdAt';
    const durationDays = (expires.getTime() - created.getTime()) / 86_400_000;
    if (durationDays > config.waivers.maxDurationDays) return `duration exceeds ${config.waivers.maxDurationDays} days`;
  }
  return undefined;
}

export function findApplicableWaiver(args: {
  finding: Finding;
  waivers: Waiver[];
  config: SentryCodeConfig;
  context: PolicyContext;
  now: Date;
  audit: PolicyAuditRecord[];
}): Waiver | undefined {
  for (const waiver of args.waivers) {
    if (!scopeMatches(waiver, args.finding, args.context)) continue;
    const invalidReason = waiverValidity(waiver, args.config, args.now);
    if (invalidReason) {
      args.audit.push({
        event: 'waiver.rejected',
        at: args.now.toISOString(),
        waiverId: waiver.id,
        findingId: args.finding.id,
        reason: invalidReason
      });
      continue;
    }
    args.audit.push({
      event: 'waiver.applied',
      at: args.now.toISOString(),
      waiverId: waiver.id,
      findingId: args.finding.id,
      reason: waiver.reason
    });
    return waiver;
  }
  return undefined;
}
