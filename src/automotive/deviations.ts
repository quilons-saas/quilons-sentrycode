import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { AutomotiveDeviation, AutomotiveStandard } from './types.js';

export async function loadAutomotiveDeviations(root: string, file: string): Promise<AutomotiveDeviation[]> {
  try {
    const raw = JSON.parse(await readFile(resolve(root, file), 'utf8')) as unknown;
    if (!Array.isArray(raw)) throw new Error('automotive deviations file must contain an array');
    return raw.map((value, index) => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`automotive deviation[${index}] must be an object`);
      const item = value as Record<string, unknown>;
      if (typeof item.id !== 'string' || typeof item.standard !== 'string' || typeof item.reason !== 'string') throw new Error(`automotive deviation[${index}] requires id, standard and reason`);
      return item as unknown as AutomotiveDeviation;
    });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
}

export function matchingDeviation(args: { standard: AutomotiveStandard; ruleId: string; fingerprint: string; path?: string; deviations: AutomotiveDeviation[]; requireApproval: boolean; now: Date }): AutomotiveDeviation | undefined {
  return args.deviations.find((d) => {
    if (d.standard !== args.standard) return false;
    if (d.ruleId && d.ruleId !== args.ruleId) return false;
    if (d.fingerprint && d.fingerprint !== args.fingerprint) return false;
    if (d.path && d.path !== args.path) return false;
    if (args.requireApproval && (!d.approver || !d.approvedAt)) return false;
    if (d.expiresAt && Date.parse(d.expiresAt) <= args.now.getTime()) return false;
    return true;
  });
}
