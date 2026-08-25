import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { Waiver } from '../core/types.js';

export async function loadWaivers(root: string, path: string): Promise<Waiver[]> {
  const absolute = resolve(root, path);
  try {
    const parsed = JSON.parse(await readFile(absolute, 'utf8')) as unknown;
    if (!Array.isArray(parsed)) throw new Error('waivers file must contain a JSON array');
    return parsed.map((entry, index) => {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error(`waiver[${index}] must be an object`);
      const value = entry as Record<string, unknown>;
      if (typeof value.id !== 'string' || typeof value.reason !== 'string' || typeof value.expiresAt !== 'string') {
        throw new Error(`waiver[${index}] requires id, reason, and expiresAt`);
      }
      const expires = new Date(value.expiresAt);
      if (Number.isNaN(expires.getTime())) throw new Error(`waiver[${index}] has invalid expiresAt`);
      return {
        id: value.id,
        reason: value.reason,
        expiresAt: value.expiresAt,
        ...(typeof value.fingerprint === 'string' ? { fingerprint: value.fingerprint } : {}),
        ...(typeof value.ruleId === 'string' ? { ruleId: value.ruleId } : {}),
        ...(typeof value.path === 'string' ? { path: value.path } : {}),
        ...(typeof value.author === 'string' ? { author: value.author } : {}),
        ...(typeof value.approver === 'string' ? { approver: value.approver } : {})
      };
    });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    if (error instanceof SyntaxError) throw new Error(`Invalid JSON in waivers file: ${absolute}`);
    throw error;
  }
}
