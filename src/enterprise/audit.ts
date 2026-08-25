import { mkdir, appendFile, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { stableId } from '../utils/hash.js';

export interface EnterpriseAuditEvent {
  schemaVersion: 1;
  id: string;
  at: string;
  type: string;
  actor: string;
  detail: Record<string, string | number | boolean | null>;
}

export async function appendAuditEvent(root: string, file: string, type: string, detail: EnterpriseAuditEvent['detail'], actor = process.env.USERNAME ?? process.env.USER ?? 'unknown'): Promise<EnterpriseAuditEvent> {
  const at = new Date().toISOString();
  const event: EnterpriseAuditEvent = { schemaVersion: 1, id: stableId('audit', `${type}|${at}|${JSON.stringify(detail)}`), at, type, actor, detail };
  const absolute = resolve(root, file);
  await mkdir(dirname(absolute), { recursive: true });
  await appendFile(absolute, `${JSON.stringify(event)}\n`, 'utf8');
  return event;
}

export async function readAuditEvents(root: string, file: string): Promise<EnterpriseAuditEvent[]> {
  try {
    const content = await readFile(resolve(root, file), 'utf8');
    return content.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as EnterpriseAuditEvent);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
}
