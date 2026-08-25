import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { mkdir, appendFile, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { sha256, stableId } from '../utils/hash.js';

export interface EnterpriseAuditEvent {
  schemaVersion: 1;
  id: string;
  at: string;
  type: string;
  actor: string;
  detail: Record<string, string | number | boolean | null>;
  previousHash: string;
  hash: string;
  signature?: string;
}

type UnsignedAuditEvent = Omit<EnterpriseAuditEvent, 'hash' | 'signature'>;
function eventHash(event: UnsignedAuditEvent): string { return sha256(JSON.stringify(event)); }

export async function appendAuditEvent(root: string, file: string, type: string, detail: EnterpriseAuditEvent['detail'], actor?: string, signingPrivateKeyFile?: string): Promise<EnterpriseAuditEvent> {
  const existing = await readAuditEvents(root, file);
  const previousHash = existing.at(-1)?.hash ?? 'GENESIS';
  const at = new Date().toISOString();
  const actualActor = actor ?? process.env.USERNAME ?? process.env.USER ?? 'unknown';
  const base: UnsignedAuditEvent = { schemaVersion: 1, id: stableId('audit', `${type}|${at}|${JSON.stringify(detail)}|${previousHash}`), at, type, actor: actualActor, detail, previousHash };
  const hash = eventHash(base);
  let signature: string | undefined;
  if (signingPrivateKeyFile) {
    const key = createPrivateKey(await readFile(resolve(root, signingPrivateKeyFile), 'utf8'));
    signature = sign('sha256', Buffer.from(hash), key).toString('base64');
  }
  const event: EnterpriseAuditEvent = { ...base, hash, ...(signature ? { signature } : {}) };
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

export async function verifyAuditChain(root: string, file: string, signingPublicKeyFile?: string): Promise<{ ok: boolean; invalidIndex?: number }> {
  const events = await readAuditEvents(root, file);
  let previousHash = 'GENESIS';
  const publicKey = signingPublicKeyFile ? createPublicKey(await readFile(resolve(root, signingPublicKeyFile), 'utf8')) : undefined;
  for (let i = 0; i < events.length; i += 1) {
    const event = events[i]!;
    const { hash, signature: _signature, ...base } = event;
    if (event.previousHash !== previousHash || eventHash(base) !== hash) return { ok: false, invalidIndex: i };
    if (publicKey && (!event.signature || !verify('sha256', Buffer.from(hash), publicKey, Buffer.from(event.signature, 'base64')))) return { ok: false, invalidIndex: i };
    previousHash = hash;
  }
  return { ok: true };
}
