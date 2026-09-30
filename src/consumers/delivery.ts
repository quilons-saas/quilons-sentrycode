import type { ApplicationStateStore } from '../application/store.js';
import type { ConsumerDeliveryEnqueueResult } from '../application/types.js';
import { appendAuditEvent } from '../enterprise/audit.js';

export interface ConsumerDeliveryMessage {
  consumerId: string;
  adapterId: string;
  adapterContractVersion: string;
  messageId: string;
  tenant: string;
  project: string;
  findingId: string;
  runId: string;
  payload: Record<string, unknown>;
}

export interface ConsumerPayloadPublisher {
  publish(payload: Record<string, unknown>): Promise<{ statusCode: number }>;
}

type ConsumerDeliveryStore = Pick<ApplicationStateStore,
  'enqueueConsumerDelivery' | 'listPendingConsumerDeliveries' | 'recordConsumerDeliveryAttempt'>;

export interface ConsumerDeliveryOptions {
  maxAttempts: number;
  retryDelayMs: number;
  batchSize?: number;
}

function required(value: string, label: string): string {
  if (!value.trim()) throw new Error(`${label} is required`);
  return value;
}

function validateMessage(message: ConsumerDeliveryMessage): ConsumerDeliveryMessage {
  required(message.consumerId, 'consumerId');
  required(message.adapterId, 'adapterId');
  required(message.adapterContractVersion, 'adapterContractVersion');
  required(message.messageId, 'messageId');
  required(message.tenant, 'tenant');
  required(message.project, 'project');
  required(message.findingId, 'findingId');
  required(message.runId, 'runId');
  if (!message.payload || typeof message.payload !== 'object' || Array.isArray(message.payload)) throw new Error('payload must be an object');
  return message;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'undefined';
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(',')}}`;
}

function assertIdempotentMatch(record: ConsumerDeliveryEnqueueResult['record'], message: ConsumerDeliveryMessage): void {
  const identityMatches = record.consumerId === message.consumerId
    && record.adapterId === message.adapterId
    && record.adapterContractVersion === message.adapterContractVersion
    && record.tenant === message.tenant
    && record.project === message.project
    && record.findingId === message.findingId
    && record.runId === message.runId;
  if (!identityMatches || canonicalJson(record.payload) !== canonicalJson(message.payload)) {
    throw new Error(`Consumer delivery idempotency collision for ${message.consumerId}/${message.messageId}`);
  }
}

export async function enqueueConsumerDeliveries(store: ConsumerDeliveryStore, messages: ConsumerDeliveryMessage[]): Promise<ConsumerDeliveryEnqueueResult[]> {
  const queued: ConsumerDeliveryEnqueueResult[] = [];
  for (const raw of messages) {
    const message = validateMessage(raw);
    const result = await store.enqueueConsumerDelivery(message);
    if (!result.created) assertIdempotentMatch(result.record, message);
    queued.push(result);
  }
  return queued;
}

export async function deliverPendingConsumerDeliveries(args: {
  store: ConsumerDeliveryStore;
  publisher: ConsumerPayloadPublisher;
  consumerId: string;
  tenant: string;
  project: string;
  options: ConsumerDeliveryOptions;
  root: string;
  auditLogFile: string;
  auditEventPrefix?: string;
  auditSigningPrivateKeyFile?: string;
  now?: Date;
}): Promise<{ attempted: number; delivered: number; failed: number }> {
  const consumerId = required(args.consumerId, 'consumerId');
  const now = args.now ?? new Date();
  const pending = await args.store.listPendingConsumerDeliveries(
    consumerId,
    args.tenant,
    args.project,
    args.options.maxAttempts,
    now.toISOString(),
    args.options.batchSize ?? 100
  );
  let delivered = 0;
  let failed = 0;
  const auditPrefix = args.auditEventPrefix?.trim() || 'consumer.delivery';
  for (const record of pending) {
    try {
      const result = await args.publisher.publish(record.payload);
      await args.store.recordConsumerDeliveryAttempt(record.consumerId, record.messageId, { delivered: true, responseStatus: result.statusCode });
      delivered += 1;
      await appendAuditEvent(args.root, args.auditLogFile, `${auditPrefix}.delivered`, {
        consumerId: record.consumerId, adapterId: record.adapterId, adapterContractVersion: record.adapterContractVersion, messageId: record.messageId,
        findingId: record.findingId, runId: record.runId, tenant: record.tenant, project: record.project,
        responseStatus: result.statusCode
      }, undefined, args.auditSigningPrivateKeyFile);
    } catch (error) {
      const message = (error as Error).message;
      const nextAttemptAt = new Date(now.getTime() + args.options.retryDelayMs).toISOString();
      await args.store.recordConsumerDeliveryAttempt(record.consumerId, record.messageId, { delivered: false, error: message, nextAttemptAt });
      failed += 1;
      await appendAuditEvent(args.root, args.auditLogFile, `${auditPrefix}.delivery_failed`, {
        consumerId: record.consumerId, adapterId: record.adapterId, adapterContractVersion: record.adapterContractVersion, messageId: record.messageId,
        findingId: record.findingId, runId: record.runId, tenant: record.tenant, project: record.project,
        error: message
      }, undefined, args.auditSigningPrivateKeyFile);
    }
  }
  return { attempted: pending.length, delivered, failed };
}
