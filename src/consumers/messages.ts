import type { ComplianceIdentity } from '../compliance/contracts.js';
import type { ConsumerConfig, ScanReport } from '../core/types.js';
import { buildTechnicalFindingEnvelope } from './envelope.js';
import { getConsumerAdapter } from './registry.js';
import { selectConsumerFindings } from './selection.js';
import type { ConsumerDeliveryMessage } from './delivery.js';

export function buildConsumerDeliveryMessages(args: {
  consumer: ConsumerConfig;
  identity: ComplianceIdentity;
  report: ScanReport;
  productVersion: string;
  producedAt?: string;
}): ConsumerDeliveryMessage[] {
  const adapter = getConsumerAdapter(args.consumer.adapter);
  if (!adapter) throw new Error(`Consumer adapter is not installed: ${args.consumer.adapter}`);

  return selectConsumerFindings(args.report, args.consumer).map((appliedFinding) => {
    const envelope = buildTechnicalFindingEnvelope({
      identity: args.identity,
      report: args.report,
      appliedFinding,
      productVersion: args.productVersion,
      ...(args.producedAt ? { producedAt: args.producedAt } : {})
    });
    const mapped = adapter.mapFinding(envelope, args.consumer);
    if (!mapped || typeof mapped !== 'object' || Array.isArray(mapped)) {
      throw new Error(`Consumer adapter ${args.consumer.adapter} returned a non-object payload`);
    }
    const messageId = adapter.deliveryMessageId(envelope, mapped, args.consumer).trim();
    if (!messageId) throw new Error(`Consumer adapter ${args.consumer.adapter} returned an empty delivery message ID`);
    return {
      consumerId: args.consumer.consumerId,
      adapterId: args.consumer.adapter,
      adapterContractVersion: adapter.contractVersion,
      messageId,
      tenant: envelope.tenant,
      project: envelope.project,
      findingId: envelope.finding.id,
      runId: envelope.correlation.runId,
      payload: mapped as Record<string, unknown>
    };
  });
}
