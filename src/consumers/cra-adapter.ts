import type { ConsumerConfig } from '../core/types.js';
import { stableId } from '../utils/hash.js';
import { CRA_REPORTING_CONTRACT_VERSION, type CraFindingReport } from '../compliance/cra-contracts.js';
import type { ConsumerAdapter, ConsumerCapabilityRequirements } from './adapter.js';
import { configuredRequirements } from './adapter.js';
import type { TechnicalFindingEnvelope } from './contracts.js';
import { HttpCraFindingPublisher } from '../compliance/publisher.js';
import type { ConsumerPayloadPublisher } from './delivery.js';

export const CRA_CONSUMER_ADAPTER_ID = 'cra' as const;
export const CRA_CONSUMER_ADAPTER_CONTRACT_VERSION = '1.0.0' as const;

export class CraConsumerAdapter implements ConsumerAdapter<CraFindingReport> {
  readonly adapterId = CRA_CONSUMER_ADAPTER_ID;
  readonly contractVersion = CRA_CONSUMER_ADAPTER_CONTRACT_VERSION;

  requirements(config: ConsumerConfig): ConsumerCapabilityRequirements {
    return configuredRequirements(config);
  }


  deliveryMessageId(_envelope: TechnicalFindingEnvelope, mapped: CraFindingReport, _config: ConsumerConfig): string {
    return mapped.reportId;
  }

  createPublisher(config: ConsumerConfig, token: string): ConsumerPayloadPublisher {
    const assessmentId = config.context.assessmentId ?? '';
    const publisher = new HttpCraFindingPublisher(config.endpoint, token, config.timeoutMs, assessmentId);
    return {
      publish: (payload) => publisher.publish(payload as unknown as CraFindingReport)
    };
  }
  mapFinding(envelope: TechnicalFindingEnvelope, _config: ConsumerConfig): CraFindingReport {
    const reportId = stableId('cra-report', `${envelope.tenant}|${envelope.project}|${envelope.repository}|${envelope.correlation.runId}|${envelope.finding.id}`);
    return {
      schemaVersion: 1,
      contractVersion: CRA_REPORTING_CONTRACT_VERSION,
      reportId,
      source: envelope.source,
      tenant: envelope.tenant,
      project: envelope.project,
      repository: envelope.repository,
      finding: envelope.finding,
      sourceRevision: envelope.sourceRevision,
      evidenceReference: {
        apiVersion: envelope.evidenceReference.apiVersion,
        runId: envelope.evidenceReference.runId,
        evidenceIds: [...envelope.evidenceReference.evidenceIds],
        resourcePath: envelope.evidenceReference.resourcePath
      },
      correlation: envelope.correlation,
      timestamps: {
        detectedAt: envelope.timestamps.detectedAt,
        scanCompletedAt: envelope.timestamps.scanCompletedAt,
        reportedAt: envelope.timestamps.producedAt
      }
    };
  }
}
