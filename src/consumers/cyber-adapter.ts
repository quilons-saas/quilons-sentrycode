import type { ConsumerConfig } from '../core/types.js';
import { stableId } from '../utils/hash.js';
import type { ConsumerAdapter, ConsumerCapabilityRequirements } from './adapter.js';
import { configuredRequirements } from './adapter.js';
import type { TechnicalFindingEnvelope } from './contracts.js';
import type { ConsumerPayloadPublisher } from './delivery.js';
import { HttpJsonConsumerPublisher } from './http-publisher.js';

export const CYBER_CONSUMER_ADAPTER_ID = 'cyber' as const;
export const CYBER_CONSUMER_ADAPTER_CONTRACT_VERSION = 'cyber.security-evidence.v1' as const;

export interface CyberSecurityEvidenceInvocation extends Record<string, unknown> {
  contractVersion: 'quilons.service-invocation.v1';
  tenantId: string;
  appId: 'quilons-sentrycode';
  operation: 'cyber.security-evidence.ingest';
  actor: { actorType: 'SERVICE'; actorId: 'quilons-sentrycode'; permissions: string[] };
  input: {
    receiptId: string;
    submission: {
      contractVersion: 'cyber.security-evidence.v1';
      capabilityId: 'cyber.security-evidence';
      capabilityVersion: 'v1';
      tenantId: string;
      evidenceId: string;
      evidenceType: 'EXTERNAL_TOOL_RESULT';
      subject: { subjectType: 'BUILD'; subjectId: string; assuranceContext: 'MANUFACTURER' | 'DEPLOYMENT' };
      assuranceContext: 'MANUFACTURER' | 'DEPLOYMENT';
      provider: { providerType: 'QUILONS_NATIVE'; providerId: 'quilons-sentrycode'; providerVersion: string };
      provenance: {
        provider: { providerType: 'QUILONS_NATIVE'; providerId: 'quilons-sentrycode'; providerVersion: string };
        source: { sourceKind: 'scanner_result'; sourceReferenceId: string; sourceLabel: string };
        normalized: true;
      };
      observedAt: string;
      collectedAt: string;
      normalizedPayload: Record<string, unknown>;
      schemaVersion: 'cyber.security-evidence.sentrycode.v1';
    };
  };
}

function contextValue(config: ConsumerConfig, key: string): string {
  const value = config.context[key] ?? '';
  if (!value.trim()) throw new Error(`Cyber consumer context.${key} is required`);
  return value.trim();
}

function assuranceContext(config: ConsumerConfig): 'MANUFACTURER' | 'DEPLOYMENT' {
  const value = (config.context.assuranceContext ?? 'MANUFACTURER').trim().toUpperCase();
  if (value !== 'MANUFACTURER' && value !== 'DEPLOYMENT') {
    throw new Error('Cyber consumer context.assuranceContext must be MANUFACTURER or DEPLOYMENT');
  }
  return value;
}

export class CyberConsumerAdapter implements ConsumerAdapter<CyberSecurityEvidenceInvocation> {
  readonly adapterId = CYBER_CONSUMER_ADAPTER_ID;
  readonly contractVersion = CYBER_CONSUMER_ADAPTER_CONTRACT_VERSION;

  requirements(config: ConsumerConfig): ConsumerCapabilityRequirements {
    return configuredRequirements(config);
  }

  deliveryMessageId(envelope: TechnicalFindingEnvelope, _mapped: CyberSecurityEvidenceInvocation, _config: ConsumerConfig): string {
    return envelope.messageId;
  }

  createPublisher(config: ConsumerConfig, token: string): ConsumerPayloadPublisher {
    return new HttpJsonConsumerPublisher(config.endpoint, token, config.timeoutMs);
  }

  mapFinding(envelope: TechnicalFindingEnvelope, config: ConsumerConfig): CyberSecurityEvidenceInvocation {
    const buildId = contextValue(config, 'buildId');
    const subjectContext = assuranceContext(config);
    const evidenceId = stableId('cyber-evidence', `${config.consumerId}|${buildId}|${envelope.messageId}`);
    const receiptId = stableId('cyber-receipt', `${config.consumerId}|${evidenceId}`);
    const provider = {
      providerType: 'QUILONS_NATIVE' as const,
      providerId: 'quilons-sentrycode' as const,
      providerVersion: envelope.source.version
    };

    return {
      contractVersion: 'quilons.service-invocation.v1',
      tenantId: envelope.tenant,
      appId: 'quilons-sentrycode',
      operation: 'cyber.security-evidence.ingest',
      actor: {
        actorType: 'SERVICE',
        actorId: 'quilons-sentrycode',
        permissions: ['cyber.security-evidence.ingest']
      },
      input: {
        receiptId,
        submission: {
          contractVersion: 'cyber.security-evidence.v1',
          capabilityId: 'cyber.security-evidence',
          capabilityVersion: 'v1',
          tenantId: envelope.tenant,
          evidenceId,
          evidenceType: 'EXTERNAL_TOOL_RESULT',
          subject: { subjectType: 'BUILD', subjectId: buildId, assuranceContext: subjectContext },
          assuranceContext: subjectContext,
          provider,
          provenance: {
            provider,
            source: {
              sourceKind: 'scanner_result',
              sourceReferenceId: envelope.messageId,
              sourceLabel: envelope.finding.scanner
            },
            normalized: true
          },
          observedAt: envelope.timestamps.detectedAt,
          collectedAt: envelope.timestamps.producedAt,
          normalizedPayload: {
            sentryCodeContractVersion: envelope.contractVersion,
            project: envelope.project,
            repository: envelope.repository,
            finding: envelope.finding,
            sourceRevision: envelope.sourceRevision,
            evidenceReference: envelope.evidenceReference,
            correlation: envelope.correlation,
            timestamps: envelope.timestamps
          },
          schemaVersion: 'cyber.security-evidence.sentrycode.v1'
        }
      }
    };
  }
}
