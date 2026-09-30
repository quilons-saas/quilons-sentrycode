import type { ConsumerConfig, Severity } from '../core/types.js';
import type { TechnicalFindingEnvelope } from './contracts.js';
import type { ConsumerPayloadPublisher } from './delivery.js';

export interface ConsumerCapabilityRequirements {
  requiredScanners: string[];
  evidenceTypes: string[];
  severities: Severity[];
  findingTypes: string[];
}

export interface ConsumerAdapter<TMapped = unknown> {
  readonly adapterId: string;
  readonly contractVersion: string;
  requirements(config: ConsumerConfig): ConsumerCapabilityRequirements;
  mapFinding(envelope: TechnicalFindingEnvelope, config: ConsumerConfig): TMapped;
  deliveryMessageId(envelope: TechnicalFindingEnvelope, mapped: TMapped, config: ConsumerConfig): string;
  createPublisher(config: ConsumerConfig, token: string): ConsumerPayloadPublisher;
}

export function configuredRequirements(config: ConsumerConfig): ConsumerCapabilityRequirements {
  return {
    requiredScanners: [...config.scanProfile.requiredScanners],
    evidenceTypes: [...config.scanProfile.evidenceTypes],
    severities: [...config.scanProfile.severities],
    findingTypes: [...config.scanProfile.findingTypes]
  };
}
