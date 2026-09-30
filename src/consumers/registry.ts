import type { ConsumerConfig, SentryCodeConfig } from '../core/types.js';
import type { ConsumerAdapter, ConsumerCapabilityRequirements } from './adapter.js';
import { CraConsumerAdapter, CRA_CONSUMER_ADAPTER_ID } from './cra-adapter.js';
import { CyberConsumerAdapter, CYBER_CONSUMER_ADAPTER_ID } from './cyber-adapter.js';

export interface ConsumerAdapterStatus {
  consumer: ConsumerConfig;
  available: boolean;
  adapterContractVersion?: string;
  requirements: ConsumerCapabilityRequirements;
}

const ADAPTERS: Record<string, ConsumerAdapter> = {
  [CRA_CONSUMER_ADAPTER_ID]: new CraConsumerAdapter(),
  [CYBER_CONSUMER_ADAPTER_ID]: new CyberConsumerAdapter()
};

function legacyCraConsumer(config: SentryCodeConfig): ConsumerConfig | null {
  if (!config.craReporting.enabled) return null;
  return {
    consumerId: 'cra',
    adapter: CRA_CONSUMER_ADAPTER_ID,
    enabled: true,
    endpoint: config.craReporting.endpoint,
    tokenEnv: config.craReporting.tokenEnv,
    timeoutMs: config.craReporting.timeoutMs,
    maxAttempts: config.craReporting.maxAttempts,
    retryDelayMs: config.craReporting.retryDelayMs,
    scanProfile: {
      requiredScanners: [],
      evidenceTypes: [],
      severities: [...config.craReporting.severities],
      findingTypes: [...config.craReporting.findingTypes]
    },
    context: { assessmentId: config.craReporting.assessmentId }
  };
}

/**
 * Lists configured consumers without activating the new delivery path. During
 * Slice 1 the existing CRA runtime remains authoritative for delivery; this
 * registry is the compatibility foundation used by later migration slices.
 */
export function listConfiguredConsumers(config: SentryCodeConfig): ConsumerConfig[] {
  const explicit = config.consumers.map((consumer) => structuredClone(consumer));
  if (explicit.some((consumer) => consumer.consumerId === 'cra')) return explicit;
  const legacy = legacyCraConsumer(config);
  return legacy ? [...explicit, legacy] : explicit;
}

export function getConsumerAdapter(adapterId: string): ConsumerAdapter | undefined {
  return ADAPTERS[adapterId];
}

export function describeConsumerAdapters(config: SentryCodeConfig): ConsumerAdapterStatus[] {
  return listConfiguredConsumers(config).map((consumer) => {
    const adapter = getConsumerAdapter(consumer.adapter);
    return {
      consumer,
      available: Boolean(adapter),
      ...(adapter ? { adapterContractVersion: adapter.contractVersion } : {}),
      requirements: adapter ? adapter.requirements(consumer) : {
        requiredScanners: [...consumer.scanProfile.requiredScanners],
        evidenceTypes: [...consumer.scanProfile.evidenceTypes],
        severities: [...consumer.scanProfile.severities],
        findingTypes: [...consumer.scanProfile.findingTypes]
      }
    };
  });
}

export function consumerRequiredScanners(config: SentryCodeConfig): string[] {
  const required = new Set<string>();
  for (const status of describeConsumerAdapters(config)) {
    if (!status.consumer.enabled || !status.available) continue;
    for (const scanner of status.requirements.requiredScanners) required.add(scanner);
  }
  return [...required].sort();
}

export function requiredScannerUnion(config: SentryCodeConfig): string[] {
  return [...new Set([...config.policy.requiredScanners, ...consumerRequiredScanners(config)])].sort();
}
