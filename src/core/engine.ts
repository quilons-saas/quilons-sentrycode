import { randomUUID } from 'node:crypto';
import type { EvidenceRecord, PolicyContext, ScanExecutionContext, ScanReport, ScannerFailure, ScannerPlugin, ScannerResult, SentryCodeConfig } from './types.js';
import type { RepositoryContext } from './types.js';
import { SCHEMA_VERSION } from './types.js';
import { evaluatePolicy } from '../policy/evaluate.js';
import { loadWaivers } from '../policy/waivers.js';
import { loadPolicyDocuments } from '../policy/documents.js';
import { resolvePolicy } from '../policy/resolve.js';
import { evaluateOpa } from '../policy/opa.js';
import { stableId } from '../utils/hash.js';
import { consumerRequiredScanners, describeConsumerAdapters } from '../consumers/registry.js';

const RANK = { PASS: 0, WARN: 1, FAIL: 2 } as const;

function stricter<T extends keyof typeof RANK>(a: T, b: T): T {
  return RANK[a] >= RANK[b] ? a : b;
}

function classifyScannerFailure(message: string): ScannerFailure {
  const normalized = message.trim() || 'unknown scanner error';
  const code = normalized.match(/\b(SCANNER_[A-Z_]+)\b/)?.[1];

  let category: ScannerFailure['category'] = 'unknown';

  if (/(?:governed\s+)?intelligence|vulnerability database|grype[- ]db|rules identity|freshness|stale|intelligence digest|intelligence timestamp/i.test(normalized)) {
    category = 'intelligence';
  } else if (/no runner profile configured|runner credential is unavailable|runner tenant\/project scope is not configured|runner endpoint must|runner token is required|runner timeout must be positive|profile.+(?:missing|not found|unavailable|invalid)|undeclared asset/i.test(normalized)) {
    category = 'provisioning';
  } else if (/SCANNER_LAUNCH_FAILED|unable to invoke container runtime|container creation failed|container start failed|runner request failed|fetch failed|ECONNREFUSED|ENOTFOUND|runner request timed out/i.test(normalized)) {
    category = 'runner_startup';
  } else if (/SCANNER_EXECUTION_FAILED|SCANNER_TIMEOUT|SCANNER_OUTPUT_|SCANNER_CLEANUP_UNCONFIRMED|supply-chain execution failed|runner artifact integrity failure|runner produced (?:empty|invalid)|execution did not complete|scanner timed out/i.test(normalized)) {
    category = 'scanner_execution';
  } else if (/coverage incomplete|unresolved component|component relationship.+unresolved/i.test(normalized)) {
    category = 'coverage';
  }

  return {
    category,
    ...(code ? { code } : {}),
    message: normalized
  };
}

export async function runScan(args: {
  repository: RepositoryContext;
  config: SentryCodeConfig;
  scanners: ScannerPlugin[];
  now?: () => Date;
  service?: string;
  execution?: ScanExecutionContext;
}): Promise<ScanReport> {
  const now = args.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const runOne = async (scanner: ScannerPlugin): Promise<ScannerResult> => {
    const started = performance.now();
    const controller = new AbortController();
    try {
      const timeoutMs = args.config.incremental.scannerTimeoutMs;
      const scan = scanner.scan({
        repository: args.repository,
        config: args.config,
        now,
        ...(args.execution ? { execution: args.execution } : {}),
        signal: controller.signal
      });
      let result: ScannerResult;
      if (timeoutMs > 0) {
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          result = await Promise.race([
            scan,
            new Promise<never>((_, reject) => {
              timer = setTimeout(() => {
                const error = new Error(`scanner timed out after ${timeoutMs}ms`);
                controller.abort(error);
                reject(error);
              }, timeoutMs);
            })
          ]);
        } finally {
          if (timer) clearTimeout(timer);
        }
      } else {
        result = await scan;
      }
      const normalized = { ...result, status: result.status ?? 'success' };
      if (normalized.status === 'failed' && !normalized.failure) {
        const failure = classifyScannerFailure(normalized.error ?? 'unknown scanner error');
        return { ...normalized, failure };
      }
      return normalized;
    } catch (error) {
      if (!controller.signal.aborted) controller.abort(error);
      const message = error instanceof Error ? error.message : String(error);
      return {
        scanner: scanner.id,
        findings: [],
        evidence: [],
        durationMs: Math.round(performance.now() - started),
        status: 'failed',
        error: message,
        failure: classifyScannerFailure(message)
      };
    }
  };
  // Run independent scanners concurrently, while preserving the configured scanner order in results.
  const scannerResults: ScannerResult[] = await Promise.all(args.scanners.map((scanner) => runOne(scanner)));

  const policyContext: PolicyContext = {
    repository: args.repository.repository,
    ...(args.config.policy.context.tenant ? { tenant: args.config.policy.context.tenant } : {}),
    ...(args.config.policy.context.project ? { project: args.config.policy.context.project } : {}),
    ...((args.service ?? args.config.policy.context.service) ? { service: args.service ?? args.config.policy.context.service } : {})
  };
  const documents = await loadPolicyDocuments(args.repository.root, args.config.policy.directory, policyContext, now());
  const consumerScanners = consumerRequiredScanners(args.config);
  const consumerPlan = describeConsumerAdapters(args.config)
    .filter((status) => status.consumer.enabled)
    .map((status) => ({
      consumerId: status.consumer.consumerId,
      adapter: status.consumer.adapter,
      adapterAvailable: status.available,
      adapterContractVersion: status.adapterContractVersion ?? null,
      requiredScanners: [...status.requirements.requiredScanners].sort(),
      evidenceTypes: [...status.requirements.evidenceTypes].sort()
    }))
    .sort((a, b) => a.consumerId.localeCompare(b.consumerId));
  const managedProfileScanners = args.config.execution.runner.enabled
    ? Object.keys(args.config.execution.runner.profiles).filter((scannerId) => Boolean(args.config.execution.runner.profiles[scannerId]))
    : [];
  const requiredScannersFloor = [...new Set([...consumerScanners, ...managedProfileScanners])].sort();
  const effectivePolicy = resolvePolicy(args.config, documents, { requiredScannersFloor });
  const waivers = await loadWaivers(args.repository.root, args.config.waivers.file);
  const policy = evaluatePolicy(args.config, scannerResults, waivers, now(), effectivePolicy, policyContext);

  const opaDecision = await evaluateOpa(args.repository.root, args.config, {
    repository: args.repository,
    scanners: scannerResults,
    effectivePolicy,
    builtinDecision: policy.decision
  });
  if (opaDecision) {
    const combined = stricter(policy.decision, opaDecision);
    policy.reasons.push(`OPA decision: ${opaDecision}; combined enforcement keeps stricter decision ${combined}`);
    policy.decision = combined;
  }

  const completedAt = now().toISOString();
  const scannerFailureEvidence: EvidenceRecord[] = scannerResults
    .filter((result) => result.status === 'failed')
    .map((result) => {
      const failure = result.failure ?? classifyScannerFailure(result.error ?? 'unknown scanner error');
      return {
        schemaVersion: SCHEMA_VERSION,
        id: stableId('evidence', `${args.repository.commitSha}|scanner.failure|${result.scanner}|${failure.category}|${failure.code ?? ''}|${failure.message}`),
        type: 'scanner.failure',
        scanner: result.scanner,
        repository: args.repository.repository,
        commitSha: args.repository.commitSha,
        branch: args.repository.branch,
        generatedAt: completedAt,
        findingIds: [],
        metadata: {
          category: failure.category,
          code: failure.code ?? null,
          error: failure.message,
          scannerStatus: 'failed'
        }
      };
    });

  const policyEvidence: EvidenceRecord = {
    schemaVersion: SCHEMA_VERSION,
    id: stableId('evidence', `${args.repository.commitSha}|policy.eval|${completedAt}|${effectivePolicy.fingerprint}`),
    type: 'policy.eval',
    scanner: 'policy',
    repository: args.repository.repository,
    commitSha: args.repository.commitSha,
    branch: args.repository.branch,
    generatedAt: completedAt,
    findingIds: policy.findings.map((item) => item.finding.id),
    metadata: {
      decision: policy.decision,
      policyFingerprint: effectivePolicy.fingerprint,
      policyDocumentCount: effectivePolicy.sourceDocuments.length,
      waivedCount: policy.waivedCount,
      opaEnabled: args.config.policy.opa.enabled,
      consumerRequiredScanners: consumerScanners.join(','),
      managedProfileRequiredScanners: managedProfileScanners.join(','),
      requiredScannerFloor: requiredScannersFloor.join(','),
      scannerFailureCount: scannerFailureEvidence.length,
      scannerFailureCategories: [...new Set(scannerFailureEvidence.map((item) => String(item.metadata.category)))].sort().join(','),
      consumerPlan: JSON.stringify(consumerPlan)
    }
  };

  return {
    schemaVersion: SCHEMA_VERSION,
    runId: randomUUID(),
    startedAt,
    completedAt,
    repository: args.repository,
    scanners: scannerResults,
    policy,
    evidence: [...scannerResults.flatMap((result) => result.evidence), ...scannerFailureEvidence, policyEvidence],
    ...(args.execution ? { execution: args.execution } : {})
  };
}
