import { randomUUID } from 'node:crypto';
import type { EvidenceRecord, PolicyContext, ScanExecutionContext, ScanReport, ScannerPlugin, ScannerResult, SentryCodeConfig } from './types.js';
import type { RepositoryContext } from './types.js';
import { SCHEMA_VERSION } from './types.js';
import { evaluatePolicy } from '../policy/evaluate.js';
import { loadWaivers } from '../policy/waivers.js';
import { loadPolicyDocuments } from '../policy/documents.js';
import { resolvePolicy } from '../policy/resolve.js';
import { evaluateOpa } from '../policy/opa.js';
import { stableId } from '../utils/hash.js';

const RANK = { PASS: 0, WARN: 1, FAIL: 2 } as const;

function stricter<T extends keyof typeof RANK>(a: T, b: T): T {
  return RANK[a] >= RANK[b] ? a : b;
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
    try {
      const timeoutMs = args.config.incremental.scannerTimeoutMs;
      const scan = scanner.scan({
        repository: args.repository,
        config: args.config,
        now,
        ...(args.execution ? { execution: args.execution } : {})
      });
      let result: ScannerResult;
      if (timeoutMs > 0) {
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          result = await Promise.race([
            scan,
            new Promise<never>((_, reject) => {
              timer = setTimeout(() => reject(new Error(`scanner timed out after ${timeoutMs}ms`)), timeoutMs);
            })
          ]);
        } finally {
          if (timer) clearTimeout(timer);
        }
      } else {
        result = await scan;
      }
      return { ...result, status: result.status ?? 'success' };
    } catch (error) {
      return {
        scanner: scanner.id,
        findings: [],
        evidence: [],
        durationMs: Math.round(performance.now() - started),
        status: 'failed',
        error: (error as Error).message
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
  const effectivePolicy = resolvePolicy(args.config, documents);
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
      opaEnabled: args.config.policy.opa.enabled
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
    evidence: [...scannerResults.flatMap((result) => result.evidence), policyEvidence],
    ...(args.execution ? { execution: args.execution } : {})
  };
}
