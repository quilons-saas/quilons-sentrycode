import type {
  AppliedFinding,
  EffectivePolicy,
  Finding,
  PolicyContext,
  PolicyResult,
  ScannerResult,
  Severity,
  SentryCodeConfig,
  Waiver
} from '../core/types.js';
import { findApplicableWaiver } from './waivers.js';

const severities: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function evaluatePolicy(
  config: SentryCodeConfig,
  scannerResults: ScannerResult[],
  waivers: Waiver[],
  now: Date,
  effectivePolicy?: EffectivePolicy,
  context?: PolicyContext
): PolicyResult {
  const policy = effectivePolicy ?? {
    sourceDocuments: [],
    failOn: config.policy.failOn,
    warnOn: config.policy.warnOn,
    requiredScanners: config.policy.requiredScanners,
    scannerFailureModes: config.policy.scannerFailureModes,
    lockedFields: [],
    fingerprint: 'config-only'
  };
  const policyContext: PolicyContext = context ?? { repository: 'unknown' };
  const audit: PolicyResult['audit'] = [{
    event: 'policy.resolved',
    at: now.toISOString(),
    policyFingerprint: policy.fingerprint,
    policySources: policy.sourceDocuments.map((item) => `${item.id}@${item.version}`)
  }];

  const presentScanners = new Set(scannerResults.filter((result) => (result.status ?? 'success') !== 'skipped').map((result) => result.scanner));
  const missing = policy.requiredScanners.filter((id) => !presentScanners.has(id));
  const reasons: string[] = [];
  let forcedDecision: 'FAIL' | 'WARN' | undefined;

  if (missing.length) {
    forcedDecision = 'FAIL';
    reasons.push(`Required scanner(s) did not run: ${missing.join(', ')}`);
  }

  for (const result of scannerResults) {
    if ((result.status ?? 'success') !== 'failed') continue;
    const mode = policy.scannerFailureModes[result.scanner] ?? (policy.requiredScanners.includes(result.scanner) ? 'fail' : 'warn');
    if (mode === 'fail') {
      forcedDecision = 'FAIL';
      reasons.push(`Scanner ${result.scanner} failed closed: ${result.error ?? 'unknown scanner error'}`);
    } else if (mode === 'warn' && forcedDecision !== 'FAIL') {
      forcedDecision = 'WARN';
      reasons.push(`Scanner ${result.scanner} failed but policy permits warning: ${result.error ?? 'unknown scanner error'}`);
    }
  }

  const applied: AppliedFinding[] = scannerResults
    .flatMap((result) => result.findings)
    .map((finding) => {
      const waiver = findApplicableWaiver({
        finding,
        waivers,
        config,
        context: policyContext,
        now,
        audit
      });
      return waiver ? { finding, waived: true, waiverId: waiver.id } : { finding, waived: false };
    });

  const counts = Object.fromEntries(
    severities.map((severity) => [
      severity,
      applied.filter((item) => !item.waived && item.finding.severity === severity).length
    ])
  ) as Record<Severity, number>;
  const blocking = applied.filter((item) => !item.waived && policy.failOn.includes(item.finding.severity));
  const warnings = applied.filter((item) => !item.waived && policy.warnOn.includes(item.finding.severity));

  let decision: PolicyResult['decision'] = blocking.length ? 'FAIL' : warnings.length ? 'WARN' : 'PASS';
  if (forcedDecision === 'FAIL') decision = 'FAIL';
  else if (forcedDecision === 'WARN' && decision === 'PASS') decision = 'WARN';

  if (blocking.length) reasons.push(`${blocking.length} unwaived finding(s) violate blocking policy`);
  else if (warnings.length) reasons.push(`${warnings.length} warning finding(s)`);
  else if (!reasons.length) reasons.push('No unwaived findings violate policy');

  return {
    decision,
    findings: applied,
    counts,
    waivedCount: applied.filter((item) => item.waived).length,
    reasons,
    effectivePolicy: policy,
    audit
  };
}
