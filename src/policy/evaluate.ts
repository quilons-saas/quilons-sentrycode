import type { AppliedFinding, Finding, PolicyResult, ScannerResult, Severity, SentryCodeConfig, Waiver } from '../core/types.js';

const severities: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

function waiverFor(finding: Finding, waivers: Waiver[], now: Date): Waiver | undefined {
  return waivers.find((waiver) => {
    if (new Date(waiver.expiresAt) <= now) return false;
    if (waiver.fingerprint && waiver.fingerprint !== finding.fingerprint) return false;
    if (waiver.ruleId && waiver.ruleId !== finding.ruleId) return false;
    if (waiver.path && waiver.path !== finding.location?.path) return false;
    return Boolean(waiver.fingerprint || waiver.ruleId || waiver.path);
  });
}

export function evaluatePolicy(config: SentryCodeConfig, scannerResults: ScannerResult[], waivers: Waiver[], now: Date): PolicyResult {
  const presentScanners = new Set(scannerResults.map((result) => result.scanner));
  const missing = config.policy.requiredScanners.filter((id) => !presentScanners.has(id));
  if (missing.length) {
    return {
      decision: 'FAIL',
      findings: [],
      counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
      waivedCount: 0,
      reasons: [`Required scanner(s) did not run: ${missing.join(', ')}`]
    };
  }

  const applied: AppliedFinding[] = scannerResults.flatMap((result) => result.findings).map((finding) => {
    const waiver = waiverFor(finding, waivers, now);
    return waiver ? { finding, waived: true, waiverId: waiver.id } : { finding, waived: false };
  });

  const counts = Object.fromEntries(severities.map((severity) => [severity, applied.filter((item) => !item.waived && item.finding.severity === severity).length])) as Record<Severity, number>;
  const blocking = applied.filter((item) => !item.waived && config.policy.failOn.includes(item.finding.severity));
  const warnings = applied.filter((item) => !item.waived && config.policy.warnOn.includes(item.finding.severity));
  const decision = blocking.length ? 'FAIL' : warnings.length ? 'WARN' : 'PASS';

  return {
    decision,
    findings: applied,
    counts,
    waivedCount: applied.filter((item) => item.waived).length,
    reasons: blocking.length ? [`${blocking.length} unwaived finding(s) violate blocking policy`] : warnings.length ? [`${warnings.length} warning finding(s)`] : ['No unwaived findings violate policy']
  };
}
