import type { AppliedFinding, ConsumerConfig, ScanReport } from '../core/types.js';

function normalized(values: string[]): Set<string> {
  return new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean));
}

export function isConsumerFindingSelected(
  report: ScanReport,
  appliedFinding: AppliedFinding,
  config: ConsumerConfig
): boolean {
  const severities = new Set(config.scanProfile.severities);
  if (severities.size > 0 && !severities.has(appliedFinding.finding.severity)) return false;

  const findingTypes = normalized(config.scanProfile.findingTypes);
  if (findingTypes.size > 0 && !findingTypes.has(appliedFinding.finding.type.trim().toLowerCase())) return false;

  const evidenceTypes = normalized(config.scanProfile.evidenceTypes);
  if (evidenceTypes.size > 0) {
    const linkedEvidenceTypes = new Set(
      report.evidence
        .filter((item) => item.findingIds.includes(appliedFinding.finding.id))
        .map((item) => item.type.trim().toLowerCase())
    );
    if (![...evidenceTypes].some((type) => linkedEvidenceTypes.has(type))) return false;
  }

  return true;
}

export function selectConsumerFindings(report: ScanReport, config: ConsumerConfig): AppliedFinding[] {
  return report.policy.findings.filter((item) => isConsumerFindingSelected(report, item, config));
}
