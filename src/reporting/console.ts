import type { ScanReport } from '../core/types.js';

export function renderConsole(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(`SentryCode ${report.policy.decision}`);
  lines.push(`Repository: ${report.repository.repository}`);
  lines.push(`Commit: ${report.repository.commitSha ?? 'unavailable'}${report.repository.isDirty ? ' (working tree dirty)' : ''}`);
  if (report.execution) {
    lines.push(`Scan mode: ${report.execution.mode}${report.execution.baseRef ? ` (${report.execution.baseRef}...${report.execution.headRef ?? 'HEAD'})` : ''}`);
    if (report.execution.mode === 'incremental') lines.push(`Changed files: ${report.execution.changedFiles.length}`);
    if (report.execution.ci) lines.push(`CI: ${report.execution.ci.provider}${report.execution.ci.pullRequest ? ' (pull request)' : ''}`);
  }
  lines.push('');

  const failedScanners = report.scanners.filter((item) => (item.status ?? 'success') === 'failed');
  for (const scanner of failedScanners) lines.push(`[SCANNER FAILED] ${scanner.scanner}: ${scanner.error ?? 'unknown error'}`);
  if (failedScanners.length) lines.push('');

  const active = report.policy.findings.filter((item) => !item.waived);
  if (!active.length) {
    lines.push('No active findings.');
  } else {
    for (const item of active) {
      const finding = item.finding;
      const location = finding.location ? `${finding.location.path}:${finding.location.line ?? 1}` : 'repository';
      lines.push(`[${finding.severity.toUpperCase()}] ${finding.ruleId} ${location}`);
      lines.push(`  ${finding.title}`);
      if (finding.metadata?.preview) lines.push(`  Match: ${String(finding.metadata.preview)}`);
    }
  }

  if (report.policy.waivedCount) lines.push(`\nWaived findings: ${report.policy.waivedCount}`);
  lines.push(`\nDecision: ${report.policy.decision}`);
  for (const reason of report.policy.reasons) lines.push(`- ${reason}`);
  return lines.join('\n');
}
