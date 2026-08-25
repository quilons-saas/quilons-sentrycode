import type { CiContext, Finding, ScanReport } from '../core/types.js';

function esc(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

export function renderCiAnnotations(report: ScanReport, ci: CiContext): string {
  const active = report.policy.findings.filter((item) => !item.waived).map((item) => item.finding);
  if (!active.length) return '';
  if (ci.provider === 'github') {
    return active.map((f) => {
      const level = ['high','critical'].includes(f.severity) ? 'error' : 'warning';
      const props = f.location ? `file=${esc(f.location.path)},line=${f.location.line ?? 1}` : '';
      return `::${level}${props ? ` ${props}` : ''}::${esc(`${f.ruleId}: ${f.title}`)}`;
    }).join('\n') + '\n';
  }
  if (ci.provider === 'azure-devops') {
    return active.map((f) => {
      const type = ['high','critical'].includes(f.severity) ? 'error' : 'warning';
      const sourcepath = f.location?.path ? `;sourcepath=${esc(f.location.path)};linenumber=${f.location.line ?? 1}` : '';
      return `##vso[task.logissue type=${type}${sourcepath}]${esc(`${f.ruleId}: ${f.title}`)}`;
    }).join('\n') + '\n';
  }
  if (ci.provider === 'gitlab' || ci.provider === 'jenkins' || ci.provider === 'generic') {
    return active.map((f) => `[SENTRYCODE:${f.severity.toUpperCase()}] ${f.location?.path ?? 'repository'} ${f.ruleId}: ${f.title}`).join('\n') + '\n';
  }
  return '';
}
