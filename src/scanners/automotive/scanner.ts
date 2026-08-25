import type { Finding, ScannerContext, ScannerPlugin, ScannerResult, Severity } from '../../core/types.js';
import { SCHEMA_VERSION } from '../../core/types.js';
import { stableId } from '../../utils/hash.js';
import { loadAutomotiveImports } from '../../automotive/imports.js';
import { loadAutomotiveDeviations, matchingDeviation } from '../../automotive/deviations.js';
import { automotiveAlignmentEvidence } from '../../automotive/evidence.js';

function normalizeSeverity(value: unknown): Severity {
  if (value === 'critical' || value === 'high' || value === 'medium' || value === 'low' || value === 'info') return value;
  if (value === 'error') return 'high';
  if (value === 'warning') return 'medium';
  return 'low';
}

export class AutomotiveScanner implements ScannerPlugin {
  readonly id = 'automotive';
  readonly version = '1.0.0';

  async scan(context: ScannerContext): Promise<ScannerResult> {
    const started = performance.now();
    if (!context.config.automotive.enabled) return { scanner: this.id, findings: [], evidence: [], durationMs: Math.round(performance.now() - started), status: 'skipped' };
    const imports = await loadAutomotiveImports(context.repository.root, context.config.automotive.importDirectory);
    if (!imports.length && context.config.automotive.requireInputs) throw new Error(`automotive scanning enabled but no analyzer imports found in ${context.config.automotive.importDirectory}`);
    const deviations = await loadAutomotiveDeviations(context.repository.root, context.config.automotive.deviationsFile);
    const now = context.now();
    const findings: Finding[] = [];
    const deviationEvidenceIds: string[] = [];

    for (const imported of imports) {
      if (!context.config.automotive.acceptedStandards.includes(imported.document.standard)) continue;
      for (const external of imported.document.findings) {
        const rawFingerprint = external.fingerprint ?? stableId('automotive', `${imported.document.standard}|${external.ruleId}|${external.path ?? ''}|${external.line ?? 0}|${external.message}`);
        const deviation = matchingDeviation({ standard: imported.document.standard, ruleId: external.ruleId, fingerprint: rawFingerprint, ...(external.path ? { path: external.path } : {}), deviations, requireApproval: context.config.automotive.requireDeviationApproval, now });
        if (deviation) {
          deviationEvidenceIds.push(deviation.id);
          continue;
        }
        findings.push({
          schemaVersion: SCHEMA_VERSION,
          id: stableId('finding', `${context.repository.commitSha}|automotive|${rawFingerprint}`),
          type: 'automotive.rule.violation',
          scanner: this.id,
          ruleId: `${imported.document.standard}:${external.ruleId}`,
          title: `${imported.document.standard.toUpperCase()} rule finding`,
          description: external.message,
          severity: normalizeSeverity(external.severity),
          ...(external.path ? { location: { path: external.path, ...(external.line ? { line: external.line } : {}), ...(external.column ? { column: external.column } : {}) } } : {}),
          fingerprint: rawFingerprint,
          remediation: 'Review the originating automotive coding-rule finding and either correct the code or record an approved engineering deviation.',
          detectedAt: now.toISOString(),
          metadata: {
            automotiveStandard: imported.document.standard,
            sourceTool: imported.document.tool.name,
            sourceToolVersion: imported.document.tool.version ?? '',
            sourceDocument: imported.source,
            tags: (external.tags ?? []).join(',')
          }
        });
      }
    }

    const generatedAt = now.toISOString();
    const evidence = automotiveAlignmentEvidence(context.repository, findings, generatedAt, context.config.automotive.evidenceTargets);
    evidence.unshift({
      schemaVersion: SCHEMA_VERSION,
      id: stableId('evidence', `${context.repository.commitSha}|automotive.rule.check|${generatedAt}`),
      type: 'automotive.rule.check',
      scanner: this.id,
      repository: context.repository.repository,
      commitSha: context.repository.commitSha,
      branch: context.repository.branch,
      generatedAt,
      findingIds: findings.map((finding) => finding.id),
      metadata: {
        importCount: imports.length,
        findingCount: findings.length,
        deviationCount: deviationEvidenceIds.length,
        standards: context.config.automotive.acceptedStandards.join(','),
        ruleContentEmbedded: false
      }
    });
    if (deviationEvidenceIds.length) evidence.push({
      schemaVersion: SCHEMA_VERSION,
      id: stableId('evidence', `${context.repository.commitSha}|automotive.deviation|${generatedAt}|${deviationEvidenceIds.sort().join(',')}`),
      type: 'automotive.deviation',
      scanner: this.id,
      repository: context.repository.repository,
      commitSha: context.repository.commitSha,
      branch: context.repository.branch,
      generatedAt,
      findingIds: [],
      metadata: { deviationCount: deviationEvidenceIds.length, deviationIds: deviationEvidenceIds.sort().join(',') }
    });
    return { scanner: this.id, findings, evidence, durationMs: Math.round(performance.now() - started), status: 'success' };
  }
}
