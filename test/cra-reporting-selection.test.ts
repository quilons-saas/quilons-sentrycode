import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCraFindingReports, isCraReportableFinding, selectCraReportableFindings } from '../src/compliance/cra-reporting.js';
import type { AppliedFinding, EvidenceRecord, Finding, ScanReport, Severity } from '../src/core/types.js';

function finding(id: string, type: string, severity: Severity, waived = false): AppliedFinding {
  const value: Finding = {
    schemaVersion: '1.0.0',
    id,
    type,
    scanner: type === 'secret' ? 'secrets' : 'dependencies',
    ruleId: `${type}.${id}`,
    title: `${severity} ${type}`,
    description: `Technical ${type} condition`,
    severity,
    fingerprint: `fp-${id}`,
    detectedAt: '2026-08-31T04:00:00.000Z'
  };
  return waived ? { finding: value, waived: true, waiverId: `waiver-${id}` } : { finding: value, waived: false };
}

function evidence(id: string, findingId: string): EvidenceRecord {
  return {
    schemaVersion: '1.0.0', id, type: 'test.evidence', scanner: 'test', repository: 'payments', commitSha: 'abc123', branch: 'main',
    generatedAt: '2026-08-31T04:00:01.000Z', findingIds: [findingId], metadata: {}
  };
}

function report(findings: AppliedFinding[], evidenceRecords = findings.map((item, index) => evidence(`e-${index + 1}`, item.finding.id))): ScanReport {
  return {
    schemaVersion: '1.0.0', runId: 'run-materiality', startedAt: '2026-08-31T04:00:00.000Z', completedAt: '2026-08-31T04:00:02.000Z',
    repository: { root: '/repo', repository: 'payments', commitSha: 'abc123', branch: 'main', isDirty: false }, scanners: [],
    policy: {
      decision: 'FAIL', findings,
      counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, waivedCount: findings.filter((item) => item.waived).length,
      reasons: [], audit: []
    },
    evidence: evidenceRecords
  };
}

test('CRA materiality uses configured severity and all finding types when type filter is empty', () => {
  const highVulnerability = finding('f1', 'vulnerability', 'high');
  const criticalSecret = finding('f2', 'secret', 'critical');
  const mediumSast = finding('f3', 'sast', 'medium');
  const selected = selectCraReportableFindings(report([highVulnerability, criticalSecret, mediumSast]), {
    severities: ['high', 'critical'], findingTypes: []
  });
  assert.deepEqual(selected.map((item) => item.finding.id), ['f1', 'f2']);
});

test('CRA materiality finding-type filter is case-insensitive and additive to severity', () => {
  const vulnerability = finding('f1', 'vulnerability', 'critical');
  const secret = finding('f2', 'secret', 'critical');
  const selected = selectCraReportableFindings(report([vulnerability, secret]), {
    severities: ['critical'], findingTypes: [' VULNERABILITY ']
  });
  assert.deepEqual(selected.map((item) => item.finding.id), ['f1']);
});

test('empty CRA severity set selects nothing', () => {
  assert.equal(isCraReportableFinding(finding('f1', 'vulnerability', 'critical'), { severities: [], findingTypes: [] }), false);
});

test('waived material findings remain reportable technical facts with waiver status', () => {
  const waived = finding('f1', 'vulnerability', 'critical', true);
  const reports = buildCraFindingReports({
    identity: { tenant: 'acme', project: 'payments-platform' },
    report: report([waived]), productVersion: '0.1.0', materiality: { severities: ['critical'], findingTypes: ['vulnerability'] },
    reportedAt: '2026-08-31T04:00:03.000Z'
  });
  assert.equal(reports.length, 1);
  assert.equal(reports[0]!.finding.status, 'waived');
  assert.equal(reports[0]!.finding.waiverId, 'waiver-f1');
});

test('CRA report generation creates only selected reports and preserves evidence references', () => {
  const vulnerability = finding('f1', 'vulnerability', 'critical');
  const secret = finding('f2', 'secret', 'medium');
  const reports = buildCraFindingReports({
    identity: { tenant: 'acme', project: 'payments-platform' }, report: report([vulnerability, secret]), productVersion: '0.1.0',
    materiality: { severities: ['high', 'critical'], findingTypes: [] }, reportedAt: '2026-08-31T04:00:03.000Z'
  });
  assert.equal(reports.length, 1);
  assert.equal(reports[0]!.finding.id, 'f1');
  assert.deepEqual(reports[0]!.evidenceReference.evidenceIds, ['e-1']);
  assert.equal('craViolation' in reports[0]!, false);
  assert.equal('complianceStatus' in reports[0]!, false);
});

test('CRA report generation fails closed when a selected material finding lacks authoritative evidence', () => {
  const vulnerability = finding('f1', 'vulnerability', 'critical');
  assert.throws(() => buildCraFindingReports({
    identity: { tenant: 'acme', project: 'payments-platform' }, report: report([vulnerability], []), productVersion: '0.1.0',
    materiality: { severities: ['critical'], findingTypes: [] }
  }), /No authoritative evidence references finding f1/);
});
