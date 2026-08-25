import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { AutomotiveScanner } from '../src/scanners/automotive/scanner.js';

test('automotive scanner normalizes imported findings and emits alignment evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-auto-scan-'));
  const dir = join(root, '.sentrycode', 'automotive', 'findings');
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'findings.json'), JSON.stringify({ schemaVersion: 1, standard: 'misra-cpp', tool: { name: 'licensed-tool' }, findings: [{ ruleId: 'R-42', message: 'example', severity: 'error', path: 'src/a.cpp', line: 4, tags: ['cybersecurity'] }] }));
  const config = structuredClone(DEFAULT_CONFIG);
  config.automotive.enabled = true;
  const result = await new AutomotiveScanner().scan({ repository: { root, repository: 'demo', commitSha: 'abc', branch: 'main', isDirty: false }, config, now: () => new Date('2026-08-25T00:00:00Z') });
  assert.equal(result.status, 'success');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0]?.ruleId, 'misra-cpp:R-42');
  assert.equal(result.findings[0]?.severity, 'high');
  assert.equal(result.evidence.some((e) => e.type === 'automotive.rule.check'), true);
  assert.equal(result.evidence.some((e) => e.metadata.evidenceTarget === 'iso-sae-21434'), true);
  assert.equal(result.evidence.some((e) => e.metadata.evidenceTarget === 'unece-r155'), true);
});

test('approved automotive deviation suppresses matching imported finding and emits deviation evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-auto-dev-'));
  const dir = join(root, '.sentrycode', 'automotive', 'findings');
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'findings.json'), JSON.stringify({ schemaVersion: 1, standard: 'misra-c', tool: { name: 'licensed-tool' }, findings: [{ ruleId: 'R-1', message: 'example', severity: 'warning', path: 'src/a.c', line: 1 }] }));
  await writeFile(join(root, '.sentrycode', 'automotive', 'deviations.json'), JSON.stringify([{ id: 'DEV-1', standard: 'misra-c', ruleId: 'R-1', reason: 'approved rationale', approver: 'chief-engineer', approvedAt: '2026-08-24T00:00:00Z', expiresAt: '2026-09-01T00:00:00Z' }]));
  const config = structuredClone(DEFAULT_CONFIG);
  config.automotive.enabled = true;
  const result = await new AutomotiveScanner().scan({ repository: { root, repository: 'demo', commitSha: 'abc', branch: 'main', isDirty: false }, config, now: () => new Date('2026-08-25T00:00:00Z') });
  assert.equal(result.findings.length, 0);
  assert.equal(result.evidence.some((e) => e.type === 'automotive.deviation'), true);
});

test('automotive scanner fails when enabled assurance has no analyzer inputs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-auto-empty-'));
  const config = structuredClone(DEFAULT_CONFIG);
  config.automotive.enabled = true;
  await assert.rejects(() => new AutomotiveScanner().scan({ repository: { root, repository: 'demo', commitSha: 'abc', branch: 'main', isDirty: false }, config, now: () => new Date('2026-08-25T00:00:00Z') }), /no analyzer imports/);
});
