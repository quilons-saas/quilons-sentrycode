import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DependencyScanner } from '../src/scanners/dependencies/scanner.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('dependency scanner enforces denied license and local vulnerability policy', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-deps-'));
  await mkdir(join(root, '.sentrycode'));
  await writeFile(join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app', version: '1.0.0' }, 'node_modules/demo': { version: '1.5.0', license: 'AGPL-3.0', resolved: 'https://registry.npmjs.org/demo/-/demo-1.5.0.tgz' } } }));
  await writeFile(join(root, '.sentrycode/vulnerability-db.json'), JSON.stringify({ schemaVersion: 1, advisories: [{ id: 'CVE-TEST', ecosystem: 'npm', package: 'demo', affected: '<2.0.0', severity: 'critical', fixedVersion: '2.0.0' }] }));
  const config = structuredClone(DEFAULT_CONFIG);
  const result = await new DependencyScanner().scan({ repository: { root, repository: 'fixture', commitSha: 'abc', branch: 'main', isDirty: false }, config, now: () => new Date('2026-08-25T00:00:00Z') });
  assert.equal(result.findings.some((item) => item.ruleId === 'license.denied'), true);
  assert.equal(result.findings.some((item) => item.ruleId === 'CVE-TEST'), true);
  assert.equal(result.evidence.some((item) => item.type === 'sbom.generated'), true);
  assert.equal(result.evidence.some((item) => item.type === 'vuln.scan'), true);
});
