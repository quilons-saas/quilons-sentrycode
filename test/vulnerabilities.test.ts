import assert from 'node:assert/strict';
import test from 'node:test';
import { vulnerabilitiesFor } from '../src/vulnerabilities/database.js';
import type { DependencyComponent, VulnerabilityAdvisory } from '../src/core/types.js';

const component: DependencyComponent = { ecosystem: 'npm', name: 'demo', version: '1.5.0', direct: true, dev: false, source: 'x', purl: 'pkg:npm/demo@1.5.0' };
const advisories: VulnerabilityAdvisory[] = [
  { id: 'A', ecosystem: 'npm', package: 'demo', affected: '<2.0.0', severity: 'high' },
  { id: 'B', ecosystem: 'npm', package: 'other', affected: '<2.0.0', severity: 'high' }
];

test('matches local vulnerability advisories by ecosystem package and range', () => {
  assert.deepEqual(vulnerabilitiesFor(component, advisories).map((item) => item.id), ['A']);
});
