import assert from 'node:assert/strict';
import test from 'node:test';
import { cyclonedxSbom, spdxSbom } from '../src/sbom/generate.js';
import type { DependencyComponent, RepositoryContext } from '../src/core/types.js';

const repository: RepositoryContext = { root: '/tmp/repo', repository: 'demo', commitSha: 'abc', branch: 'main', isDirty: false };
const components: DependencyComponent[] = [{ ecosystem: 'npm', name: 'left-pad', version: '1.3.0', direct: true, dev: false, source: 'package-lock.json', license: 'MIT', purl: 'pkg:npm/left-pad@1.3.0' }];

test('generates CycloneDX 1.5 SBOM', () => {
  const bom = cyclonedxSbom(repository, components, '2026-08-25T00:00:00Z') as { bomFormat: string; specVersion: string; components: unknown[] };
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.specVersion, '1.5');
  assert.equal(bom.components.length, 1);
});

test('generates SPDX 2.3 SBOM', () => {
  const bom = spdxSbom(repository, components, '2026-08-25T00:00:00Z') as { spdxVersion: string; packages: unknown[] };
  assert.equal(bom.spdxVersion, 'SPDX-2.3');
  assert.equal(bom.packages.length, 1);
});
