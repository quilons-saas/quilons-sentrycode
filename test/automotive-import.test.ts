import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadAutomotiveImports } from '../src/automotive/imports.js';

test('loads native and SARIF automotive findings without embedding rule text', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-auto-import-'));
  const dir = join(root, '.sentrycode', 'automotive', 'findings');
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'native.json'), JSON.stringify({ schemaVersion: 1, standard: 'misra-c', tool: { name: 'tool-a', version: '1' }, findings: [{ ruleId: 'R1', message: 'finding', severity: 'warning', path: 'a.c', line: 3 }] }));
  await writeFile(join(dir, 'sarif.json'), JSON.stringify({ version: '2.1.0', runs: [{ properties: { automotiveStandard: 'autosar-cpp' }, tool: { driver: { name: 'tool-b', version: '2' } }, results: [{ ruleId: 'A1', level: 'error', message: { text: 'issue' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'b.cpp' }, region: { startLine: 7 } } }] }] }] }));
  const docs = await loadAutomotiveImports(root, '.sentrycode/automotive/findings');
  assert.equal(docs.length, 2);
  assert.deepEqual(docs.map((d) => d.document.standard).sort(), ['autosar-cpp', 'misra-c']);
  assert.equal(docs.find((d) => d.document.standard === 'misra-c')?.document.findings[0]?.ruleId, 'R1');
});
