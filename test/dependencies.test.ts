import assert from 'node:assert/strict';
import test from 'node:test';
import { parseDependencyFiles } from '../src/dependencies/discover.js';
import { diffDependencies } from '../src/dependencies/diff.js';

const now = '2026-08-25T00:00:00.000Z';

test('discovers npm package-lock and pinned Python requirements', () => {
  const snapshot = parseDependencyFiles({
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app', version: '1.0.0' }, 'node_modules/left-pad': { version: '1.3.0', license: 'MIT', resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz' } } }),
    'requirements.txt': 'requests==2.32.3\n# comment\n'
  }, now);
  assert.equal(snapshot.components.length, 2);
  assert.equal(snapshot.components.find((item) => item.name === 'left-pad')?.license, 'MIT');
  assert.equal(snapshot.components.find((item) => item.name === 'requests')?.ecosystem, 'pypi');
});

test('dependency diff classifies add/remove/upgrade/downgrade', () => {
  const before = parseDependencyFiles({ 'requirements.txt': 'a==1.0.0\nb==2.0.0\nc==3.0.0\n' }, now);
  const after = parseDependencyFiles({ 'requirements.txt': 'a==2.0.0\nb==1.0.0\nd==1.0.0\n' }, now);
  const changes = diffDependencies(before, after);
  assert.deepEqual(changes.map((item) => `${item.name}:${item.kind}`), ['a:upgraded', 'b:downgraded', 'c:removed', 'd:added']);
});
