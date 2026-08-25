import assert from 'node:assert/strict';
import test from 'node:test';
import { matchesAny } from '../src/utils/glob.js';

test('double-star include matches root and nested files', () => {
  assert.equal(matchesAny('README.md', ['**/*']), true);
  assert.equal(matchesAny('src/index.ts', ['**/*']), true);
});

test('double-star extension pattern matches root and nested lock files', () => {
  assert.equal(matchesAny('package.lock', ['**/*.lock']), true);
  assert.equal(matchesAny('nested/package.lock', ['**/*.lock']), true);
});
