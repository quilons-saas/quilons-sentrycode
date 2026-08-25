import test from 'node:test';
import assert from 'node:assert/strict';
import { detectCi } from '../src/ci/context.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('detects GitHub pull request context', () => {
  const ci = detectCi(DEFAULT_CONFIG, {
    GITHUB_ACTIONS:'true',
    GITHUB_BASE_REF:'main',
    GITHUB_HEAD_REF:'feature/x',
    GITHUB_REPOSITORY:'quilons/sentrycode',
    GITHUB_RUN_ID:'42'
  });
  assert.equal(ci.provider,'github');
  assert.equal(ci.pullRequest,true);
  assert.equal(ci.baseRef,'main');
  assert.equal(ci.headRef,'feature/x');
});

test('explicit CI provider overrides auto detection', () => {
  const config=structuredClone(DEFAULT_CONFIG); config.ci.provider='generic';
  const ci=detectCi(config,{ GITHUB_ACTIONS:'true' });
  assert.equal(ci.provider,'generic');
});
