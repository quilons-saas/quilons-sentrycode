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

test('detects Gerrit change and patchset context', () => {
  const ci = detectCi(DEFAULT_CONFIG, {
    GERRIT_CHANGE_NUMBER:'1234',
    GERRIT_PATCHSET_NUMBER:'7',
    GERRIT_PATCHSET_REVISION:'abc123',
    GERRIT_BRANCH:'main',
    GERRIT_PROJECT:'acme/widget',
    GERRIT_REFSPEC:'refs/changes/34/1234/7'
  });
  assert.equal(ci.provider,'gerrit');
  assert.equal(ci.pullRequest,true);
  assert.equal(ci.changeNumber,'1234');
  assert.equal(ci.patchsetNumber,'7');
  assert.equal(ci.revision,'abc123');
  assert.equal(ci.repository,'acme/widget');
  assert.equal(ci.baseRef,'main');
});
