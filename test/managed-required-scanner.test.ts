import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { runScan } from '../src/core/engine.js';
import type { ScannerPlugin } from '../src/core/types.js';

function success(id: string): ScannerPlugin {
  return { id, version: 'test', async scan() { return { scanner: id, findings: [], evidence: [], durationMs: 0 }; } };
}

test('enabled managed scanner profiles form a fail-closed required-scanner floor', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sc-managed-floor-'));
  try {
    const config = structuredClone(DEFAULT_CONFIG);
    config.execution.runner.enabled = true;
    config.execution.runner.profiles = { 'supply-chain': 'syft-grype' };
    const supply: ScannerPlugin = { id: 'supply-chain', version: 'test', async scan() { throw new Error('governed intelligence unavailable'); } };
    const report = await runScan({
      repository: { root, repository: 'repo', commitSha: 'abc', branch: 'main', isDirty: false },
      config,
      scanners: [success('secrets'), success('dependencies'), supply, success('sast'), success('git-assurance')],
      now: () => new Date('2026-10-07T00:00:00Z')
    });
    assert.equal(report.policy.decision, 'FAIL');
    assert.match(report.policy.reasons.join('\n'), /supply-chain failed closed/);
    assert.match(String(report.evidence.at(-1)?.metadata.requiredScannerFloor), /supply-chain/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
