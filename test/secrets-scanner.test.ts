import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { SecretsScanner } from '../src/scanners/secrets/scanner.js';

test('secrets scanner detects and redacts a credential assignment', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-secret-'));
  await mkdir(join(root, 'src'));
  await writeFile(join(root, 'src', 'config.ts'), `const apiKey = "abc123_SUPER_SECRET_VALUE_987654";\n`);
  const scanner = new SecretsScanner();
  const result = await scanner.scan({
    repository: { root, repository: 'fixture', commitSha: 'abc', branch: 'main', isDirty: false },
    config: structuredClone(DEFAULT_CONFIG),
    now: () => new Date('2026-08-25T00:00:00Z')
  });
  assert.ok(result.findings.some((finding) => finding.ruleId === 'generic-secret-assignment'));
  const preview = String(result.findings[0]?.metadata?.preview ?? '');
  assert.ok(!preview.includes('SUPER_SECRET_VALUE'));
  assert.equal(result.evidence[0]?.type, 'secret.scan');
});
