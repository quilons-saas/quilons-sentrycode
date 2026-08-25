import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SastScanner } from '../src/scanners/sast/scanner.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('SAST detects JavaScript eval and Python shell=True', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-sast-'));
  await mkdir(join(root, 'src'));
  await writeFile(join(root, 'src', 'bad.ts'), 'const value = eval(userInput);\n');
  await writeFile(join(root, 'src', 'bad.py'), 'subprocess.run(cmd, shell=True)\n');
  const scanner = new SastScanner();
  const result = await scanner.scan({ repository:{root,repository:'demo',commitSha:'abc',branch:'main',isDirty:false}, config:structuredClone(DEFAULT_CONFIG), now:()=>new Date('2026-08-25T00:00:00Z') });
  assert.equal(result.status ?? 'success', 'success');
  assert.ok(result.findings.some((f) => f.ruleId === 'js-eval'));
  assert.ok(result.findings.some((f) => f.ruleId === 'py-shell-true'));
  assert.equal(result.evidence[0]?.type, 'sast.scan');
});
