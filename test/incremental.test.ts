import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { buildIncrementalPlan } from '../src/incremental/plan.js';

const exec=promisify(execFile);
test('incremental plan detects changed files between refs', async () => {
  const root=await mkdtemp(resolve(tmpdir(),'sc-inc-'));
  await exec('git',['init'],{cwd:root}); await exec('git',['config','user.email','test@example.com'],{cwd:root}); await exec('git',['config','user.name','Test'],{cwd:root});
  await writeFile(resolve(root,'a.ts'),'export const a=1;\n'); await exec('git',['add','.'],{cwd:root}); await exec('git',['commit','-m','base'],{cwd:root});
  const {stdout}=await exec('git',['rev-parse','HEAD'],{cwd:root}); const base=stdout.trim();
  await writeFile(resolve(root,'a.ts'),'export const a=2;\n'); await exec('git',['add','.'],{cwd:root}); await exec('git',['commit','-m','change'],{cwd:root});
  const plan=await buildIncrementalPlan({root,repository:'x',commitSha:null,config:DEFAULT_CONFIG,ci:{provider:'local',detected:false,pullRequest:false},baseRef:base});
  assert.equal(plan.mode,'incremental');
  assert.deepEqual(plan.changedFiles,['a.ts']);
});
