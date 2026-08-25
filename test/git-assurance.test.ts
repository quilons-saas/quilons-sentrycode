import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { GitAssuranceScanner } from '../src/scanners/git/scanner.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
const exec=promisify(execFile);

test('git assurance reports unsigned commit when signing is required', async () => {
  const root=await mkdtemp(join(tmpdir(),'sentrycode-git-'));
  await exec('git',['init'],{cwd:root}); await exec('git',['config','user.name','Test User'],{cwd:root}); await exec('git',['config','user.email','test@example.com'],{cwd:root});
  await writeFile(join(root,'a.txt'),'hello'); await exec('git',['add','.'],{cwd:root}); await exec('git',['commit','-m','initial'],{cwd:root});
  const {stdout}=await exec('git',['rev-parse','HEAD'],{cwd:root});
  const config=structuredClone(DEFAULT_CONFIG); config.gitAssurance.requireSignedCommit=true;
  const result=await new GitAssuranceScanner().scan({repository:{root,repository:'demo',commitSha:stdout.trim(),branch:'main',isDirty:false},config,now:()=>new Date('2026-08-25T00:00:00Z')});
  assert.ok(result.findings.some(f=>f.ruleId==='unsigned-commit'));
  assert.equal(result.evidence[0]?.type,'commit.verification');
});
