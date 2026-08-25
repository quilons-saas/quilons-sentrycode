import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { scanHistorySecrets, scanStagedSecrets } from '../src/git/secrets.js';
const execFileAsync=promisify(execFile);
async function git(root:string,args:string[]){ await execFileAsync('git',args,{cwd:root,windowsHide:true}); }

test('staged and historical secret scans catch credentials before/after commit', async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-git-secret-'));
  await git(root,['init']); await git(root,['config','user.email','test@example.com']); await git(root,['config','user.name','Test']);
  await writeFile(join(root,'secret.txt'),'github_token = "ghp_abcdefghijklmnopqrstuvwxyz123456"\n'); await git(root,['add','secret.txt']);
  const staged=await scanStagedSecrets(root,structuredClone(DEFAULT_CONFIG)); assert.ok(staged.length>=1); assert.equal(String(staged[0]?.metadata?.preview).includes('abcdefghijklmnopqrstuvwxyz'),false);
  await git(root,['commit','-m','secret']); await writeFile(join(root,'secret.txt'),'clean\n'); await git(root,['add','secret.txt']); await git(root,['commit','-m','remove']);
  const history=await scanHistorySecrets(root,structuredClone(DEFAULT_CONFIG),10); assert.ok(history.length>=1);
});
