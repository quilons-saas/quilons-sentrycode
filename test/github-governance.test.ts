import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GitHubGovernanceProvider } from '../src/git/github-provider.js';
const execFileAsync=promisify(execFile);

test('GitHub governance provider reads branch protection requirements',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-gh-')); await execFileAsync('git',['init'],{cwd:root}); await execFileAsync('git',['remote','add','origin','https://github.com/acme/widget.git'],{cwd:root});
  const previous=globalThis.fetch;
  globalThis.fetch=async()=>new Response(JSON.stringify({required_status_checks:{checks:[{context:'ci'}]},required_pull_request_reviews:{required_approving_review_count:2}}),{status:200,headers:{'content-type':'application/json'}});
  try { const state=await new GitHubGovernanceProvider({token:'x'}).inspect(root,'main'); assert.equal(state.protected,true); assert.equal(state.requiredApprovals,2); assert.equal(state.statusChecksRequired,true); assert.equal(state.repository,'acme/widget'); }
  finally { globalThis.fetch=previous; }
});
