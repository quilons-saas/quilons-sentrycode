import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises'; import { tmpdir } from 'node:os'; import { join } from 'node:path';
import { execFile } from 'node:child_process'; import { promisify } from 'node:util';
import { GitAssuranceScanner } from '../src/scanners/git/scanner.js'; import { DEFAULT_CONFIG } from '../src/config/defaults.js';
const execFileAsync=promisify(execFile);

test('Gerrit assurance enforces required review labels',async()=>{
 const root=await mkdtemp(join(tmpdir(),'sentrycode-gerrit-assurance-')); await execFileAsync('git',['init'],{cwd:root}); await execFileAsync('git',['config','user.email','dev@example.com'],{cwd:root}); await execFileAsync('git',['config','user.name','Dev'],{cwd:root}); await execFileAsync('git',['commit','--allow-empty','-m','init'],{cwd:root});
 const cfg=structuredClone(DEFAULT_CONFIG); cfg.gitAssurance.gerrit.enabled=true; cfg.gitAssurance.gerrit.apiBaseUrl='https://gerrit.example'; cfg.gitAssurance.gerrit.tokenEnv='TEST_GERRIT_TOKEN';
 const old=process.env.TEST_GERRIT_TOKEN; process.env.TEST_GERRIT_TOKEN='x'; const prev=globalThis.fetch; globalThis.fetch=async()=>new Response(")]}'\n"+JSON.stringify({_number:99,project:'acme/widget',branch:'main',current_revision:'abc',labels:{'Code-Review':{value:1},Verified:{value:1}}}),{status:200});
 try{ const result=await new GitAssuranceScanner().scan({repository:{root,repository:'acme/widget',commitSha:'abc',branch:'main',isDirty:false},config:cfg,now:()=>new Date('2026-08-30T00:00:00Z'),execution:{mode:'full',changedFiles:[],ci:{provider:'gerrit',detected:true,pullRequest:true,changeNumber:'99',revision:'abc'}}}); assert.ok(result.findings.some(f=>f.ruleId==='gerrit.required-label'&&f.description.includes('Code-Review'))); assert.equal(result.evidence[0]?.metadata.governanceProvider,'gerrit'); }
 finally{ globalThis.fetch=prev; if(old===undefined) delete process.env.TEST_GERRIT_TOKEN; else process.env.TEST_GERRIT_TOKEN=old; }
});
