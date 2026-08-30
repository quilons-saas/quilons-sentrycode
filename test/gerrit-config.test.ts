import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig } from '../src/config/load.js';

test('loads first-class Gerrit assurance and publishing configuration',async()=>{
 const root=await mkdtemp(join(tmpdir(),'sentrycode-gerrit-config-')); await mkdir(join(root,'.sentrycode'));
 await writeFile(join(root,'.sentrycode','config.json'),JSON.stringify({schemaVersion:1,gitAssurance:{gerrit:{enabled:true,apiBaseUrl:'https://gerrit.example',authMode:'basic',usernameEnv:'G_USER',passwordEnv:'G_PASS',requiredLabels:{'Code-Review':2,Verified:1},publishReview:true,voteLabel:'Verified',passVote:1,warnVote:0,failVote:-1,notify:'ALL',failClosed:true,timeoutMs:9000}},ci:{provider:'gerrit'}}));
 const c=await loadConfig(root); assert.equal(c.ci.provider,'gerrit'); assert.equal(c.gitAssurance.gerrit.enabled,true); assert.equal(c.gitAssurance.gerrit.requiredLabels['Code-Review'],2); assert.equal(c.gitAssurance.gerrit.notify,'ALL');
});
