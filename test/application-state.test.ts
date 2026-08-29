import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ApplicationStateStore } from '../src/application/store.js';
import type { ApplicationAuditRecord, ApplicationStateStatus, IntegrationRecord, ManagedPolicyAssignment, ManagedScannerSetting, PrincipalRecord, RegisteredRepository, WaiverWorkflowRecord } from '../src/application/types.js';
import { SentryCodeAdminService } from '../src/application/admin-service.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

class MemoryStore implements ApplicationStateStore {
  repos:RegisteredRepository[]=[]; scanners:ManagedScannerSetting[]=[]; policies:ManagedPolicyAssignment[]=[]; waivers:WaiverWorkflowRecord[]=[]; integrations:IntegrationRecord[]=[]; principals:PrincipalRecord[]=[]; audits:ApplicationAuditRecord[]=[];
  async status():Promise<ApplicationStateStatus>{return{configured:true,connected:true,schemaVersion:1,detail:'memory'}} async migrate(){return 1}
  async listRepositories(t:string,p:string){return this.repos.filter(x=>x.tenant===t&&x.project===p)}
  async upsertRepository(v:Omit<RegisteredRepository,'createdAt'|'updatedAt'>){const now=new Date().toISOString();const x={...v,createdAt:now,updatedAt:now};this.repos=this.repos.filter(r=>r.id!==v.id);this.repos.push(x);return x}
  async listScannerSettings(id:string){return this.scanners.filter(x=>x.repositoryId===id)}
  async upsertScannerSetting(v:Omit<ManagedScannerSetting,'updatedAt'|'updatedBy'>,actor:string){const x={...v,updatedAt:new Date().toISOString(),updatedBy:actor};this.scanners=this.scanners.filter(s=>!(s.repositoryId===v.repositoryId&&s.scanner===v.scanner));this.scanners.push(x);return x}
  async listPolicies(t:string,p:string){return this.policies.filter(x=>x.tenant===t&&x.project===p)}
  async upsertPolicy(v:Omit<ManagedPolicyAssignment,'version'|'updatedAt'|'updatedBy'>,actor:string){const prev=this.policies.find(x=>x.id===v.id);const x={...v,version:(prev?.version??0)+1,updatedAt:new Date().toISOString(),updatedBy:actor};this.policies=this.policies.filter(p=>p.id!==v.id);this.policies.push(x);return x}
  async listWaivers(t:string,p:string){return this.waivers.filter(x=>x.tenant===t&&x.project===p)} async createWaiver(v:WaiverWorkflowRecord){this.waivers.push(v);return v}
  async transitionWaiver(id:string,status:'active'|'rejected'|'revoked',actor:string){const x=this.waivers.find(w=>w.id===id);if(!x)return null;x.status=status;x.approver=status==='active'?actor:x.approver;x.decidedAt=new Date().toISOString();return x}
  async listIntegrations(t:string,p:string){return this.integrations.filter(x=>x.tenant===t&&x.project===p)} async upsertIntegration(v:Omit<IntegrationRecord,'updatedAt'|'updatedBy'>,actor:string){const x={...v,updatedAt:new Date().toISOString(),updatedBy:actor};this.integrations.push(x);return x}
  async listPrincipals(){return this.principals} async upsertPrincipal(v:PrincipalRecord){this.principals.push(v);return v} async appendAudit(v:ApplicationAuditRecord){this.audits.push(v)} async listAudit(){return this.audits} async close(){}
}

test('UI-managed scanner and policy state materialize to repository contracts', async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentry-admin-')); await mkdir(join(root,'.sentrycode','policies'),{recursive:true}); await writeFile(join(root,'package.json'),'{}'); await writeFile(join(root,'.sentrycode','config.json'),JSON.stringify({schemaVersion:1}));
  const store=new MemoryStore(); const config=structuredClone(DEFAULT_CONFIG); config.integrity.auditLogFile='.sentrycode/audit/events.jsonl';
  const admin=new SentryCodeAdminService(root,config,{tenant:'acme',project:'payments'},store);
  const repo=await admin.registerRepository({name:'payments',rootPath:root,defaultBranch:'main'},'alice');
  await admin.setScanner(repo.id,{scanner:'secrets',enabled:true,required:true,failureMode:'fail'},'alice');
  await admin.materializeScannerConfig(repo,await admin.scanners(repo.id));
  const policy=await admin.setPolicy({repositoryId:repo.id,failOn:['critical'],warnOn:['high'],requiredScanners:['secrets'],scannerFailureModes:{secrets:'fail'}},'alice');
  const policyPath=await admin.materializePolicy(repo,policy);
  const configFile=JSON.parse(await readFile(join(root,'.sentrycode','config.json'),'utf8'));
  assert.equal(configFile.secrets.enabled,true); assert.deepEqual(configFile.policy.requiredScanners,['secrets']);
  const policyFile=JSON.parse(await readFile(policyPath,'utf8')); assert.equal(policyFile.level,'repository'); assert.deepEqual(policyFile.enforcement.failOn,['critical']);
  const audit=await readFile(join(root,'.sentrycode','audit','events.jsonl'),'utf8'); assert.match(audit,/ui\.scanner\.update/); assert.match(audit,/ui\.policy\.upsert/);
});

test('active UI waiver materialization preserves manual waivers', async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentry-waiver-')); await mkdir(join(root,'.sentrycode'),{recursive:true}); await writeFile(join(root,'package.json'),'{}'); await writeFile(join(root,'.sentrycode','waivers.json'),JSON.stringify([{id:'manual',reason:'manual',expiresAt:'2099-01-01T00:00:00Z',ruleId:'x'}]));
  const store=new MemoryStore(); const config=structuredClone(DEFAULT_CONFIG); const admin=new SentryCodeAdminService(root,config,{tenant:'acme',project:'payments'},store); const repo=await admin.registerRepository({name:'payments',rootPath:root,defaultBranch:'main'},'alice');
  const waiver=await admin.requestWaiver({repositoryId:repo.id,ruleId:'sec.rule',reason:'temporary',expiresAt:'2099-01-01T00:00:00Z'},'alice'); await admin.materializeWaivers(repo,[waiver]); const values=JSON.parse(await readFile(join(root,'.sentrycode','waivers.json'),'utf8'));
  assert.equal(values.length,2); assert.ok(values.some((x:any)=>x.id==='manual')); assert.ok(values.some((x:any)=>x.id===waiver.id));
});

test('administration rejects repository IDs outside the configured tenant/project scope', async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentry-scope-')); await writeFile(join(root,'package.json'),'{}');
  const store=new MemoryStore(); const now=new Date().toISOString(); store.repos.push({id:'foreign',tenant:'other',project:'other',name:'foreign',rootPath:root,defaultBranch:'main',enabled:true,createdAt:now,updatedAt:now});
  const admin=new SentryCodeAdminService(root,structuredClone(DEFAULT_CONFIG),{tenant:'acme',project:'payments'},store);
  await assert.rejects(()=>admin.setScanner('foreign',{scanner:'secrets',enabled:true,required:true,failureMode:'fail'},'alice'),/REPOSITORY_SCOPE_MISMATCH/);
});

test('signed configuration enforcement blocks UI materialization', async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentry-signed-ui-')); await mkdir(join(root,'.sentrycode'),{recursive:true}); await writeFile(join(root,'package.json'),'{}');
  const store=new MemoryStore(); const config=structuredClone(DEFAULT_CONFIG); config.integrity.requireSignedConfig=true; const admin=new SentryCodeAdminService(root,config,{tenant:'acme',project:'payments'},store); const repo=await admin.registerRepository({name:'payments',rootPath:root,defaultBranch:'main'},'alice');
  await assert.rejects(()=>admin.materializeScannerConfig(repo,[]),/SIGNED_CONFIG_WRITE_BLOCKED/);
});
