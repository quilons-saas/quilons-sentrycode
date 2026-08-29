import { stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { SentryCodeConfig } from '../core/types.js';
import { runDiagnostics } from '../enterprise/diagnostics.js';
import { createBackup, restoreBackup, applyComplianceRetention } from '../enterprise/backup.js';
import { appendAuditEvent } from '../enterprise/audit.js';
import { syncOsvDatabase } from '../vulnerabilities/osv.js';
import { verifyAuditChain, readAuditEvents } from '../enterprise/audit.js';
import { loadVulnerabilityDatabase } from '../vulnerabilities/database.js';
import { loadAutomotiveImports } from '../automotive/imports.js';
import { loadAutomotiveDeviations } from '../automotive/deviations.js';

async function exists(path:string):Promise<boolean>{try{await stat(path);return true}catch{return false}}
export async function enterpriseStatus(root:string,config:SentryCodeConfig){
  const [diagnostics,audit,intelligence]=await Promise.all([
    runDiagnostics(root,config),
    verifyAuditChain(root,config.integrity.auditLogFile,config.integrity.evidenceSigningPublicKeyFile||undefined),
    loadVulnerabilityDatabase(root,config.vulnerabilities.databaseFile)
  ]);
  const events=await readAuditEvents(root,config.integrity.auditLogFile);
  return {
    diagnostics,
    audit:{ok:audit.ok,eventCount:events.length,...(audit.invalidIndex===undefined?{}:{invalidIndex:audit.invalidIndex})},
    intelligence:{available:intelligence.available,advisoryCount:intelligence.advisories.length,updatedAt:intelligence.updatedAt??null,offline:config.offline.enabled,osvEnabled:config.vulnerabilities.osv.enabled},
    compliance:{enabled:config.compliance.enabled,endpoint:config.compliance.endpoint||null,authMode:config.compliance.authMode,tenant:config.compliance.tenant||null,project:config.compliance.project||null},
    storage:{backupDirectory:config.operations.backupDirectory,retentionDays:config.operations.retentionDays}
  };
}
export async function automotiveStatus(root:string,config:SentryCodeConfig){
  const imports=await loadAutomotiveImports(root,config.automotive.importDirectory);
  const deviations=await loadAutomotiveDeviations(root,config.automotive.deviationsFile);
  const counts:Record<string,number>={'misra-c':0,'misra-cpp':0,'autosar-cpp':0};
  for(const item of imports)counts[item.document.standard]=(counts[item.document.standard]??0)+item.document.findings.length;
  return {enabled:config.automotive.enabled,requireInputs:config.automotive.requireInputs,requireDeviationApproval:config.automotive.requireDeviationApproval,acceptedStandards:config.automotive.acceptedStandards,evidenceTargets:config.automotive.evidenceTargets,importDocuments:imports.length,findings:counts,deviations:deviations.length,importDirectory:config.automotive.importDirectory,deviationsFile:config.automotive.deviationsFile};
}

export async function createOperationalBackup(root:string,config:SentryCodeConfig,actor:string){
  const path=await createBackup(root,['.sentrycode/config.json',config.policy.directory,config.waivers.file,config.vulnerabilities.databaseFile,config.compliance.storeDirectory,config.integrity.auditLogFile],config.operations.backupDirectory);
  await appendAuditEvent(root,config.integrity.auditLogFile,'ui.backup.created',{path},actor,config.integrity.evidenceSigningPrivateKeyFile||undefined);
  return {path,createdAt:new Date().toISOString(),databaseNote:'PostgreSQL must be backed up separately with pg_dump or platform-native backup tooling.'};
}
export async function applyOperationalRetention(root:string,config:SentryCodeConfig,actor:string){
  const removed=await applyComplianceRetention(root,config.compliance.storeDirectory,config.operations.retentionDays);
  await appendAuditEvent(root,config.integrity.auditLogFile,'ui.retention.applied',{retentionDays:config.operations.retentionDays,removed:removed.length},actor,config.integrity.evidenceSigningPrivateKeyFile||undefined);
  return {retentionDays:config.operations.retentionDays,removed};
}
export async function restoreOperationalBackup(root:string,config:SentryCodeConfig,backupPath:string,actor:string){
  if(!backupPath.trim())throw new Error('backupPath is required');
  await restoreBackup(root,backupPath,{ 'config.json':'.sentrycode/config.json','policies':config.policy.directory,'waivers.json':config.waivers.file,'vulnerability-db.json':config.vulnerabilities.databaseFile,'compliance':config.compliance.storeDirectory,'events.jsonl':config.integrity.auditLogFile });
  await appendAuditEvent(root,config.integrity.auditLogFile,'ui.backup.restored',{backupPath},actor,config.integrity.evidenceSigningPrivateKeyFile||undefined);
  return {restored:true,backupPath};
}
export async function synchronizeIntelligence(root:string,config:SentryCodeConfig,actor:string){
  const result=await syncOsvDatabase(root,config);
  await appendAuditEvent(root,config.integrity.auditLogFile,'ui.intelligence.synced',{advisoryCount:result.advisoryCount,componentCount:result.componentCount},actor,config.integrity.evidenceSigningPrivateKeyFile||undefined);
  return result;
}
