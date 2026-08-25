import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { complianceIdentity } from '../src/compliance/scope.js';
import { issueComplianceToken, verifyComplianceToken } from '../src/compliance/auth.js';
import { SentryCodeComplianceService } from '../src/compliance/service.js';
import { startComplianceServer } from '../src/compliance/server.js';

test('HMAC compliance token is bound to tenant and project scope', () => {
  const token = issueComplianceToken(complianceIdentity('tenant-a','project-a'), 'secret', { issuer:'issuer', audience:'aud', ttlSeconds:60, now:100 });
  const claims = verifyComplianceToken(token, 'secret', { issuer:'issuer', audience:'aud', now:120 });
  assert.equal(claims.tenant, 'tenant-a'); assert.equal(claims.project, 'project-a');
  assert.throws(() => verifyComplianceToken(token, 'wrong', { issuer:'issuer', audience:'aud', now:120 }), /signature/);
  assert.throws(() => verifyComplianceToken(token, 'secret', { issuer:'issuer', audience:'aud', now:1000 }), /expired/);
});

test('capability API rejects scope escalation with HMAC token', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-hmac-api-'));
  await writeFile(join(root,'package.json'), JSON.stringify({ version:'0.1.0' }));
  const service = new SentryCodeComplianceService(root, '.sentrycode/compliance');
  const running = await startComplianceServer(service, { host:'127.0.0.1', port:0, hmac:{ secret:'shared', issuer:'issuer', audience:'aud' } });
  try {
    const token = issueComplianceToken(complianceIdentity('tenant-a','project-a'), 'shared', { issuer:'issuer', audience:'aud', ttlSeconds:60 });
    const base=`http://127.0.0.1:${running.port}`;
    const ok=await fetch(`${base}/v1/runs`,{headers:{authorization:`Bearer ${token}`}}); assert.equal(ok.status,200);
    const forbidden=await fetch(`${base}/v1/runs?tenant=tenant-b&project=project-a`,{headers:{authorization:`Bearer ${token}`}}); assert.equal(forbidden.status,403);
  } finally { await new Promise<void>((resolve,reject)=>running.server.close((error?:Error)=>error?reject(error):resolve())); }
});
