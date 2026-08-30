import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { startWebServer } from '../src/web/server.js';
import { roleAllows } from '../src/web/auth.js';

test('RBAC hierarchy is monotonic and does not let viewer mutate administration', async()=>{
  assert.equal(roleAllows('administrator','security_admin'),true);
  assert.equal(roleAllows('security_admin','engineer'),true);
  assert.equal(roleAllows('viewer','engineer'),false);

  const root=await mkdtemp(join(tmpdir(),'sentry-enterprise-auth-'));
  const assets=join(root,'assets'); await mkdir(assets); await writeFile(join(root,'package.json'),'{}'); await writeFile(join(assets,'index.html'),'<html></html>');
  const running=await startWebServer(root,structuredClone(DEFAULT_CONFIG),{tenant:'acme',project:'payments'},{host:'127.0.0.1',port:0,assetRoot:assets,token:'viewer-token',adminToken:'admin-token'});
  try{
    const health=await fetch(`${running.url}/api/v1/health`); assert.equal(health.status,200);
    const anonymous=await fetch(`${running.url}/api/v1/status`); assert.equal(anonymous.status,401);
    const viewerSession=await fetch(`${running.url}/api/v1/admin/session`,{method:'POST',headers:{authorization:'Bearer viewer-token'}});
    assert.equal(viewerSession.status,200);
    const session=await viewerSession.json() as {role:string}; assert.equal(session.role,'viewer');
    const forbidden=await fetch(`${running.url}/api/v1/admin/principals`,{method:'PUT',headers:{authorization:'Bearer viewer-token','content-type':'application/json'},body:JSON.stringify({subject:'a',displayName:'A',role:'administrator'})});
    assert.equal(forbidden.status,403);
    const adminSession=await fetch(`${running.url}/api/v1/admin/session`,{method:'POST',headers:{authorization:'Bearer admin-token'}});
    assert.equal(adminSession.status,200);
    assert.equal((await adminSession.json() as {role:string}).role,'administrator');
  }finally{running.server.close()}
});
