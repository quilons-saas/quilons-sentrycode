import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { startWebServer } from '../src/web/server.js';
import { DisabledApplicationStateStore } from '../src/application/store.js';

test('standalone web server serves UI assets and status API', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-web-server-'));
  const assets = join(root,'assets');
  await mkdir(assets);
  await writeFile(join(root,'package.json'),'{}');
  await writeFile(join(assets,'index.html'),'<html>SentryCode UI</html>');
  await writeFile(join(assets,'logo.png'), Buffer.from([0x89,0x50,0x4e,0x47]));
  const running = await startWebServer(root, structuredClone(DEFAULT_CONFIG), null, { host:'127.0.0.1', port:0, assetRoot:assets });
  try {
    const page = await fetch(`${running.url}/`);
    assert.equal(page.status,200);
    assert.match(await page.text(),/SentryCode UI/);
    const logo = await fetch(`${running.url}/logo.png`);
    assert.equal(logo.status,200);
    assert.equal(logo.headers.get('content-type'),'image/png');
    const status = await fetch(`${running.url}/api/v1/status`);
    assert.equal(status.status,200);
    const body = await status.json() as { product:string; ready:boolean };
    assert.equal(body.product,'QUILONS SentryCode');
    assert.equal(body.ready,false);
  } finally { running.server.close(); }
});

test('non-loopback standalone web server requires an API token', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-web-auth-'));
  await writeFile(join(root,'package.json'),'{}');
  await assert.rejects(() => startWebServer(root, structuredClone(DEFAULT_CONFIG), null, { host:'0.0.0.0', port:0, assetRoot:root }), /SENTRYCODE_UI_TOKEN/);
});

test('standalone administration writes require a separate admin token', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sentrycode-web-admin-'));
  const assets = join(root,'assets'); await mkdir(assets); await writeFile(join(root,'package.json'),'{}'); await writeFile(join(assets,'index.html'),'<html></html>');
  const identity={tenant:'acme',project:'payments'};
  const noToken = await startWebServer(root, structuredClone(DEFAULT_CONFIG), identity, { host:'127.0.0.1',port:0,assetRoot:assets,applicationStore:new DisabledApplicationStateStore() });
  try { const r=await fetch(`${noToken.url}/api/v1/admin/repositories`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'}); assert.equal(r.status,503); } finally { noToken.server.close(); }
  const protectedServer = await startWebServer(root, structuredClone(DEFAULT_CONFIG), identity, { host:'127.0.0.1',port:0,assetRoot:assets,adminToken:'correct',applicationStore:new DisabledApplicationStateStore() });
  try {
    const rejectedSession=await fetch(`${protectedServer.url}/api/v1/admin/session`,{method:'POST',headers:{authorization:'Bearer wrong','x-sentrycode-actor':'tester'}}); assert.equal(rejectedSession.status,401);
    const acceptedSession=await fetch(`${protectedServer.url}/api/v1/admin/session`,{method:'POST',headers:{authorization:'Bearer correct','x-sentrycode-actor':'tester'}}); assert.equal(acceptedSession.status,200);
    const sessionBody=await acceptedSession.json() as {authenticated:boolean;actor:string}; assert.equal(sessionBody.authenticated,true); assert.equal(sessionBody.actor,'tester');
    const wrong=await fetch(`${protectedServer.url}/api/v1/admin/repositories`,{method:'POST',headers:{authorization:'Bearer wrong','content-type':'application/json'},body:'{}'}); assert.equal(wrong.status,401);
    const accepted=await fetch(`${protectedServer.url}/api/v1/admin/repositories`,{method:'POST',headers:{authorization:'Bearer correct','content-type':'application/json'},body:JSON.stringify({name:'x',rootPath:root})}); assert.equal(accepted.status,503);
  } finally { protectedServer.server.close(); }
});
