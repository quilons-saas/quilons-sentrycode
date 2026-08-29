import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { startWebServer } from '../src/web/server.js';

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
