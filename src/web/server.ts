import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';
import type { ComplianceIdentity } from '../compliance/contracts.js';
import type { SentryCodeConfig } from '../core/types.js';
import { SentryCodeWebService } from './service.js';

export interface WebServerOptions { host: string; port: number; token?: string; assetRoot?: string; }
function isLoopback(host: string): boolean { return host === '127.0.0.1' || host === '::1' || host === 'localhost'; }
function bearer(req: IncomingMessage): string { const value = req.headers.authorization ?? ''; return value.startsWith('Bearer ') ? value.slice(7) : ''; }
function json(res: ServerResponse, status: number, body: unknown): void { const content = `${JSON.stringify(body, null, 2)}\n`; res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(content), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }); res.end(content); }
function mime(path: string): string { const ext = extname(path); return ext === '.html' ? 'text/html; charset=utf-8' : ext === '.css' ? 'text/css; charset=utf-8' : ext === '.js' ? 'text/javascript; charset=utf-8' : ext === '.svg' ? 'image/svg+xml' : ext === '.png' ? 'image/png' : 'application/octet-stream'; }
function safeAsset(root: string, pathname: string): string { const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, ''); const candidate = resolve(root, relative); if (!candidate.startsWith(resolve(root))) throw new Error('invalid_asset_path'); return candidate; }

async function sendAsset(res: ServerResponse, root: string, pathname: string): Promise<void> {
  let path = safeAsset(root, pathname);
  try { if (!(await stat(path)).isFile()) throw new Error('not_file'); }
  catch { path = resolve(root, 'index.html'); }
  const content = await readFile(path);
  res.writeHead(200, { 'content-type': mime(path), 'content-length': content.length, 'cache-control': path.endsWith('index.html') ? 'no-store' : 'public, max-age=3600', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" });
  res.end(content);
}

export async function startWebServer(repositoryRoot: string, config: SentryCodeConfig, identity: ComplianceIdentity | null, options: WebServerOptions) {
  if (!isLoopback(options.host) && !options.token) throw new Error('SENTRYCODE_UI_TOKEN is required when the Web UI binds to a non-loopback host');
  const service = new SentryCodeWebService(repositoryRoot, config, identity);
  const assetRoot = options.assetRoot ?? resolve(dirname(fileURLToPath(import.meta.url)), '../../ui');
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      if (url.pathname.startsWith('/api/')) {
        if (options.token && bearer(req) !== options.token) { json(res, 401, { error: 'unauthorized' }); return; }
        if (req.method !== 'GET') { json(res, 405, { error: 'method_not_allowed' }); return; }
        if (url.pathname === '/api/v1/status') { json(res, 200, await service.status()); return; }
        if (url.pathname === '/api/v1/dashboard') { json(res, 200, await service.dashboard()); return; }
        if (url.pathname === '/api/v1/repositories') { json(res, 200, await service.repositories()); return; }
        if (url.pathname === '/api/v1/runs') { json(res, 200, await service.listRuns()); return; }
        if (url.pathname === '/api/v1/findings') { json(res, 200, await service.findings()); return; }
        if (url.pathname === '/api/v1/config') { json(res, 200, service.configSummary()); return; }
        const run = /^\/api\/v1\/runs\/([A-Za-z0-9._-]+)$/.exec(url.pathname);
        if (run) { const value = await service.runDetail(run[1]!); json(res, value ? 200 : 404, value ?? { error: 'run_not_found' }); return; }
        json(res, 404, { error: 'not_found' }); return;
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') { json(res, 405, { error: 'method_not_allowed' }); return; }
      await sendAsset(res, assetRoot, url.pathname);
    } catch (error) {
      const message = (error as Error).message;
      if (message === 'UI_SCOPE_NOT_CONFIGURED') { json(res, 409, { error: 'scope_not_configured', message: 'Configure compliance.tenant/project or policy.context tenant/project before browsing stored runs.' }); return; }
      json(res, 500, { error: 'request_failed', message });
    }
  });
  await new Promise<void>((resolvePromise, reject) => { server.once('error', reject); server.listen(options.port, options.host, () => resolvePromise()); });
  const address = server.address() as AddressInfo;
  return { server, host: address.address, port: address.port, url: `http://${isLoopback(options.host) ? '127.0.0.1' : options.host}:${address.port}` };
}
