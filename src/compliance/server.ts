import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { ComplianceIdentity } from './contracts.js';
import { complianceIdentity } from './scope.js';
import { SentryCodeComplianceService } from './service.js';
import { verifyComplianceToken } from './auth.js';

export interface ComplianceServerOptions {
  host: string;
  port: number;
  token?: string;
  hmac?: { secret: string; issuer: string; audience: string };
}
function isLoopback(host: string): boolean { return host === '127.0.0.1' || host === '::1' || host === 'localhost'; }
function json(res: ServerResponse, status: number, body: unknown): void { const content = `${JSON.stringify(body, null, 2)}\n`; res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(content), 'cache-control': 'no-store' }); res.end(content); }
function queryIdentity(url: URL): ComplianceIdentity { return complianceIdentity(url.searchParams.get('tenant') ?? '', url.searchParams.get('project') ?? ''); }
function bearer(req: IncomingMessage): string { const value = req.headers.authorization ?? ''; return value.startsWith('Bearer ') ? value.slice(7) : ''; }

export async function startComplianceServer(service: SentryCodeComplianceService, options: ComplianceServerOptions) {
  if (!isLoopback(options.host) && !options.token && !options.hmac?.secret) throw new Error('A bearer token is required when Compliance API binds to a non-loopback host');
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      let claimedIdentity: ComplianceIdentity | undefined;
      if (options.hmac?.secret) {
        try { const claims = verifyComplianceToken(bearer(req), options.hmac.secret, { issuer: options.hmac.issuer, audience: options.hmac.audience }); claimedIdentity = complianceIdentity(claims.tenant, claims.project); }
        catch { json(res, 401, { error: 'unauthorized' }); return; }
      } else if (options.token && bearer(req) !== options.token) { json(res, 401, { error: 'unauthorized' }); return; }
      if (req.method !== 'GET') { json(res, 405, { error: 'method_not_allowed' }); return; }
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      if (url.pathname === '/v1/health') { json(res, 200, service.health()); return; }
      if (url.pathname === '/v1/ready') { const value = await service.readiness(); json(res, value.ready ? 200 : 503, value); return; }
      if (url.pathname === '/v1/manifest') { json(res, 200, await service.manifest()); return; }
      const scope = claimedIdentity ?? queryIdentity(url);
      if (claimedIdentity) {
        const requestedTenant = url.searchParams.get('tenant'); const requestedProject = url.searchParams.get('project');
        if ((requestedTenant && requestedTenant !== claimedIdentity.tenant) || (requestedProject && requestedProject !== claimedIdentity.project)) { json(res, 403, { error: 'scope_forbidden' }); return; }
      }
      if (url.pathname === '/v1/runs') { json(res, 200, await service.listRuns(scope)); return; }
      const match = /^\/v1\/runs\/([A-Za-z0-9._-]+)(?:\/(findings|evidence|policy|waivers))?$/.exec(url.pathname);
      if (!match) { json(res, 404, { error: 'not_found' }); return; }
      const runId = match[1]!; const view = match[2];
      const value = view === 'findings' ? await service.getFindings(scope, runId) : view === 'evidence' ? await service.getEvidence(scope, runId) : view === 'policy' ? await service.getPolicyStatus(scope, runId) : view === 'waivers' ? await service.getWaiverStatus(scope, runId) : await service.getRun(scope, runId);
      if (value === null) { json(res, 404, { error: 'run_not_found' }); return; }
      json(res, 200, value);
    } catch (error) { const message = (error as Error).message; json(res, message.includes('required for Compliance') ? 400 : 500, { error: 'request_failed', message }); }
  });
  await new Promise<void>((resolvePromise, reject) => { server.once('error', reject); server.listen(options.port, options.host, () => resolvePromise()); });
  const address = server.address() as AddressInfo;
  return { server, host: address.address, port: address.port };
}
