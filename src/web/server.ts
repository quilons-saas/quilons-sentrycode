import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';
import type { ComplianceIdentity } from '../compliance/contracts.js';
import type { SentryCodeConfig } from '../core/types.js';
import { createApplicationStateStore } from '../application/factory.js';
import type { ApplicationStateStore } from '../application/store.js';
import { SentryCodeAdminService } from '../application/admin-service.js';
import { SentryCodeWebService } from './service.js';
import { authenticateRequest, oidcRuntimeConfig, roleAllows, type WebAuthSession } from './auth.js';
import { applyOperationalRetention, automotiveStatus, createOperationalBackup, enterpriseStatus, restoreOperationalBackup, synchronizeIntelligence } from './operations.js';

export interface WebServerOptions { host: string; port: number; token?: string; adminToken?: string; assetRoot?: string; applicationStore?: ApplicationStateStore; }
function isLoopback(host: string): boolean { return host === '127.0.0.1' || host === '::1' || host === 'localhost'; }
function bearer(req: IncomingMessage): string { const value = req.headers.authorization ?? ''; return value.startsWith('Bearer ') ? value.slice(7) : ''; }
function json(res: ServerResponse, status: number, body: unknown): void { const content = `${JSON.stringify(body, null, 2)}\n`; res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(content), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }); res.end(content); }
function mime(path: string): string { const ext = extname(path); return ext === '.html' ? 'text/html; charset=utf-8' : ext === '.css' ? 'text/css; charset=utf-8' : ext === '.js' ? 'text/javascript; charset=utf-8' : ext === '.svg' ? 'image/svg+xml' : ext === '.png' ? 'image/png' : 'application/octet-stream'; }
function safeAsset(root: string, pathname: string): string { const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, ''); const candidate = resolve(root, relative); if (!candidate.startsWith(resolve(root))) throw new Error('invalid_asset_path'); return candidate; }
async function body(req: IncomingMessage): Promise<any> { const chunks: Buffer[]=[]; let size=0; for await (const chunk of req){ const b=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk); size+=b.length; if(size>1_048_576) throw new Error('request_body_too_large'); chunks.push(b); } if(!chunks.length) return {}; try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw new Error('invalid_json');} }
function actor(req:IncomingMessage):string { const value=req.headers['x-sentrycode-actor']; return typeof value==='string'&&value.trim()?value.trim():'local-admin'; }
function requiredRole(path:string,method:string): 'viewer'|'engineer'|'security_admin'|'administrator' {
  if(path==='/api/v1/admin/session') return 'viewer';
  if(method==='GET') return 'viewer';
  if(path==='/api/v1/admin/waivers'&&method==='POST') return 'engineer';
  if(path.includes('/scanners')||path==='/api/v1/admin/policies'||path==='/api/v1/admin/operations/intelligence-sync'||/\/api\/v1\/admin\/waivers\/[^/]+\/(approve|reject|revoke)$/.test(path)) return 'security_admin';
  return 'administrator';
}

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
  const applicationStore = options.applicationStore ?? await createApplicationStateStore();
  const admin = new SentryCodeAdminService(repositoryRoot, config, identity, applicationStore);
  const assetRoot = options.assetRoot ?? resolve(dirname(fileURLToPath(import.meta.url)), '../../ui');
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      if (url.pathname.startsWith('/api/')) {
        const isAdmin=url.pathname.startsWith('/api/v1/admin/');
        const supplied=bearer(req);
        const publicProbe=(url.pathname==='/api/v1/health'||url.pathname==='/api/v1/ready')&&req.method==='GET';
        if(!isAdmin && !publicProbe && options.token && supplied!==options.token){
          const webSession=await authenticateRequest(req,applicationStore,options.adminToken);
          if(!webSession){ json(res,401,{error:'unauthorized'}); return; }
        }
        let session:WebAuthSession|null=null;
        const isPublicAdminState=url.pathname==='/api/v1/admin/state'&&req.method==='GET';
        if(isAdmin&&!isPublicAdminState){
          if(options.token&&supplied===options.token) session={subject:'ui-viewer',displayName:'UI Viewer',role:'viewer',mode:'local-token'};
          else session=await authenticateRequest(req,applicationStore,options.adminToken);
          if(!session){
            const oidc=oidcRuntimeConfig();
            if(!options.adminToken&&!oidc.enabled){json(res,503,{error:'administration_locked',message:'Set SENTRYCODE_UI_ADMIN_TOKEN or configure enterprise OIDC to enable administration.'});return;}
            json(res,401,{error:'admin_unauthorized',message:oidc.enabled?'Provide a valid local administrator or authorized OIDC token.':'Provide the SENTRYCODE_UI_ADMIN_TOKEN.'}); return;
          }
          const required=requiredRole(url.pathname,req.method??'GET');
          if(!roleAllows(session.role,required)){json(res,403,{error:'forbidden',message:`${required} role required`});return;}
        }
        if (url.pathname === '/api/v1/health' && req.method==='GET') { json(res,200,{product:'QUILONS SentryCode',health:'ok'}); return; }
        if (url.pathname === '/api/v1/ready' && req.method==='GET') { const [web,db]=await Promise.all([service.status(),applicationStore.status()]); const ready=Boolean(web.ready&&db.connected); json(res,ready?200:503,{ready,webReady:web.ready,databaseReady:db.connected,schemaVersion:db.schemaVersion}); return; }
        if (url.pathname === '/api/v1/status' && req.method==='GET') { json(res, 200, await service.status()); return; }
        if (url.pathname === '/api/v1/dashboard' && req.method==='GET') { json(res, 200, await service.dashboard()); return; }
        if (url.pathname === '/api/v1/repositories' && req.method==='GET') { json(res, 200, await service.repositories()); return; }
        if (url.pathname === '/api/v1/runs' && req.method==='GET') { json(res, 200, await service.listRuns()); return; }
        if (url.pathname === '/api/v1/findings' && req.method==='GET') { json(res, 200, await service.findings()); return; }
        if (url.pathname === '/api/v1/config' && req.method==='GET') { json(res, 200, service.configSummary()); return; }
        const run = /^\/api\/v1\/runs\/([A-Za-z0-9._-]+)$/.exec(url.pathname);
        if (run && req.method==='GET') { const value = await service.runDetail(run[1]!); json(res, value ? 200 : 404, value ?? { error: 'run_not_found' }); return; }

        if(url.pathname==='/api/v1/admin/session'&&req.method==='POST'){ json(res,200,{authenticated:true,actor:session!.displayName,subject:session!.subject,displayName:session!.displayName,role:session!.role,mode:session!.mode}); return; }
        if(url.pathname==='/api/v1/admin/state'&&req.method==='GET'){ json(res,200,await admin.state()); return; }
        if(url.pathname==='/api/v1/admin/repositories'&&req.method==='GET'){ json(res,200,await admin.repositories()); return; }
        if(url.pathname==='/api/v1/admin/repositories'&&req.method==='POST'){ json(res,201,await admin.registerRepository(await body(req),session!.displayName)); return; }
        const scanners=/^\/api\/v1\/admin\/repositories\/([^/]+)\/scanners$/.exec(url.pathname);
        if(scanners&&req.method==='GET'){ json(res,200,await admin.scanners(decodeURIComponent(scanners[1]!))); return; }
        if(scanners&&req.method==='PUT'){ const repositoryId=decodeURIComponent(scanners[1]!); const value=await admin.setScanner(repositoryId,await body(req),session!.displayName); const repos=await admin.repositories(); const repo=repos.find(x=>x.id===repositoryId); const materialized=repo?await admin.materializeScannerConfig(repo,await admin.scanners(repositoryId)):null; json(res,200,{setting:value,materialized}); return; }
        if(url.pathname==='/api/v1/admin/policies'&&req.method==='GET'){ json(res,200,await admin.policies()); return; }
        if(url.pathname==='/api/v1/admin/policies'&&req.method==='PUT'){ const p=await admin.setPolicy(await body(req),session!.displayName); const repos=await admin.repositories(); const targets=p.repositoryId?repos.filter(x=>x.id===p.repositoryId):repos; const materialized=[]; for(const repo of targets) materialized.push(await admin.materializePolicy(repo,p)); json(res,200,{policy:p,materialized}); return; }
        if(url.pathname==='/api/v1/admin/waivers'&&req.method==='GET'){ json(res,200,await admin.waivers()); return; }
        if(url.pathname==='/api/v1/admin/waivers'&&req.method==='POST'){ const value=await admin.requestWaiver(await body(req),session!.displayName); const repos=await admin.repositories(); const waivers=await admin.waivers(); for(const repo of repos.filter(x=>!value.repositoryId||x.id===value.repositoryId)) await admin.materializeWaivers(repo,waivers.filter(x=>!x.repositoryId||x.repositoryId===repo.id)); json(res,201,value); return; }
        const waiver=/^\/api\/v1\/admin\/waivers\/([^/]+)\/(approve|reject|revoke)$/.exec(url.pathname);
        if(waiver&&req.method==='POST'){ const status=waiver[2]==='approve'?'active':waiver[2]==='reject'?'rejected':'revoked'; const value=await admin.decideWaiver(decodeURIComponent(waiver[1]!),status,session!.displayName); if(value){ const repos=await admin.repositories(); const waivers=await admin.waivers(); for(const repo of repos.filter(x=>!value.repositoryId||x.id===value.repositoryId)) await admin.materializeWaivers(repo,waivers.filter(x=>!x.repositoryId||x.repositoryId===repo.id)); } json(res,value?200:404,value??{error:'waiver_not_found'}); return; }
        if(url.pathname==='/api/v1/admin/integrations'&&req.method==='GET'){ json(res,200,await admin.integrations()); return; }
        if(url.pathname==='/api/v1/admin/integrations'&&req.method==='PUT'){ json(res,200,await admin.setIntegration(await body(req),session!.displayName)); return; }
        if(url.pathname==='/api/v1/admin/principals'&&req.method==='GET'){ json(res,200,await admin.principals()); return; }
        if(url.pathname==='/api/v1/admin/principals'&&req.method==='PUT'){ json(res,200,await admin.setPrincipal(await body(req),session!.displayName)); return; }
        if(url.pathname==='/api/v1/admin/enterprise'&&req.method==='GET'){ json(res,200,await enterpriseStatus(repositoryRoot,config)); return; }
        if(url.pathname==='/api/v1/admin/operations/backup'&&req.method==='POST'){ json(res,201,await createOperationalBackup(repositoryRoot,config,session!.displayName)); return; }
        if(url.pathname==='/api/v1/admin/operations/retention'&&req.method==='POST'){ json(res,200,await applyOperationalRetention(repositoryRoot,config,session!.displayName)); return; }
        if(url.pathname==='/api/v1/admin/operations/restore'&&req.method==='POST'){ const input=await body(req); json(res,200,await restoreOperationalBackup(repositoryRoot,config,String(input.backupPath??''),session!.displayName)); return; }
        if(url.pathname==='/api/v1/admin/operations/intelligence-sync'&&req.method==='POST'){ json(res,200,await synchronizeIntelligence(repositoryRoot,config,session!.displayName)); return; }
        if(url.pathname==='/api/v1/admin/automotive'&&req.method==='GET'){ json(res,200,await automotiveStatus(repositoryRoot,config)); return; }
        if(url.pathname==='/api/v1/admin/auth'&&req.method==='GET'){ const oidc=oidcRuntimeConfig(); json(res,200,{session,oidc:{enabled:oidc.enabled,issuer:oidc.issuer||null,audience:oidc.audience||null}}); return; }
        if(url.pathname==='/api/v1/admin/audit'&&req.method==='GET'){ json(res,200,await admin.audit()); return; }
        json(res, 404, { error: 'not_found' }); return;
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') { json(res, 405, { error: 'method_not_allowed' }); return; }
      await sendAsset(res, assetRoot, url.pathname);
    } catch (error) {
      const message = (error as Error).message;
      if (message === 'UI_SCOPE_NOT_CONFIGURED') { json(res, 409, { error: 'scope_not_configured', message: 'Configure compliance.tenant/project or policy.context tenant/project before browsing stored runs.' }); return; }
      if(message==='DATABASE_NOT_CONFIGURED'){json(res,503,{error:'database_not_configured',message:'Set SENTRYCODE_DATABASE_URL and run sentrycode database migrate.'});return;}
      if(message==='SIGNED_CONFIG_WRITE_BLOCKED'){json(res,409,{error:'signed_config_write_blocked',message:'UI file materialization is blocked while signed configuration enforcement is enabled.'});return;}
      if(message==='REPOSITORY_SCOPE_MISMATCH'){json(res,404,{error:'repository_not_found'});return;}
      if(message==='invalid_json'){json(res,400,{error:'invalid_json'});return;}
      json(res, 500, { error: 'request_failed', message });
    }
  });
  server.on('close',()=>{void applicationStore.close();});
  await new Promise<void>((resolvePromise, reject) => { server.once('error', reject); server.listen(options.port, options.host, () => resolvePromise()); });
  const address = server.address() as AddressInfo;
  return { server, host: address.address, port: address.port, url: `http://${isLoopback(options.host) ? '127.0.0.1' : options.host}:${address.port}` };
}
