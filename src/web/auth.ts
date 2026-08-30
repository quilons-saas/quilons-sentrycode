import { createPublicKey, verify } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { ApplicationStateStore } from '../application/store.js';
import type { AdminRole, PrincipalRecord } from '../application/types.js';

export interface WebAuthSession {
  subject: string;
  displayName: string;
  role: AdminRole;
  mode: 'local-token' | 'oidc';
}
export interface OidcRuntimeConfig {
  enabled: boolean;
  issuer: string;
  audience: string;
  jwksUri: string;
}
const rank: Record<AdminRole, number> = { viewer: 1, engineer: 2, security_admin: 3, administrator: 4 };
export function roleAllows(actual: AdminRole, required: AdminRole): boolean { return rank[actual] >= rank[required]; }
export function oidcRuntimeConfig(): OidcRuntimeConfig {
  const issuer=(process.env.SENTRYCODE_OIDC_ISSUER??'').replace(/\/+$/,'');
  const audience=process.env.SENTRYCODE_OIDC_AUDIENCE??'';
  const jwksUri=process.env.SENTRYCODE_OIDC_JWKS_URI??'';
  return { enabled:Boolean(issuer&&audience), issuer, audience, jwksUri };
}
function b64url(value:string):Buffer { return Buffer.from(value.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(value.length/4)*4,'='),'base64'); }
function audOk(value:unknown, expected:string):boolean { return typeof value==='string'?value===expected:Array.isArray(value)&&value.includes(expected); }
let cache:{uri:string;at:number;keys:any[]}|null=null;
async function jwks(uri:string,issuer:string):Promise<any[]>{
  let actual=uri;
  if(!actual){
    const discovery=await fetch(`${issuer}/.well-known/openid-configuration`,{headers:{accept:'application/json'}});
    if(!discovery.ok)throw new Error(`OIDC_DISCOVERY_UNAVAILABLE:${discovery.status}`);
    const metadata=await discovery.json() as {jwks_uri?:string};
    if(!metadata.jwks_uri)throw new Error('OIDC_DISCOVERY_INVALID');
    actual=metadata.jwks_uri;
  }
  if(cache&&cache.uri===actual&&Date.now()-cache.at<300_000)return cache.keys;
  const r=await fetch(actual,{headers:{accept:'application/json'}});
  if(!r.ok)throw new Error(`OIDC_JWKS_UNAVAILABLE:${r.status}`);
  const body=await r.json() as {keys?:any[]};
  if(!Array.isArray(body.keys))throw new Error('OIDC_JWKS_INVALID');
  cache={uri:actual,at:Date.now(),keys:body.keys}; return body.keys;
}
async function verifyOidc(token:string, store:ApplicationStateStore):Promise<WebAuthSession>{
  const cfg=oidcRuntimeConfig(); if(!cfg.enabled)throw new Error('OIDC_NOT_CONFIGURED');
  const parts=token.split('.'); if(parts.length!==3)throw new Error('OIDC_TOKEN_INVALID');
  const header=JSON.parse(b64url(parts[0]!).toString('utf8')) as {alg?:string;kid?:string};
  const claims=JSON.parse(b64url(parts[1]!).toString('utf8')) as Record<string,unknown>;
  if(header.alg!=='RS256'||!header.kid)throw new Error('OIDC_TOKEN_ALG_UNSUPPORTED');
  if(claims.iss!==cfg.issuer||!audOk(claims.aud,cfg.audience))throw new Error('OIDC_TOKEN_SCOPE_INVALID');
  const now=Math.floor(Date.now()/1000);
  if(typeof claims.exp!=='number'||claims.exp<=now)throw new Error('OIDC_TOKEN_EXPIRED');
  if(typeof claims.nbf==='number'&&claims.nbf>now+30)throw new Error('OIDC_TOKEN_NOT_ACTIVE');
  const key=(await jwks(cfg.jwksUri,cfg.issuer)).find((k:any)=>k.kid===header.kid&&k.kty==='RSA');
  if(!key)throw new Error('OIDC_KEY_NOT_FOUND');
  const ok=verify('RSA-SHA256',Buffer.from(`${parts[0]}.${parts[1]}`),createPublicKey({key,format:'jwk'} as any),b64url(parts[2]!));
  if(!ok)throw new Error('OIDC_SIGNATURE_INVALID');
  const subject=String(claims.sub??''); if(!subject)throw new Error('OIDC_SUBJECT_MISSING');
  const principal=(await store.listPrincipals()).find((p)=>p.subject===subject&&p.enabled);
  if(!principal)throw new Error('OIDC_PRINCIPAL_NOT_AUTHORIZED');
  return {subject,displayName:principal.displayName,role:principal.role,mode:'oidc'};
}
export async function authenticateRequest(req:IncomingMessage, store:ApplicationStateStore, adminToken?:string):Promise<WebAuthSession|null>{
  const raw=req.headers.authorization??''; const token=raw.startsWith('Bearer ')?raw.slice(7):'';
  if(adminToken&&token===adminToken){
    const actorHeader=req.headers['x-sentrycode-actor'];
    const displayName=typeof actorHeader==='string'&&actorHeader.trim()?actorHeader.trim():'local-admin';
    return {subject:'local-admin',displayName,role:'administrator',mode:'local-token'};
  }
  if(token&&oidcRuntimeConfig().enabled)return verifyOidc(token,store);
  return null;
}
export function publicPrincipal(value:PrincipalRecord){return {id:value.id,subject:value.subject,displayName:value.displayName,role:value.role,enabled:value.enabled,createdAt:value.createdAt,updatedAt:value.updatedAt};}
