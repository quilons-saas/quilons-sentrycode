import { createHmac, timingSafeEqual } from 'node:crypto';
import type { ComplianceIdentity } from './contracts.js';

export interface ComplianceTokenClaims {
  schemaVersion: 1;
  tenant: string;
  project: string;
  iss: string;
  aud: string;
  exp: number;
}
function b64(value: string): string { return Buffer.from(value).toString('base64url'); }
function mac(payload: string, secret: string): string { return createHmac('sha256', secret).update(payload).digest('base64url'); }

export function issueComplianceToken(identity: ComplianceIdentity, secret: string, options: { issuer: string; audience: string; ttlSeconds?: number; now?: number }): string {
  if (!secret) throw new Error('Compliance HMAC secret is required');
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const claims: ComplianceTokenClaims = { schemaVersion: 1, tenant: identity.tenant, project: identity.project, iss: options.issuer, aud: options.audience, exp: now + (options.ttlSeconds ?? 900) };
  const payload = b64(JSON.stringify(claims));
  return `${payload}.${mac(payload, secret)}`;
}

export function verifyComplianceToken(token: string, secret: string, options: { issuer: string; audience: string; now?: number }): ComplianceTokenClaims {
  const [payload, signature] = token.split('.');
  if (!payload || !signature || !secret) throw new Error('invalid compliance token');
  const expected = Buffer.from(mac(payload, secret)); const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new Error('invalid compliance token signature');
  let claims: ComplianceTokenClaims;
  try { claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as ComplianceTokenClaims; } catch { throw new Error('invalid compliance token payload'); }
  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (claims.schemaVersion !== 1 || !claims.tenant || !claims.project || claims.iss !== options.issuer || claims.aud !== options.audience || !Number.isFinite(claims.exp) || claims.exp <= now) throw new Error('invalid or expired compliance token claims');
  return claims;
}
