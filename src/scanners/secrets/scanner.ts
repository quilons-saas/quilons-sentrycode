import { readFile } from 'node:fs/promises';
import { relative } from 'node:path';
import { discoverFiles } from '../../core/files.js';
import { SCHEMA_VERSION, type Finding, type ScannerContext, type ScannerPlugin, type ScannerResult, type SentryCodeConfig } from '../../core/types.js';
import { stableId } from '../../utils/hash.js';
import { looksLikeHighEntropySecret } from './entropy.js';
import { BUILTIN_SECRET_PATTERNS, type SecretPattern } from './patterns.js';

function lineAndColumn(content: string, index: number): { line: number; column: number } {
  const before = content.slice(0, index);
  const parts = before.split('\n');
  return { line: parts.length, column: (parts.at(-1)?.length ?? 0) + 1 };
}

function isLikelyNonSecretToken(value: string): boolean {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) return true;
  if (value.includes('/') && value.includes('.')) return true;
  if (/^(?:registry\.|www\.)/i.test(value)) return true;
  return false;
}

function redact(value: string): string {
  if (value.length <= 8) return '[REDACTED]';
  return `${value.slice(0, 3)}…${value.slice(-3)}`;
}

function buildFinding(args: {
  scanner: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Finding['severity'];
  path: string;
  line: number;
  column: number;
  matched: string;
  detectedAt: string;
  fingerprintSalt?: string;
}): Finding {
  const fingerprint = stableId('fp', `${args.ruleId}|${args.path}|${args.line}|${args.matched}|${args.fingerprintSalt ?? ''}`);
  return {
    schemaVersion: SCHEMA_VERSION,
    id: stableId('finding', `${fingerprint}|${args.detectedAt}`),
    type: 'secret',
    scanner: args.scanner,
    ruleId: args.ruleId,
    title: args.title,
    description: args.description,
    severity: args.severity,
    location: { path: args.path, line: args.line, column: args.column },
    fingerprint,
    remediation: 'Remove the secret from source control, rotate/revoke it if real, and store it in an approved secret manager or CI secret store.',
    detectedAt: args.detectedAt,
    metadata: { preview: redact(args.matched) }
  };
}

/** Scan an in-memory text payload. Full secret values never leave this function. */
export function scanSecretText(args: {
  path: string;
  content: string;
  config: SentryCodeConfig;
  detectedAt: string;
  scanner?: string;
  fingerprintSalt?: string;
}): Finding[] {
  if (args.content.includes('\u0000')) return [];
  const scanner = args.scanner ?? 'secrets';
  const findings: Finding[] = [];
  const custom: SecretPattern[] = args.config.secrets.customPatterns.map((pattern) => ({
    id: pattern.id,
    regex: new RegExp(pattern.pattern, 'g'),
    severity: pattern.severity,
    title: `Custom secret pattern: ${pattern.id}`,
    description: pattern.description ?? `Repository content matched custom secret rule ${pattern.id}.`
  }));
  const patterns = [...BUILTIN_SECRET_PATTERNS, ...custom];
  for (const pattern of patterns) {
    pattern.regex.lastIndex = 0;
    for (const match of args.content.matchAll(pattern.regex)) {
      const matched = match[1] ?? match[0];
      const index = (match.index ?? 0) + match[0].indexOf(matched);
      const pos = lineAndColumn(args.content, index);
      findings.push(buildFinding({ scanner, ruleId: pattern.id, title: pattern.title, description: pattern.description, severity: pattern.severity, path: args.path, line: pos.line, column: pos.column, matched, detectedAt: args.detectedAt, ...(args.fingerprintSalt ? { fingerprintSalt: args.fingerprintSalt } : {}) }));
    }
  }
  if (args.config.secrets.highEntropy) {
    const tokenRegex = /\b[A-Za-z0-9+/=_\-.]{24,128}\b/g;
    for (const match of args.content.matchAll(tokenRegex)) {
      const value = match[0];
      if (isLikelyNonSecretToken(value) || !looksLikeHighEntropySecret(value, args.config.secrets.minEntropyLength)) continue;
      const pos = lineAndColumn(args.content, match.index ?? 0);
      findings.push(buildFinding({ scanner, ruleId: 'high-entropy-token', title: 'High-entropy token detected', description: 'A high-entropy token that may be a credential was found.', severity: 'high', path: args.path, line: pos.line, column: pos.column, matched: value, detectedAt: args.detectedAt, ...(args.fingerprintSalt ? { fingerprintSalt: args.fingerprintSalt } : {}) }));
    }
  }
  return [...new Map(findings.map((finding) => [finding.fingerprint, finding])).values()];
}

export class SecretsScanner implements ScannerPlugin {
  readonly id = 'secrets';
  readonly version = '0.2.0';

  async scan(context: ScannerContext): Promise<ScannerResult> {
    const started = performance.now();
    const detectedAt = context.now().toISOString();
    if (!context.config.secrets.enabled) return { scanner: this.id, findings: [], evidence: [], durationMs: Math.round(performance.now() - started), status: 'skipped', error: 'scanner disabled by configuration' };
    const files = await discoverFiles(context.repository.root, context.config, context.execution?.mode === 'incremental' ? context.execution.changedFiles : undefined);
    const findings: Finding[] = [];
    for (const absolute of files) {
      let content: string;
      try { content = await readFile(absolute, 'utf8'); } catch { continue; }
      const path = relative(context.repository.root, absolute).replace(/\\/g, '/');
      findings.push(...scanSecretText({ path, content, config: context.config, detectedAt, scanner: this.id }));
    }
    const unique = [...new Map(findings.map((finding) => [finding.fingerprint, finding])).values()];
    return {
      scanner: this.id,
      findings: unique,
      evidence: [{
        schemaVersion: SCHEMA_VERSION,
        id: stableId('evidence', `${context.repository.commitSha}|secrets|${detectedAt}`),
        type: 'secret.scan',
        scanner: this.id,
        repository: context.repository.repository,
        commitSha: context.repository.commitSha,
        branch: context.repository.branch,
        generatedAt: detectedAt,
        findingIds: unique.map((finding) => finding.id),
        metadata: { scannerVersion: this.version, filesScanned: files.length, findingCount: unique.length }
      }],
      durationMs: Math.round(performance.now() - started)
    };
  }
}
