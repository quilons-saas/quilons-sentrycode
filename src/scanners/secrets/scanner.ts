import { readFile } from 'node:fs/promises';
import { relative } from 'node:path';
import { discoverFiles } from '../../core/files.js';
import { SCHEMA_VERSION, type Finding, type ScannerContext, type ScannerPlugin, type ScannerResult } from '../../core/types.js';
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
}): Finding {
  const fingerprint = stableId('fp', `${args.ruleId}|${args.path}|${args.line}|${args.matched}`);
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

export class SecretsScanner implements ScannerPlugin {
  readonly id = 'secrets';
  readonly version = '0.1.0';

  async scan(context: ScannerContext): Promise<ScannerResult> {
    const started = performance.now();
    const detectedAt = context.now().toISOString();
    const findings: Finding[] = [];
    if (!context.config.secrets.enabled) {
      return { scanner: this.id, findings, evidence: [], durationMs: Math.round(performance.now() - started), status: 'skipped', error: 'scanner disabled by configuration' };
    }

    const custom: SecretPattern[] = context.config.secrets.customPatterns.map((pattern) => ({
      id: pattern.id,
      regex: new RegExp(pattern.pattern, 'g'),
      severity: pattern.severity,
      title: `Custom secret pattern: ${pattern.id}`,
      description: pattern.description ?? `Repository content matched custom secret rule ${pattern.id}.`
    }));
    const patterns = [...BUILTIN_SECRET_PATTERNS, ...custom];
    const files = await discoverFiles(context.repository.root, context.config, context.execution?.mode === 'incremental' ? context.execution.changedFiles : undefined);

    for (const absolute of files) {
      let content: string;
      try {
        content = await readFile(absolute, 'utf8');
      } catch {
        continue;
      }
      if (content.includes('\u0000')) continue;
      const path = relative(context.repository.root, absolute).replace(/\\/g, '/');

      for (const pattern of patterns) {
        pattern.regex.lastIndex = 0;
        for (const match of content.matchAll(pattern.regex)) {
          const matched = match[1] ?? match[0];
          const index = (match.index ?? 0) + (match[0].indexOf(matched));
          const pos = lineAndColumn(content, index);
          findings.push(buildFinding({
            scanner: this.id,
            ruleId: pattern.id,
            title: pattern.title,
            description: pattern.description,
            severity: pattern.severity,
            path,
            line: pos.line,
            column: pos.column,
            matched,
            detectedAt
          }));
        }
      }

      if (context.config.secrets.highEntropy) {
        const tokenRegex = /\b[A-Za-z0-9+/=_\-.]{24,128}\b/g;
        for (const match of content.matchAll(tokenRegex)) {
          const value = match[0];
          if (isLikelyNonSecretToken(value)) continue;
          if (!looksLikeHighEntropySecret(value, context.config.secrets.minEntropyLength)) continue;
          const pos = lineAndColumn(content, match.index ?? 0);
          findings.push(buildFinding({
            scanner: this.id,
            ruleId: 'high-entropy-token',
            title: 'High-entropy token detected',
            description: 'A high-entropy token that may be a credential was found.',
            severity: 'high',
            path,
            line: pos.line,
            column: pos.column,
            matched: value,
            detectedAt
          }));
        }
      }
    }

    const unique = [...new Map(findings.map((finding) => [finding.fingerprint, finding])).values()];
    const evidence = [{
      schemaVersion: SCHEMA_VERSION,
      id: stableId('evidence', `${context.repository.commitSha}|secrets|${detectedAt}`),
      type: 'secret.scan',
      scanner: this.id,
      repository: context.repository.repository,
      commitSha: context.repository.commitSha,
      branch: context.repository.branch,
      generatedAt: detectedAt,
      findingIds: unique.map((finding) => finding.id),
      metadata: {
        scannerVersion: this.version,
        filesScanned: files.length,
        findingCount: unique.length
      }
    }];

    return {
      scanner: this.id,
      findings: unique,
      evidence,
      durationMs: Math.round(performance.now() - started)
    };
  }
}
