import type { Severity } from '../../core/types.js';

export interface SecretPattern {
  id: string;
  regex: RegExp;
  severity: Severity;
  title: string;
  description: string;
}

export const BUILTIN_SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'private-key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    severity: 'critical',
    title: 'Private key material detected',
    description: 'Private key material must not be committed to source control.'
  },
  {
    id: 'aws-access-key-id',
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    severity: 'critical',
    title: 'AWS access key identifier detected',
    description: 'An AWS access key identifier appears in repository content.'
  },
  {
    id: 'github-token',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/g,
    severity: 'critical',
    title: 'GitHub token detected',
    description: 'A GitHub credential appears in repository content.'
  },
  {
    id: 'generic-secret-assignment',
    regex: /\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret)\b\s*[:=]\s*["']([^"'\r\n]{8,})["']/gi,
    severity: 'high',
    title: 'Credential-like assignment detected',
    description: 'A credential-like value appears to be assigned directly in source or configuration.'
  }
];
