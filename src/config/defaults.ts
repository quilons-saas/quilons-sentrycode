import type { SentryCodeConfig } from '../core/types.js';

export const DEFAULT_CONFIG: SentryCodeConfig = {
  schemaVersion: 1,
  scan: {
    include: ['**/*'],
    exclude: [
      '.git/**',
      'node_modules/**',
      'dist/**',
      'build/**',
      'coverage/**',
      '.next/**',
      '.venv/**',
      'venv/**',
      '**/*.lock',
      '**/*.png',
      '**/*.jpg',
      '**/*.jpeg',
      '**/*.gif',
      '**/*.pdf',
      '**/*.zip'
    ],
    maxFileBytes: 2_000_000
  },
  secrets: {
    enabled: true,
    highEntropy: true,
    minEntropyLength: 24,
    customPatterns: []
  },
  dependencies: {
    enabled: true,
    includeDev: true,
    allowedRegistries: [],
    deniedPackages: [],
    allowedPackages: [],
    versionRestrictions: {}
  },
  licenses: {
    enabled: true,
    allowed: [],
    denied: ['AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'SSPL-1.0'],
    reviewRequired: ['GPL-2.0', 'GPL-3.0', 'LGPL-2.1', 'LGPL-3.0'],
    unknown: 'warn',
    overrides: {}
  },
  vulnerabilities: {
    enabled: true,
    databaseFile: '.sentrycode/vulnerability-db.json',
    failOnKnownExploited: true
  },
  sbom: {
    defaultFormat: 'cyclonedx'
  },
  sast: { enabled: true, languages: ['javascript', 'typescript', 'python'] },
  gitAssurance: { enabled: true, requireCleanTree: false, requireSignedCommit: false, allowedEmailDomains: [] },
  provenance: { enabled: true, artifactPaths: [], signingPrivateKeyFile: '', signingPublicKeyFile: '' },
  policy: {
    failOn: ['high', 'critical'],
    warnOn: ['medium'],
    requiredScanners: ['secrets', 'dependencies', 'sast', 'git-assurance'],
    directory: '.sentrycode/policies',
    scannerFailureModes: {
      secrets: 'fail',
      dependencies: 'fail',
      sast: 'fail',
      'git-assurance': 'fail'
    },
    context: {},
    opa: {
      enabled: false,
      binary: 'opa',
      query: 'data.sentrycode.release.decision',
      policyFiles: []
    }
  },
  waivers: {
    file: '.sentrycode/waivers.json',
    requireApproval: false,
    requireTicket: false,
    maxDurationDays: 90
  },
  waiversFile: '.sentrycode/waivers.json'
};
