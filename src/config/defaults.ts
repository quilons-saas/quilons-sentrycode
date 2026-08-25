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
  ci: { enabled: true, provider: 'auto', annotations: true },
  monorepo: { enabled: true, serviceRoots: [], discoverWorkspaces: true },
  incremental: { enabled: true, baseRef: '', headRef: 'HEAD', cacheFile: '.sentrycode/cache/incremental.json', scannerTimeoutMs: 120000 },
  compliance: { enabled: false, tenant: '', project: '', storeDirectory: '.sentrycode/compliance', endpoint: '', tokenEnv: 'SENTRYCODE_COMPLIANCE_TOKEN', timeoutMs: 15000, listenHost: '127.0.0.1', listenPort: 7786, apiTokenEnv: 'SENTRYCODE_PLUGIN_API_TOKEN' },
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
