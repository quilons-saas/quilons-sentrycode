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
    historyMaxCommits: 500,
    customPatterns: []
  },
  dependencies: {
    enabled: true,
    includeDev: true,
    allowedRegistries: [],
    deniedRegistries: [],
    deniedPackages: [],
    allowedPackages: [],
    versionRestrictions: {},
    maintenance: { enabled: false, metadataFile: '.sentrycode/dependency-health.json', maxReleaseAgeDays: 730, denyDeprecated: true, requireMetadata: false }
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
    failOnKnownExploited: true,
    osv: { enabled: true, endpoint: 'https://api.osv.dev', timeoutMs: 20000 }
  },
  sbom: {
    defaultFormat: 'cyclonedx'
  },
  sast: { enabled: true, languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'c', 'cpp', 'rust', 'go'], external: { enabled: false, command: '', args: [], sarifFile: '.sentrycode/external-sast.sarif', timeoutMs: 120000 } },
  gitAssurance: { enabled: true, requireCleanTree: false, requireSignedCommit: false, allowedEmailDomains: [], github: { enabled: false, tokenEnv: 'GITHUB_TOKEN', apiBaseUrl: 'https://api.github.com', requireProtectedBranch: true, minimumApprovals: 1, requireStatusChecks: true }, gerrit: { enabled: false, apiBaseUrl: '', authMode: 'bearer', tokenEnv: 'SENTRYCODE_GERRIT_TOKEN', usernameEnv: 'SENTRYCODE_GERRIT_USERNAME', passwordEnv: 'SENTRYCODE_GERRIT_PASSWORD', requiredLabels: { 'Code-Review': 2, Verified: 1 }, publishReview: true, voteLabel: 'Verified', passVote: 1, warnVote: 0, failVote: -1, notify: 'OWNER_REVIEWERS', failClosed: true, timeoutMs: 15000 } },
  provenance: { enabled: true, artifactPaths: [], signingPrivateKeyFile: '', signingPublicKeyFile: '' },
  automotive: { enabled: false, importDirectory: '.sentrycode/automotive/findings', deviationsFile: '.sentrycode/automotive/deviations.json', acceptedStandards: ['misra-c', 'misra-cpp', 'autosar-cpp'], requireDeviationApproval: true, requireInputs: true, evidenceTargets: ['iso-sae-21434', 'unece-r155', 'unece-r156'] },
  ci: { enabled: true, provider: 'auto', annotations: true },
  monorepo: { enabled: true, serviceRoots: [], discoverWorkspaces: true },
  incremental: { enabled: true, baseRef: '', headRef: 'HEAD', cacheFile: '.sentrycode/cache/incremental.json', scannerTimeoutMs: 120000 },
  compliance: { enabled: false, tenant: '', project: '', storeDirectory: '.sentrycode/compliance', endpoint: '', tokenEnv: 'SENTRYCODE_COMPLIANCE_TOKEN', timeoutMs: 15000, listenHost: '127.0.0.1', listenPort: 7786, apiTokenEnv: 'SENTRYCODE_PLUGIN_API_TOKEN', authMode: 'static', hmacSecretEnv: 'SENTRYCODE_PLUGIN_HMAC_SECRET', tokenIssuer: 'quilons-compliance', tokenAudience: 'quilons.sentrycode' },
  craReporting: { enabled: false, endpoint: '', tokenEnv: 'SENTRYCODE_CRA_TOKEN', timeoutMs: 15000, maxAttempts: 5, retryDelayMs: 30000, severities: ['high', 'critical'], findingTypes: [] },
  offline: { enabled: false, requireSignedIntelligenceBundles: false, intelligencePublicKeyFile: '' },
  integrity: { requireSignedConfig: false, configSignatureFile: '.sentrycode/config.sig.json', publicKeyFile: '', auditLogFile: '.sentrycode/audit/events.jsonl', evidenceManifests: true, evidenceSigningPrivateKeyFile: '', evidenceSigningPublicKeyFile: '' },
  operations: { backupDirectory: '.sentrycode/backups', retentionDays: 365 },
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
