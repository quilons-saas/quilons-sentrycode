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
  policy: {
    failOn: ['high', 'critical'],
    warnOn: ['medium'],
    requiredScanners: ['secrets']
  },
  waiversFile: '.sentrycode/waivers.json'
};
