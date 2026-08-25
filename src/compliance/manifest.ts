import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { PluginManifest } from './contracts.js';
import { COMPLIANCE_API_VERSION, SENTRYCODE_PLUGIN_ID } from './contracts.js';

const CAPABILITIES = [
  { id: 'sentrycode.scan', version: '1.0.0', description: 'Run software engineering compliance scans.', operations: ['scan', 'check'] },
  { id: 'sentrycode.findings', version: '1.0.0', description: 'Query normalized SentryCode findings by run.', operations: ['list', 'get'] },
  { id: 'sentrycode.evidence', version: '1.0.0', description: 'Publish and query versioned compliance evidence envelopes.', operations: ['publish', 'list', 'get'] },
  { id: 'sentrycode.policy', version: '1.0.0', description: 'Expose effective policy and release decisions.', operations: ['status', 'evaluate'] },
  { id: 'sentrycode.waivers', version: '1.0.0', description: 'Expose governed waiver state without granting cross-module database access.', operations: ['status'] },
  { id: 'sentrycode.health', version: '1.0.0', description: 'Health and readiness probes for installer/platform integration.', operations: ['health', 'ready'] }
] as const;

export async function loadPluginManifest(root: string): Promise<PluginManifest> {
  let productVersion = '0.0.0';
  try {
    const pkg = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8')) as { version?: unknown };
    if (typeof pkg.version === 'string') productVersion = pkg.version;
  } catch {
    // Keep manifest usable from packaged/dist contexts where package.json may not be available.
  }
  return {
    schemaVersion: 1,
    pluginId: SENTRYCODE_PLUGIN_ID,
    product: 'QUILONS SentryCode',
    productVersion,
    apiVersion: COMPLIANCE_API_VERSION,
    standalone: true,
    capabilities: CAPABILITIES.map((item) => ({ ...item, operations: [...item.operations] })),
    health: { command: 'sentrycode compliance health' },
    readiness: { command: 'sentrycode compliance ready' },
    evidenceTypes: [
      'secret.scan', 'sbom.generated', 'dependency.check', 'license.check', 'vuln.scan', 'sast.scan',
      'commit.verification', 'build.attestation', 'provenance.attestation', 'policy.eval', 'release.gate'
    ]
  };
}
