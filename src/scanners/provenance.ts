import { resolve } from 'node:path';
import { SCHEMA_VERSION, type ScannerContext, type ScannerPlugin, type ScannerResult } from '../core/types.js';
import { buildStatement, collectArtifacts, signStatement } from '../provenance/attestation.js';
import { stableId } from '../utils/hash.js';

export class ProvenanceScanner implements ScannerPlugin {
  readonly id = 'provenance';
  readonly version = '0.1.0';

  async scan(context: ScannerContext): Promise<ScannerResult> {
    const started = performance.now();
    const generatedAt = context.now().toISOString();
    if (!context.config.provenance.enabled) {
      return { scanner: this.id, findings: [], evidence: [], durationMs: Math.round(performance.now() - started), status: 'skipped', error: 'scanner disabled by configuration' };
    }
    const artifacts = await collectArtifacts(context.repository.root, context.config.provenance.artifactPaths);
    const statement = buildStatement(context.repository, artifacts, new Date(generatedAt));
    const keyFile = context.config.provenance.signingPrivateKeyFile
      ? resolve(context.repository.root, context.config.provenance.signingPrivateKeyFile)
      : undefined;
    const attestation = await signStatement(statement, keyFile);
    const common = {
      schemaVersion: SCHEMA_VERSION,
      scanner: this.id,
      repository: context.repository.repository,
      commitSha: context.repository.commitSha,
      branch: context.repository.branch,
      generatedAt,
      findingIds: [] as string[],
      metadata: {
        scannerVersion: this.version,
        artifactCount: artifacts.length,
        artifactDigests: JSON.stringify(artifacts.map((item) => ({ path: item.path, sha256: item.sha256, size: item.size }))),
        signed: attestation.algorithm !== 'none',
        publicKeyFingerprint: attestation.publicKeyFingerprint ?? null,
        builder: `node:${process.version}`
      }
    };
    return {
      scanner: this.id,
      findings: [],
      evidence: [
        { ...common, id: stableId('evidence', `${context.repository.commitSha}|build.attestation|${generatedAt}`), type: 'build.attestation' },
        { ...common, id: stableId('evidence', `${context.repository.commitSha}|provenance.attestation|${generatedAt}`), type: 'provenance.attestation' }
      ],
      durationMs: Math.round(performance.now() - started)
    };
  }
}
