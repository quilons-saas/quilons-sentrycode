import type { EvidenceRecord, Finding, RepositoryContext } from '../core/types.js';
import { SCHEMA_VERSION } from '../core/types.js';
import { stableId } from '../utils/hash.js';
import type { AutomotiveEvidenceTarget } from './types.js';

export function automotiveAlignmentEvidence(repository: RepositoryContext, findings: Finding[], generatedAt: string, targets: AutomotiveEvidenceTarget[]): EvidenceRecord[] {
  const evidence: EvidenceRecord[] = [];
  for (const target of targets) {
    const relevant = target === 'unece-r156'
      ? findings.filter((finding) => String(finding.metadata?.tags ?? '').includes('software-update'))
      : findings;
    if (!relevant.length) continue;
    const type = target === 'unece-r156' ? 'automotive.software-update.assurance' : 'automotive.cybersecurity.engineering';
    evidence.push({
      schemaVersion: SCHEMA_VERSION,
      id: stableId('evidence', `${repository.commitSha}|${target}|${generatedAt}|${relevant.map((f) => f.id).sort().join(',')}`),
      type,
      scanner: 'automotive',
      repository: repository.repository,
      commitSha: repository.commitSha,
      branch: repository.branch,
      generatedAt,
      findingIds: relevant.map((finding) => finding.id),
      metadata: {
        evidenceTarget: target,
        evidenceNature: 'engineering-evidence-mapping',
        complianceConclusion: false,
        findingCount: relevant.length
      }
    });
  }
  return evidence;
}
