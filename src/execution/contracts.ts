import { createHash, timingSafeEqual } from 'node:crypto';

export const RUNNER_API_VERSION = 1 as const;
export const RUNNER_LABEL_PREFIX = 'com.quilons.sentrycode';

export type RunnerOutcome = 'completed' | 'failed' | 'cancelled' | 'timeout';
export type RunnerEventCode =
  | 'SCANNER_STARTING'
  | 'SCANNER_COMPLETED'
  | 'SCANNER_EXECUTION_FAILED'
  | 'SCANNER_LAUNCH_FAILED'
  | 'SCANNER_OUTPUT_MISSING'
  | 'SCANNER_CLEANUP_UNCONFIRMED'
  | 'SCANNER_OUTPUT_LIMIT'
  | 'SCANNER_TIMEOUT'
  | 'SCANNER_CANCELLED';

export interface RunnerInputFile {
  path: string;
  size: number;
  sha256: string;
  contentBase64: string;
}

export interface RunnerInputPayload {
  digest: string;
  files: RunnerInputFile[];
  totalBytes: number;
}

export interface RunnerJobRequestV1 {
  schemaVersion: typeof RUNNER_API_VERSION;
  runId: string;
  scope: { tenant: string; project: string };
  profileId: string;
  input: RunnerInputPayload;
}

export interface RunnerArtifact {
  name: string;
  sha256: string;
  bytes: number;
  contentBase64: string;
}

export interface RunnerIntelligenceIdentity {
  provider: string;
  id: string;
  schema: string;
  builtAt: string;
  importedAt: string;
  sha256: string;
  maxAgeHours: number;
  sources: string[];
}

export interface RunnerStepIdentity {
  stepId: string;
  imageRef: string;
  imageDigest: string;
  exitCode: number | null;
  outcome: RunnerOutcome;
}

export interface RunnerEvent {
  at: string;
  code: RunnerEventCode;
  stepId?: string;
  message: string;
}

export interface RunnerJobResponseV1 {
  schemaVersion: typeof RUNNER_API_VERSION;
  runId: string;
  scope: { tenant: string; project: string };
  profileId: string;
  /** Exact operator-provisioned profile version used for this run. */
  profileVersion?: string;
  profileDigest: string;
  rulesIdentity: string;
  inputDigest: string;
  outcome: RunnerOutcome;
  errorCode?: string;
  artifacts: RunnerArtifact[];
  steps: RunnerStepIdentity[];
  events: RunnerEvent[];
  cleanupConfirmed: boolean;
  intelligence?: RunnerIntelligenceIdentity;
}

export interface RunnerProfileAsset {
  path: string;
  sha256: string;
}

export interface RunnerProfileStep {
  id: string;
  imageRef: string;
  args: string[];
  acceptedExitCodes: number[];
  timeoutMs: number;
  outputs: string[];
  environment?: Record<string, string>;
}

export interface RunnerProfileManifestV1 {
  schemaVersion: 1;
  id: string;
  version: string;
  rulesIdentity: string;
  steps: RunnerProfileStep[];
  assets: RunnerProfileAsset[];
  intelligence?: {
    provider: string;
    id: string;
    schema: string;
    builtAt: string;
    importedAt: string;
    /** Legacy single-asset identity path. New multi-file databases should use assetPaths. */
    path?: string;
    /** Exact declared profile assets that form the governed intelligence snapshot. */
    assetPaths?: string[];
    sha256: string;
    maxAgeHours: number;
    sources: string[];
  };
}

export interface LoadedRunnerProfile {
  manifest: RunnerProfileManifestV1;
  profileDigest: string;
  directory: string;
}

export function sha256(buffer: Uint8Array | string): string {
  return createHash('sha256').update(buffer).digest('hex');
}

export function immutableImageDigest(imageRef: string): string | undefined {
  const match = imageRef.match(/@sha256:([a-f0-9]{64})$/i);
  return match?.[1]?.toLowerCase();
}

export function constantTimeTokenMatch(actual: string, expected: string): boolean {
  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function validateRunId(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) throw new Error('Invalid runner runId');
  return value;
}

export function validateProfileId(value: string): string {
  if (!/^[a-z0-9][a-z0-9._-]{0,127}$/.test(value)) throw new Error('Invalid runner profileId');
  return value;
}
