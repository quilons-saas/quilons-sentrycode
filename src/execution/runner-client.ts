import type { SentryCodeConfig } from '../core/types.js';
import type { RunnerJobRequestV1, RunnerJobResponseV1 } from './contracts.js';
import { RUNNER_API_VERSION, sha256, validateRunId } from './contracts.js';
import { snapshotRepository } from './snapshot.js';

export interface RunnerClientOptions {
  endpoint: string;
  token: string;
  tenant: string;
  project: string;
  timeoutMs: number;
}

function assertHexSha256(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/i.test(value)) throw new Error(`Runner returned invalid ${label}`);
  return value.toLowerCase();
}

function assertResponse(value: unknown, request: RunnerJobRequestV1): RunnerJobResponseV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Runner returned malformed response');
  const result = value as RunnerJobResponseV1;
  if (result.schemaVersion !== RUNNER_API_VERSION || result.runId !== request.runId || result.profileId !== request.profileId || result.inputDigest !== request.input.digest) {
    throw new Error('Runner response binding mismatch');
  }
  if (result.scope?.tenant !== request.scope.tenant || result.scope?.project !== request.scope.project) throw new Error('Runner response scope mismatch');
  if (!['completed', 'failed', 'cancelled', 'timeout'].includes(result.outcome)) throw new Error('Runner returned invalid outcome');
  assertHexSha256(result.profileDigest, 'profile digest');
  if (typeof result.rulesIdentity !== 'string' || !result.rulesIdentity.trim()) throw new Error('Runner returned invalid rules identity');
  if (!Array.isArray(result.artifacts) || !Array.isArray(result.steps) || !Array.isArray(result.events) || typeof result.cleanupConfirmed !== 'boolean') throw new Error('Runner response is incomplete');
  const artifactNames = new Set<string>();
  for (const artifact of result.artifacts) {
    if (!artifact || typeof artifact.name !== 'string' || !artifact.name || artifactNames.has(artifact.name)) throw new Error('Runner returned invalid or duplicate artifact identity');
    artifactNames.add(artifact.name);
    const content = Buffer.from(artifact.contentBase64, 'base64');
    if (content.length !== artifact.bytes || sha256(content) !== assertHexSha256(artifact.sha256, `artifact digest for ${artifact.name}`)) throw new Error(`Runner artifact integrity failure: ${artifact.name}`);
  }
  if (result.outcome === 'completed' && !result.cleanupConfirmed) throw new Error('Runner completed without cleanup confirmation');
  if (result.intelligence) {
    assertHexSha256(result.intelligence.sha256, 'intelligence digest');
    if (!Number.isFinite(result.intelligence.maxAgeHours) || result.intelligence.maxAgeHours <= 0) throw new Error('Runner returned invalid intelligence freshness policy');
  }
  return result;
}

function parsedJson(body: string): unknown | undefined {
  if (!body.trim()) return undefined;
  try { return JSON.parse(body) as unknown; } catch { return undefined; }
}

export class RunnerClient {
  constructor(private readonly options: RunnerClientOptions) {
    if (!/^https?:\/\//.test(options.endpoint)) throw new Error('Runner endpoint must be HTTP(S)');
    if (!options.token) throw new Error('Runner token is required');
    if (!options.tenant || !options.project) throw new Error('Runner tenant/project scope is required');
    if (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0) throw new Error('Runner timeout must be positive');
  }

  private async cancelRun(runId: string): Promise<void> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Math.min(5_000, this.options.timeoutMs));
    try {
      const response = await fetch(new URL(`/v1/jobs/${encodeURIComponent(runId)}`, this.options.endpoint), {
        method: 'DELETE',
        headers: { authorization: `Bearer ${this.options.token}` },
        signal: controller.signal
      });
      // 404 is safe: either the request never reached the runner or the job already completed/cleaned up.
      if (!response.ok && response.status !== 404) throw new Error(`Runner cancellation failed (${response.status})`);
    } finally {
      clearTimeout(timeout);
    }
  }

  async runRepositoryProfile(args: { runId: string; profileId: string; repositoryRoot: string; config: SentryCodeConfig; signal?: AbortSignal }): Promise<RunnerJobResponseV1> {
    validateRunId(args.runId);
    const input = await snapshotRepository(args.repositoryRoot, args.config);
    const request: RunnerJobRequestV1 = { schemaVersion: RUNNER_API_VERSION, runId: args.runId, scope: { tenant: this.options.tenant, project: this.options.project }, profileId: args.profileId, input };
    const controller = new AbortController();
    let timedOut = false;
    let externallyCancelled = false;
    const timeout = setTimeout(() => { timedOut = true; controller.abort(new Error('Runner request timed out')); }, this.options.timeoutMs);
    const onAbort = () => { externallyCancelled = true; controller.abort(args.signal?.reason ?? new Error('Runner request cancelled')); };
    if (args.signal) args.signal.addEventListener('abort', onAbort, { once: true });
    try {
      const response = await fetch(new URL('/v1/jobs', this.options.endpoint), {
        method: 'POST',
        headers: { authorization: `Bearer ${this.options.token}`, 'content-type': 'application/json' },
        body: JSON.stringify(request),
        signal: controller.signal
      });
      const body = await response.text();
      const parsed = parsedJson(body);
      // Execution failures are intentionally returned as a bound RunnerJobResponse with HTTP 422.
      // Preserve that typed outcome so the scanner can distinguish findings from execution failure.
      if (response.ok || response.status === 422) {
        try { return assertResponse(parsed, request); }
        catch (error) {
          if (response.ok) throw error;
        }
      }
      throw new Error(`Runner request failed (${response.status}): ${body.slice(0, 512)}`);
    } catch (error) {
      if (controller.signal.aborted) {
        await this.cancelRun(args.runId).catch(() => undefined);
        if (timedOut) throw new Error(`Runner request timed out after ${this.options.timeoutMs}ms`);
        if (externallyCancelled) throw new Error('Runner request cancelled');
      }
      throw error;
    } finally {
      clearTimeout(timeout);
      if (args.signal) args.signal.removeEventListener('abort', onAbort);
    }
  }
}
