import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { chmod, mkdir, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { RunnerInputPayload, RunnerJobRequestV1, RunnerJobResponseV1 } from './contracts.js';
import { constantTimeTokenMatch, RUNNER_API_VERSION, sha256, validateProfileId, validateRunId } from './contracts.js';
import { canonicalInputDigest } from './snapshot.js';
import { RunnerProfileRegistry } from './profile-registry.js';
import { DockerWorkerExecutor } from './docker-executor.js';
import { RunnerLease } from './runner-lease.js';

export interface RunnerServerOptions {
  host: string;
  port: number;
  token: string;
  tenant: string;
  project: string;
  installationId: string;
  workRoot: string;
  profilesRoot: string;
  workVolumeName?: string;
  profileVolumeName?: string;
  maxRequestBytes?: number;
  maxFiles?: number;
  maxInputBytes?: number;
  maxFileBytes?: number;
  maxConcurrency?: number;
  dockerBinary?: string;
}

function json(res: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body), 'cache-control': 'no-store' });
  res.end(body);
}
function authToken(req: IncomingMessage): string { const raw = req.headers.authorization ?? ''; return raw.startsWith('Bearer ') ? raw.slice(7) : ''; }

export function boundedRunnerDiagnostic(error: unknown, maxLength = 512): string {
  const raw = error instanceof Error ? error.message : String(error);
  const singleLine = raw.replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim();
  const safe = singleLine || 'unknown runner launch failure';
  return safe.length <= maxLength ? safe : `${safe.slice(0, Math.max(0, maxLength - 3))}...`;
}
async function readBody(req: IncomingMessage, limit: number): Promise<unknown> {
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const raw of req) { const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw); bytes += chunk.length; if (bytes > limit) throw new Error('REQUEST_TOO_LARGE'); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown; } catch { throw new Error('INVALID_JSON'); }
}
function safeRelative(path: string): string {
  const value = path.replace(/\\/g, '/');
  if (!value || value.startsWith('/') || value === '..' || value.startsWith('../') || value.includes('/../') || value.includes('\0')) throw new Error('UNSAFE_INPUT_PATH');
  return value;
}
function parseRequest(value: unknown, options: RunnerServerOptions): RunnerJobRequestV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('INVALID_REQUEST');
  const request = value as RunnerJobRequestV1;
  if (request.schemaVersion !== RUNNER_API_VERSION) throw new Error('UNSUPPORTED_SCHEMA');
  validateRunId(request.runId); validateProfileId(request.profileId);
  if (request.scope?.tenant !== options.tenant || request.scope?.project !== options.project) throw new Error('SCOPE_MISMATCH');
  if (!request.input || typeof request.input !== 'object' || !Array.isArray(request.input.files)) throw new Error('INVALID_INPUT');
  return request;
}

async function materializeInput(root: string, input: RunnerInputPayload, options: RunnerServerOptions): Promise<void> {
  const maxFiles = options.maxFiles ?? 10_000, maxBytes = options.maxInputBytes ?? 256 * 1024 * 1024, maxFile = options.maxFileBytes ?? 16 * 1024 * 1024;
  if (input.files.length > maxFiles || input.totalBytes > maxBytes) throw new Error('INPUT_LIMIT_EXCEEDED');
  let total = 0;
  const descriptors: Array<{ path: string; size: number; sha256: string }> = [];
  for (const file of input.files) {
    const path = safeRelative(file.path);
    const content = Buffer.from(file.contentBase64, 'base64');
    if (content.length !== file.size || content.length > maxFile || sha256(content) !== file.sha256) throw new Error('INPUT_INTEGRITY_FAILURE');
    total += content.length; if (total > maxBytes) throw new Error('INPUT_LIMIT_EXCEEDED');
    const absolute = resolve(root, path);
    const parent = absolute.slice(0, Math.max(absolute.lastIndexOf('/'), absolute.lastIndexOf('\\')));
    if (parent) await mkdir(parent, { recursive: true, mode: 0o755 });
    await writeFile(absolute, content, { mode: 0o444, flag: 'wx' });
    descriptors.push({ path, size: content.length, sha256: file.sha256 });
  }
  if (total !== input.totalBytes || canonicalInputDigest(descriptors) !== input.digest) throw new Error('INPUT_DIGEST_MISMATCH');
  await chmod(root, 0o555).catch(() => undefined);
}

export class RunnerServer {
  private readonly epoch = randomUUID();
  private readonly registry: RunnerProfileRegistry;
  private active = 0;
  private readonly jobs = new Map<string, AbortController>();
  private server: ReturnType<typeof createServer> | undefined;
  private readonly lease: RunnerLease;

  constructor(private readonly options: RunnerServerOptions) {
    if (!options.token) throw new Error('Runner token is required');
    if (!options.tenant || !options.project) throw new Error('Runner fixed tenant/project scope is required');
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(options.installationId)) throw new Error('Invalid runner installationId');
    this.registry = new RunnerProfileRegistry(options.profilesRoot);
    this.lease = new RunnerLease(options.workRoot);
  }

  private executor(jobRoot: string, profileDirectory: string): DockerWorkerExecutor {
    return new DockerWorkerExecutor({
      installationId: this.options.installationId,
      epoch: this.epoch,
      inputDirectory: resolve(jobRoot, 'input'),
      outputDirectory: resolve(jobRoot, 'output'),
      profileDirectory,
      ...(this.options.dockerBinary ? { dockerBinary: this.options.dockerBinary } : {}),
      ...(this.options.workVolumeName ? { workVolumeName: this.options.workVolumeName, workVolumeRoot: this.options.workRoot } : {}),
      ...(this.options.profileVolumeName ? { profileVolumeName: this.options.profileVolumeName, profileVolumeRoot: this.options.profilesRoot } : {})
    });
  }

  async recover(): Promise<number> {
    await mkdir(this.options.workRoot, { recursive: true, mode: 0o700 });
    const executor = new DockerWorkerExecutor({ installationId: this.options.installationId, epoch: this.epoch, inputDirectory: this.options.workRoot, outputDirectory: this.options.workRoot, profileDirectory: this.options.profilesRoot, ...(this.options.dockerBinary ? { dockerBinary: this.options.dockerBinary } : {}) });
    const recovered = await executor.recoverStaleWorkers();
    await rm(resolve(this.options.workRoot, 'jobs'), { recursive: true, force: true });
    await mkdir(resolve(this.options.workRoot, 'jobs'), { recursive: true, mode: 0o700 });
    return recovered;
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!constantTimeTokenMatch(authToken(req), this.options.token)) { json(res, 401, { error: 'UNAUTHORIZED' }); return; }
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'runner'}`);
    if (req.method === 'GET' && url.pathname === '/readyz') { json(res, 200, { ready: true, schemaVersion: RUNNER_API_VERSION, installationId: this.options.installationId }); return; }
    if (req.method === 'DELETE' && url.pathname.startsWith('/v1/jobs/')) {
      const runId = decodeURIComponent(url.pathname.slice('/v1/jobs/'.length));
      try { validateRunId(runId); } catch { json(res, 400, { error: 'INVALID_RUN_ID' }); return; }
      const job = this.jobs.get(runId); if (!job) { json(res, 404, { error: 'RUN_NOT_FOUND' }); return; }
      job.abort(new Error('cancelled')); json(res, 202, { runId, cancelled: true }); return;
    }
    if (req.method !== 'POST' || url.pathname !== '/v1/jobs') { json(res, 404, { error: 'NOT_FOUND' }); return; }
    if (this.active >= (this.options.maxConcurrency ?? 2)) { json(res, 429, { error: 'RUNNER_BUSY' }); return; }

    let request: RunnerJobRequestV1;
    try { request = parseRequest(await readBody(req, this.options.maxRequestBytes ?? 384 * 1024 * 1024), this.options); }
    catch (error) { json(res, error instanceof Error && error.message === 'REQUEST_TOO_LARGE' ? 413 : 400, { error: (error as Error).message }); return; }
    if (this.jobs.has(request.runId)) { json(res, 409, { error: 'DUPLICATE_RUN_ID' }); return; }

    let profile;
    try { profile = await this.registry.load(request.profileId); }
    catch (error) { json(res, 422, { error: 'PROFILE_UNAVAILABLE', message: (error as Error).message }); return; }

    const jobRoot = resolve(this.options.workRoot, 'jobs', request.runId);
    const inputRoot = resolve(jobRoot, 'input');
    await rm(jobRoot, { recursive: true, force: true });
    await mkdir(inputRoot, { recursive: true, mode: 0o700 });
    try { await materializeInput(inputRoot, request.input, this.options); }
    catch (error) { await rm(jobRoot, { recursive: true, force: true }); json(res, 422, { error: (error as Error).message }); return; }

    const controller = new AbortController(); this.jobs.set(request.runId, controller); this.active += 1;
    const executor = this.executor(jobRoot, profile.directory);
    try {
      let result;
      try {
        result = await executor.execute(request.runId, profile, controller.signal);
      } catch (error) {
        const cleanupConfirmed = await executor.cleanupRun(request.runId).catch(() => false);
        const diagnostic = boundedRunnerDiagnostic(error);
        result = {
          outcome: 'failed' as const,
          errorCode: 'SCANNER_LAUNCH_FAILED',
          artifacts: [],
          steps: [],
          events: [{
            at: new Date().toISOString(),
            code: 'SCANNER_LAUNCH_FAILED' as const,
            message: `Scanner execution could not be established: ${diagnostic}`
          }],
          cleanupConfirmed
        };
      }
      const response: RunnerJobResponseV1 = {
        schemaVersion: RUNNER_API_VERSION, runId: request.runId, scope: request.scope, profileId: request.profileId,
        profileVersion: profile.manifest.version, profileDigest: profile.profileDigest, rulesIdentity: profile.manifest.rulesIdentity, inputDigest: request.input.digest,
        outcome: result.outcome, artifacts: result.artifacts, steps: result.steps, events: result.events, cleanupConfirmed: result.cleanupConfirmed,
        ...(profile.manifest.intelligence ? { intelligence: {
          provider: profile.manifest.intelligence.provider, id: profile.manifest.intelligence.id, schema: profile.manifest.intelligence.schema,
          builtAt: profile.manifest.intelligence.builtAt, importedAt: profile.manifest.intelligence.importedAt, sha256: profile.manifest.intelligence.sha256,
          maxAgeHours: profile.manifest.intelligence.maxAgeHours, sources: [...profile.manifest.intelligence.sources]
        } } : {}),
        ...(result.errorCode ? { errorCode: result.errorCode } : {})
      };
      json(res, result.outcome === 'completed' ? 200 : 422, response);
    } finally {
      this.jobs.delete(request.runId); this.active -= 1;
      await rm(jobRoot, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  async listen(): Promise<{ host: string; port: number }> {
    if (this.server) throw new Error('Runner server already started');
    await this.lease.acquire();
    try { await this.recover(); } catch (error) { await this.lease.release(); throw error; }
    this.server = createServer((req, res) => { void this.handle(req, res).catch((error) => { if (!res.headersSent) json(res, 500, { error: 'RUNNER_INTERNAL_ERROR' }); else res.destroy(error as Error); }); });
    return new Promise((resolveListen, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(this.options.port, this.options.host, () => {
        const address = this.server!.address(); if (!address || typeof address === 'string') reject(new Error('Runner did not bind TCP')); else resolveListen({ host: this.options.host, port: address.port });
      });
    });
  }

  async close(): Promise<void> {
    for (const controller of this.jobs.values()) controller.abort(new Error('runner shutting down'));
    if (!this.server) return;
    await new Promise<void>((resolveClose, reject) => this.server!.close((error) => error ? reject(error) : resolveClose()));
    this.server = undefined;
    await this.lease.release();
  }
}
