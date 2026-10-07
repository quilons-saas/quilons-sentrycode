import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmod, chown, lstat, mkdir, readFile, realpath, rm } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';
import type { LoadedRunnerProfile, RunnerArtifact, RunnerEvent, RunnerOutcome, RunnerStepIdentity } from './contracts.js';
import { immutableImageDigest, RUNNER_LABEL_PREFIX, sha256, validateRunId } from './contracts.js';

export interface DockerExecutorOptions {
  dockerBinary?: string;
  installationId: string;
  epoch: string;
  inputDirectory: string;
  outputDirectory: string;
  profileDirectory: string;
  workVolumeName?: string;
  profileVolumeName?: string;
  workVolumeRoot?: string;
  profileVolumeRoot?: string;
  cpuLimit?: number;
  memoryLimit?: string;
  pidsLimit?: number;
  maxLogBytes?: number;
  maxArtifactBytes?: number;
}

interface CommandResult { code: number; stdout: string; stderr: string; outputLimited: boolean }

function boundedAppend(current: Buffer[], chunk: Buffer, state: { bytes: number; limited: boolean }, maxBytes: number): void {
  if (state.limited) return;
  const remaining = maxBytes - state.bytes;
  if (remaining <= 0) { state.limited = true; return; }
  current.push(chunk.subarray(0, remaining));
  state.bytes += Math.min(chunk.length, remaining);
  if (chunk.length > remaining) state.limited = true;
}

async function runCommand(binary: string, args: string[], maxBytes: number): Promise<CommandResult> {
  return new Promise((resolveResult, reject) => {
    const child = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    const outState = { bytes: 0, limited: false };
    const errState = { bytes: 0, limited: false };
    child.stdout.on('data', (chunk: Buffer) => boundedAppend(out, chunk, outState, maxBytes));
    child.stderr.on('data', (chunk: Buffer) => boundedAppend(err, chunk, errState, maxBytes));
    child.once('error', reject);
    child.once('close', (code) => resolveResult({
      code: code ?? -1,
      stdout: Buffer.concat(out).toString('utf8'),
      stderr: Buffer.concat(err).toString('utf8'),
      outputLimited: outState.limited || errState.limited
    }));
  });
}

function safeName(value: string): string { return value.replace(/[^A-Za-z0-9_.-]/g, '-').slice(0, 48); }

export function dockerMountArgs(options: DockerExecutorOptions): string[] {
  const volumeSubpath = (absolute: string, root: string, label: string): string => {
    const normalized = absolute.replace(/\\/g, '/');
    const normalizedRoot = root.replace(/\\/g, '/').replace(/\/$/, '');
    if (!normalized.startsWith(`${normalizedRoot}/`)) throw new Error(`${label} is outside configured volume root`);
    const subpath = normalized.slice(normalizedRoot.length + 1);
    if (!subpath || subpath === '..' || subpath.startsWith('../') || subpath.includes('/../')) throw new Error(`Invalid ${label} volume subpath`);
    return subpath;
  };
  if (options.workVolumeName) {
    const workRoot = options.workVolumeRoot ?? '/runner-work';
    const inputSubpath = volumeSubpath(options.inputDirectory, workRoot, 'input');
    const outputSubpath = volumeSubpath(options.outputDirectory, workRoot, 'output');
    const args = [
      '--mount', `type=volume,src=${options.workVolumeName},dst=/input,volume-subpath=${inputSubpath},readonly`,
      '--mount', `type=volume,src=${options.workVolumeName},dst=/output,volume-subpath=${outputSubpath}`
    ];
    if (options.profileVolumeName) {
      const profileRoot = options.profileVolumeRoot ?? '/runner-profiles';
      const profileSubpath = volumeSubpath(options.profileDirectory, profileRoot, 'profile');
      args.push('--mount', `type=volume,src=${options.profileVolumeName},dst=/profile,volume-subpath=${profileSubpath},readonly`);
    } else {
      args.push('--mount', `type=bind,src=${options.profileDirectory},dst=/profile,readonly`);
    }
    return args;
  }
  return [
    '--mount', `type=bind,src=${options.inputDirectory},dst=/input,readonly`,
    '--mount', `type=bind,src=${options.outputDirectory},dst=/output`,
    '--mount', `type=bind,src=${options.profileDirectory},dst=/profile,readonly`
  ];
}

export class DockerWorkerExecutor {
  private readonly docker: string;
  private readonly maxLogBytes: number;
  private readonly maxArtifactBytes: number;

  constructor(private readonly options: DockerExecutorOptions) {
    this.docker = options.dockerBinary ?? 'docker';
    this.maxLogBytes = options.maxLogBytes ?? 2 * 1024 * 1024;
    this.maxArtifactBytes = options.maxArtifactBytes ?? 64 * 1024 * 1024;
  }

  private labels(runId: string, stepId?: string): string[] {
    const values: Record<string, string> = {
      [`${RUNNER_LABEL_PREFIX}.runner`]: 'true',
      [`${RUNNER_LABEL_PREFIX}.installation`]: this.options.installationId,
      [`${RUNNER_LABEL_PREFIX}.epoch`]: this.options.epoch,
      [`${RUNNER_LABEL_PREFIX}.run`]: runId
    };
    if (stepId) values[`${RUNNER_LABEL_PREFIX}.step`] = stepId;
    return Object.entries(values).flatMap(([key, value]) => ['--label', `${key}=${value}`]);
  }

  async cleanupRun(runId: string): Promise<boolean> {
    validateRunId(runId);
    const query = await runCommand(this.docker, ['ps', '-aq', '--filter', `label=${RUNNER_LABEL_PREFIX}.installation=${this.options.installationId}`, '--filter', `label=${RUNNER_LABEL_PREFIX}.run=${runId}`], 128 * 1024);
    if (query.code !== 0) return false;
    const ids = query.stdout.split(/\s+/).filter(Boolean);
    if (ids.length) {
      const removed = await runCommand(this.docker, ['rm', '-f', ...ids], 128 * 1024);
      if (removed.code !== 0) return false;
    }
    const verify = await runCommand(this.docker, ['ps', '-aq', '--filter', `label=${RUNNER_LABEL_PREFIX}.installation=${this.options.installationId}`, '--filter', `label=${RUNNER_LABEL_PREFIX}.run=${runId}`], 128 * 1024);
    return verify.code === 0 && !verify.stdout.trim();
  }

  async recoverStaleWorkers(): Promise<number> {
    const query = await runCommand(this.docker, ['ps', '-aq', '--filter', `label=${RUNNER_LABEL_PREFIX}.runner=true`, '--filter', `label=${RUNNER_LABEL_PREFIX}.installation=${this.options.installationId}`], 256 * 1024);
    if (query.code !== 0) throw new Error(`Unable to enumerate runner-owned workers: ${query.stderr.trim() || query.stdout.trim()}`);
    const ids = query.stdout.split(/\s+/).filter(Boolean);
    if (!ids.length) return 0;
    const removed = await runCommand(this.docker, ['rm', '-f', ...ids], 256 * 1024);
    if (removed.code !== 0) throw new Error(`Unable to remove stale runner-owned workers: ${removed.stderr.trim() || removed.stdout.trim()}`);
    return ids.length;
  }

  async execute(runId: string, profile: LoadedRunnerProfile, signal?: AbortSignal): Promise<{
    outcome: RunnerOutcome;
    errorCode?: string;
    steps: RunnerStepIdentity[];
    artifacts: RunnerArtifact[];
    events: RunnerEvent[];
    cleanupConfirmed: boolean;
  }> {
    validateRunId(runId);
    await mkdir(this.options.outputDirectory, { recursive: true, mode: 0o770 });
    await chmod(this.options.outputDirectory, 0o770).catch(() => undefined);
    if (process.platform !== 'win32') await chown(this.options.outputDirectory, 65532, 65532);
    const steps: RunnerStepIdentity[] = [];
    const events: RunnerEvent[] = [];
    const emit = (code: RunnerEvent['code'], message: string, stepId?: string) => events.push({ at: new Date().toISOString(), code, message, ...(stepId ? { stepId } : {}) });
    let outcome: RunnerOutcome = 'completed';
    let errorCode: string | undefined;

    for (const step of profile.manifest.steps) {
      if (signal?.aborted) { outcome = 'cancelled'; errorCode = 'SCANNER_CANCELLED'; emit('SCANNER_CANCELLED', 'Scanner run cancelled before launch', step.id); break; }
      const name = `sc-${safeName(runId)}-${safeName(step.id)}-${randomUUID().slice(0, 8)}`;
      const imageDigest = immutableImageDigest(step.imageRef)!;
      emit('SCANNER_STARTING', `Starting scanner step ${step.id}`, step.id);
      const createArgs = [
        'create', '--name', name,
        ...this.labels(runId, step.id),
        '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
        '--user', '65532:65532', '--cpus', String(this.options.cpuLimit ?? 0.5), '--memory', this.options.memoryLimit ?? '256m', '--pids-limit', String(this.options.pidsLimit ?? 32),
        '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
        ...dockerMountArgs(this.options),
        ...Object.entries(step.environment ?? {}).flatMap(([key, value]) => ['--env', `${key}=${value}`]),
        step.imageRef,
        ...step.args
      ];
      let create: CommandResult;
      try { create = await runCommand(this.docker, createArgs, this.maxLogBytes); }
      catch (error) {
        outcome = 'failed'; errorCode = 'SCANNER_LAUNCH_FAILED'; emit('SCANNER_LAUNCH_FAILED', `Unable to invoke container runtime: ${(error as Error).message}`, step.id);
        steps.push({ stepId: step.id, imageRef: step.imageRef, imageDigest, exitCode: null, outcome });
        break;
      }
      if (create.code !== 0 || !create.stdout.trim()) {
        outcome = 'failed'; errorCode = 'SCANNER_LAUNCH_FAILED'; emit('SCANNER_LAUNCH_FAILED', 'Container creation failed', step.id);
        steps.push({ stepId: step.id, imageRef: step.imageRef, imageDigest, exitCode: null, outcome });
        break;
      }
      const containerId = create.stdout.trim().split(/\s+/).at(-1)!;
      const start = await runCommand(this.docker, ['start', containerId], this.maxLogBytes);
      if (start.code !== 0) {
        outcome = 'failed'; errorCode = 'SCANNER_LAUNCH_FAILED'; emit('SCANNER_LAUNCH_FAILED', 'Container start failed', step.id);
        steps.push({ stepId: step.id, imageRef: step.imageRef, imageDigest, exitCode: null, outcome });
        await this.cleanupRun(runId);
        break;
      }

      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<'timeout'>((resolveTimeout) => { timer = setTimeout(() => resolveTimeout('timeout'), step.timeoutMs); });
      const cancelled = new Promise<'cancelled'>((resolveCancelled) => {
        if (!signal) return;
        if (signal.aborted) resolveCancelled('cancelled');
        else signal.addEventListener('abort', () => resolveCancelled('cancelled'), { once: true });
      });
      const wait = runCommand(this.docker, ['wait', containerId], 128 * 1024).then((result) => ({ type: 'wait' as const, result }));
      const result = await Promise.race([wait, timeout, cancelled]);
      if (timer) clearTimeout(timer);
      if (result === 'timeout') {
        outcome = 'timeout'; errorCode = 'SCANNER_TIMEOUT'; emit('SCANNER_TIMEOUT', `Scanner step exceeded ${step.timeoutMs}ms`, step.id);
        steps.push({ stepId: step.id, imageRef: step.imageRef, imageDigest, exitCode: null, outcome });
        await this.cleanupRun(runId); break;
      }
      if (result === 'cancelled') {
        outcome = 'cancelled'; errorCode = 'SCANNER_CANCELLED'; emit('SCANNER_CANCELLED', 'Scanner step cancelled', step.id);
        steps.push({ stepId: step.id, imageRef: step.imageRef, imageDigest, exitCode: null, outcome });
        await this.cleanupRun(runId); break;
      }
      const exitCode = result.result.code === 0 ? Number(result.result.stdout.trim().split(/\s+/).at(-1)) : NaN;
      const logs = await runCommand(this.docker, ['logs', containerId], this.maxLogBytes);
      if (logs.outputLimited) {
        outcome = 'failed'; errorCode = 'SCANNER_OUTPUT_LIMIT'; emit('SCANNER_OUTPUT_LIMIT', `Scanner output exceeded ${this.maxLogBytes} bytes`, step.id);
        steps.push({ stepId: step.id, imageRef: step.imageRef, imageDigest, exitCode: Number.isInteger(exitCode) ? exitCode : null, outcome });
        await this.cleanupRun(runId); break;
      }
      if (!Number.isInteger(exitCode) || !step.acceptedExitCodes.includes(exitCode)) {
        outcome = 'failed'; errorCode = 'SCANNER_EXECUTION_FAILED'; emit('SCANNER_EXECUTION_FAILED', `Scanner step exited with ${Number.isInteger(exitCode) ? exitCode : 'unknown'}`, step.id);
        steps.push({ stepId: step.id, imageRef: step.imageRef, imageDigest, exitCode: Number.isInteger(exitCode) ? exitCode : null, outcome });
        await this.cleanupRun(runId); break;
      }
      emit('SCANNER_COMPLETED', `Scanner step completed with exit ${exitCode}`, step.id);
      steps.push({ stepId: step.id, imageRef: step.imageRef, imageDigest, exitCode, outcome: 'completed' });
      await runCommand(this.docker, ['rm', '-f', containerId], 128 * 1024);
    }

    const artifacts: RunnerArtifact[] = [];
    if (outcome === 'completed') {
      const requested = [...new Set(profile.manifest.steps.flatMap((step) => step.outputs))];
      let total = 0;
      const outputRoot = await realpath(this.options.outputDirectory);
      for (const name of requested) {
        const absolute = resolve(this.options.outputDirectory, name);
        const st = await lstat(absolute).catch(() => undefined);
        if (!st?.isFile() || st.isSymbolicLink()) {
          outcome = 'failed'; errorCode = 'SCANNER_OUTPUT_MISSING'; emit('SCANNER_OUTPUT_MISSING', `Scanner artifact is missing or not a regular file: ${name}`); break;
        }
        const resolved = await realpath(absolute);
        const rel = relative(outputRoot, resolved);
        if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) {
          outcome = 'failed'; errorCode = 'SCANNER_OUTPUT_MISSING'; emit('SCANNER_OUTPUT_MISSING', `Scanner artifact escapes the isolated output root: ${name}`); break;
        }
        total += st.size;
        if (total > this.maxArtifactBytes) { outcome = 'failed'; errorCode = 'SCANNER_OUTPUT_LIMIT'; emit('SCANNER_OUTPUT_LIMIT', `Scanner artifacts exceeded ${this.maxArtifactBytes} bytes`); break; }
        const content = await readFile(resolved);
        artifacts.push({ name, sha256: sha256(content), bytes: content.length, contentBase64: content.toString('base64') });
      }
    }

    const cleanupConfirmed = await this.cleanupRun(runId);
    if (!cleanupConfirmed && outcome === 'completed') {
      outcome = 'failed'; errorCode = 'SCANNER_CLEANUP_UNCONFIRMED';
      emit('SCANNER_CLEANUP_UNCONFIRMED', 'Runner-owned worker cleanup could not be confirmed');
    }
    if (outcome !== 'completed') await rm(this.options.outputDirectory, { recursive: true, force: true }).catch(() => undefined);
    return { outcome, ...(errorCode ? { errorCode } : {}), steps, artifacts, events, cleanupConfirmed };
  }
}
