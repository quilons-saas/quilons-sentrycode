import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import type { Decision, SentryCodeConfig } from '../core/types.js';

export interface OpaInput {
  repository: unknown;
  scanners: unknown;
  effectivePolicy: unknown;
  builtinDecision: Decision;
}

interface ProcessResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

async function runOpa(binary: string, args: string[], cwd: string, input: string): Promise<ProcessResult> {
  return await new Promise<ProcessResult>((resolvePromise, reject) => {
    const child = spawn(binary, args, {
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    const maxBuffer = 4 * 1024 * 1024;
    let settled = false;

    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(error);
    };

    child.stdout.on('data', (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      stdoutBytes += buffer.length;
      if (stdoutBytes > maxBuffer) {
        fail(new Error(`OPA stdout exceeded ${maxBuffer} bytes`));
        return;
      }
      stdoutChunks.push(buffer);
    });

    child.stderr.on('data', (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      stderrBytes += buffer.length;
      if (stderrBytes > maxBuffer) {
        fail(new Error(`OPA stderr exceeded ${maxBuffer} bytes`));
        return;
      }
      stderrChunks.push(buffer);
    });

    child.once('error', (error) => fail(error));

    child.once('close', (code) => {
      if (settled) return;
      settled = true;
      resolvePromise({
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        exitCode: code ?? -1
      });
    });

    child.stdin.once('error', (error) => fail(error));
    child.stdin.end(input, 'utf8');
  });
}

export async function evaluateOpa(root: string, config: SentryCodeConfig, input: OpaInput): Promise<Decision | undefined> {
  if (!config.policy.opa.enabled) return undefined;
  if (!config.policy.opa.policyFiles.length) throw new Error('OPA is enabled but policy.opa.policyFiles is empty');

  const args = ['eval', '--format', 'json', '--stdin-input'];
  for (const file of config.policy.opa.policyFiles) args.push('--data', resolve(root, file));
  args.push(config.policy.opa.query);

  let result: ProcessResult;
  try {
    result = await runOpa(config.policy.opa.binary, args, root, JSON.stringify(input));
  } catch (error) {
    throw new Error(`OPA evaluation failed: ${(error as Error).message}`);
  }

  if (result.exitCode !== 0) {
    const detail = result.stderr.trim() || `exit code ${result.exitCode}`;
    throw new Error(`OPA evaluation failed: ${detail}`);
  }

  let parsed: unknown;
  try { parsed = JSON.parse(result.stdout) as unknown; }
  catch { throw new Error('OPA returned invalid JSON'); }

  const value = (((parsed as { result?: Array<{ expressions?: Array<{ value?: unknown }> }> }).result?.[0]?.expressions?.[0]?.value));
  if (value === undefined) throw new Error(`OPA query returned no value: ${config.policy.opa.query}`);
  if (typeof value === 'string' && ['PASS', 'WARN', 'FAIL'].includes(value)) return value as Decision;
  if (typeof value === 'boolean') return value ? 'PASS' : 'FAIL';
  if (value && typeof value === 'object' && typeof (value as { decision?: unknown }).decision === 'string') {
    const decision = (value as { decision: string }).decision;
    if (['PASS', 'WARN', 'FAIL'].includes(decision)) return decision as Decision;
  }
  throw new Error('OPA decision must be PASS/WARN/FAIL, boolean, or an object containing decision');
}
