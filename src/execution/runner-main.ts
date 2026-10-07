import { RunnerServer } from './runner-server.js';

function required(name: string): string { const value = process.env[name]; if (!value) throw new Error(`${name} is required`); return value; }
function integer(name: string, fallback: number): number { const raw = process.env[name]; if (!raw) return fallback; const value = Number(raw); if (!Number.isInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer`); return value; }

async function main(): Promise<void> {
  const server = new RunnerServer({
    host: process.env.SENTRYCODE_RUNNER_HOST ?? '0.0.0.0',
    port: integer('SENTRYCODE_RUNNER_PORT', 7791),
    token: required('SENTRYCODE_RUNNER_TOKEN'),
    tenant: required('SENTRYCODE_RUNNER_TENANT'),
    project: required('SENTRYCODE_RUNNER_PROJECT'),
    installationId: required('SENTRYCODE_RUNNER_INSTALLATION_ID'),
    workRoot: process.env.SENTRYCODE_RUNNER_WORK_ROOT ?? '/var/lib/sentrycode-runner',
    profilesRoot: process.env.SENTRYCODE_RUNNER_PROFILES_ROOT ?? '/opt/sentrycode-runner/profiles',
    ...(process.env.SENTRYCODE_RUNNER_WORK_VOLUME ? { workVolumeName: process.env.SENTRYCODE_RUNNER_WORK_VOLUME } : {}),
    ...(process.env.SENTRYCODE_RUNNER_PROFILE_VOLUME ? { profileVolumeName: process.env.SENTRYCODE_RUNNER_PROFILE_VOLUME } : {}),
    maxConcurrency: integer('SENTRYCODE_RUNNER_MAX_CONCURRENCY', 2),
    dockerBinary: process.env.SENTRYCODE_RUNNER_DOCKER_BINARY ?? 'docker'
  });
  const address = await server.listen();
  process.stdout.write(`${JSON.stringify({ event: 'runner.ready', ...address })}\n`);
  const shutdown = async () => { await server.close(); process.exitCode = 0; };
  process.once('SIGTERM', () => void shutdown());
  process.once('SIGINT', () => void shutdown());
}

main().catch((error) => { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
