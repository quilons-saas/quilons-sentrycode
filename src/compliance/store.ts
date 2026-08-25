import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import type { ComplianceIdentity, CompliancePublication, StoredRunSummary } from './contracts.js';
import { tenantStoreRoot } from './scope.js';

function safeRunId(value: string): string {
  if (!/^[A-Za-z0-9._-]+$/.test(value)) throw new Error('Invalid run ID');
  return value;
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

async function atomicJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  await rename(tmp, path);
}

export class LocalComplianceStore {
  constructor(private readonly repositoryRoot: string, private readonly storeDirectory: string) {}

  private root(identity: ComplianceIdentity): string { return tenantStoreRoot(this.repositoryRoot, this.storeDirectory, identity); }
  private runDir(identity: ComplianceIdentity, runId: string): string { return resolve(this.root(identity), 'runs', safeRunId(runId)); }

  async publish(identity: ComplianceIdentity, publication: CompliancePublication): Promise<void> {
    if (publication.summary.tenant !== identity.tenant || publication.summary.project !== identity.project) throw new Error('Compliance publication scope mismatch');
    const dir = this.runDir(identity, publication.summary.runId);
    await mkdir(dirname(dir), { recursive: true });
    try { await mkdir(dir); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Error(`Compliance run ${publication.summary.runId} is immutable and already exists`);
      throw error;
    }
    await atomicJson(resolve(dir, 'summary.json'), publication.summary);
    await atomicJson(resolve(dir, 'evidence.json'), publication.evidence);
    await atomicJson(resolve(dir, 'report.json'), publication.report);
    await atomicJson(resolve(dir, 'events.json'), publication.events);
  }

  async getPublication(identity: ComplianceIdentity, runId: string): Promise<CompliancePublication | null> {
    const dir = this.runDir(identity, runId);
    try {
      const [summary, evidence, report, events] = await Promise.all([
        readJson<CompliancePublication['summary']>(resolve(dir, 'summary.json')),
        readJson<CompliancePublication['evidence']>(resolve(dir, 'evidence.json')),
        readJson<CompliancePublication['report']>(resolve(dir, 'report.json')),
        readJson<CompliancePublication['events']>(resolve(dir, 'events.json')),
      ]);
      return { summary, evidence, report, events };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
  }

  async listRuns(identity: ComplianceIdentity): Promise<StoredRunSummary[]> {
    const runsRoot = resolve(this.root(identity), 'runs');
    let names: string[];
    try { names = await readdir(runsRoot); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error; }
    const summaries: StoredRunSummary[] = [];
    for (const name of names.sort()) {
      try { summaries.push(await readJson<StoredRunSummary>(resolve(runsRoot, basename(name), 'summary.json'))); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    }
    return summaries.sort((a,b) => b.completedAt.localeCompare(a.completedAt));
  }
}
