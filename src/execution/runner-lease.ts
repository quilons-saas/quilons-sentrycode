import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

interface LeaseRecord { owner: string; heartbeatAt: number }

export class RunnerLease {
  private readonly owner = randomUUID();
  private readonly directory: string;
  private readonly recordPath: string;
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(root: string, private readonly staleAfterMs = 15_000, private readonly heartbeatEveryMs = 5_000) {
    if (staleAfterMs < 3_000 || heartbeatEveryMs < 500 || heartbeatEveryMs >= staleAfterMs) throw new Error('Invalid runner lease timing');
    this.directory = resolve(root, '.runner-lease');
    this.recordPath = resolve(this.directory, 'owner.json');
  }

  private async writeHeartbeat(): Promise<void> {
    const temp = resolve(this.directory, `owner.${this.owner}.tmp`);
    const record: LeaseRecord = { owner: this.owner, heartbeatAt: Date.now() };
    await writeFile(temp, JSON.stringify(record), { encoding: 'utf8', mode: 0o600 });
    await rename(temp, this.recordPath);
  }

  private async current(): Promise<LeaseRecord | undefined> {
    try {
      const value = JSON.parse(await readFile(this.recordPath, 'utf8')) as unknown;
      if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
      const record = value as Partial<LeaseRecord>;
      return typeof record.owner === 'string' && typeof record.heartbeatAt === 'number' ? { owner: record.owner, heartbeatAt: record.heartbeatAt } : undefined;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw error;
    }
  }

  async acquire(): Promise<void> {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        await mkdir(this.directory, { mode: 0o700 });
        await this.writeHeartbeat();
        this.timer = setInterval(() => { void this.writeHeartbeat().catch(() => undefined); }, this.heartbeatEveryMs);
        this.timer.unref?.();
        return;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
      const record = await this.current();
      if (record && Date.now() - record.heartbeatAt < this.staleAfterMs) throw new Error('Another SentryCode runner owns this installation');
      const tombstone = `${this.directory}.stale.${randomUUID()}`;
      try { await rename(this.directory, tombstone); await rm(tombstone, { recursive: true, force: true }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    }
    throw new Error('Unable to acquire SentryCode runner lease');
  }

  async release(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    const record = await this.current();
    if (record?.owner === this.owner) await rm(this.directory, { recursive: true, force: true });
  }
}
