import type { ApplicationStateStore } from './store.js';
import { DisabledApplicationStateStore } from './store.js';
import { createPostgresApplicationStateStore } from './postgres.js';
export async function createApplicationStateStore(): Promise<ApplicationStateStore> {
  const url = process.env.SENTRYCODE_DATABASE_URL?.trim();
  return url ? createPostgresApplicationStateStore(url) : new DisabledApplicationStateStore();
}
