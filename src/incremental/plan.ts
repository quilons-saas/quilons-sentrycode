import type { CiContext, IncrementalPlan, SentryCodeConfig } from '../core/types.js';
import { changedFilesBetween, resolveAvailableRef } from '../git/changes.js';
import { affectedServices, discoverServices } from '../monorepo/discover.js';
import { readIncrementalCache } from './cache.js';

export async function buildIncrementalPlan(args: {
  root: string;
  repository: string;
  commitSha: string | null;
  config: SentryCodeConfig;
  ci: CiContext;
  forceFull?: boolean;
  baseRef?: string;
  headRef?: string;
}): Promise<IncrementalPlan> {
  const services = await discoverServices(args.root, args.config);
  if (args.forceFull || !args.config.incremental.enabled) return { mode:'full', changedFiles:[], affectedServices:services, cacheHit:false };

  const cache = await readIncrementalCache(args.root, args.config.incremental.cacheFile);
  const candidate = args.baseRef || args.ci.baseRef || args.config.incremental.baseRef || cache?.lastSuccessfulCommit;
  const head = args.headRef || args.ci.headRef || args.config.incremental.headRef || 'HEAD';
  if (!candidate) return { mode:'full', changedFiles:[], affectedServices:services, cacheHit:Boolean(cache) };
  const availableBase = await resolveAvailableRef(args.root, candidate);
  if (!availableBase) return { mode:'full', changedFiles:[], affectedServices:services, cacheHit:Boolean(cache) };
  const changedFiles = await changedFilesBetween(args.root, availableBase, head);
  return {
    mode:'incremental',
    baseRef:availableBase,
    headRef:head,
    changedFiles,
    affectedServices:affectedServices(changedFiles, services),
    cacheHit: Boolean(cache && cache.lastSuccessfulCommit === candidate)
  };
}
