import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import type { LoadedRunnerProfile, RunnerProfileManifestV1 } from './contracts.js';
import { immutableImageDigest, sha256, validateProfileId } from './contracts.js';

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}
function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim() || value.includes('\0')) throw new Error(`${label} must be a non-empty string`);
  return value;
}
function safeRelative(value: unknown, label: string): string {
  const path = nonEmpty(value, label).replace(/\\/g, '/');
  if (path.startsWith('/') || path === '..' || path.startsWith('../') || path.includes('/../')) throw new Error(`${label} must be a safe relative path`);
  return path;
}
function hash(value: unknown, label: string): string {
  const text = nonEmpty(value, label).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(text)) throw new Error(`${label} must be SHA-256`);
  return text;
}

function parseManifest(raw: unknown): RunnerProfileManifestV1 {
  const value = asObject(raw, 'runner profile');
  if (value.schemaVersion !== 1) throw new Error('Runner profile schemaVersion must be 1');
  const id = validateProfileId(nonEmpty(value.id, 'runner profile id'));
  const version = nonEmpty(value.version, 'runner profile version');
  const rulesIdentity = nonEmpty(value.rulesIdentity, 'runner profile rulesIdentity');
  if (!Array.isArray(value.steps) || value.steps.length === 0) throw new Error('Runner profile steps must be a non-empty array');
  if (!Array.isArray(value.assets)) throw new Error('Runner profile assets must be an array');

  const stepIds = new Set<string>();
  const steps = value.steps.map((item, index) => {
    const step = asObject(item, `runner profile steps[${index}]`);
    const stepId = nonEmpty(step.id, `runner profile steps[${index}].id`);
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(stepId) || stepIds.has(stepId)) throw new Error(`Invalid or duplicate runner step id: ${stepId}`);
    stepIds.add(stepId);
    const imageRef = nonEmpty(step.imageRef, `runner profile steps[${index}].imageRef`);
    if (!immutableImageDigest(imageRef)) throw new Error(`Runner profile image must be immutable by digest: ${imageRef}`);
    if (!Array.isArray(step.args) || step.args.some((arg) => typeof arg !== 'string' || arg.includes('\0'))) throw new Error(`runner profile steps[${index}].args must be strings`);
    if (!Array.isArray(step.acceptedExitCodes) || step.acceptedExitCodes.length === 0 || step.acceptedExitCodes.some((code) => !Number.isInteger(code) || Number(code) < 0 || Number(code) > 255)) throw new Error(`runner profile steps[${index}].acceptedExitCodes invalid`);
    const timeoutMs = Number(step.timeoutMs);
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 3_600_000) throw new Error(`runner profile steps[${index}].timeoutMs invalid`);
    if (!Array.isArray(step.outputs) || step.outputs.some((output) => typeof output !== 'string')) throw new Error(`runner profile steps[${index}].outputs invalid`);
    let environment: Record<string, string> | undefined;
    if (step.environment !== undefined) {
      const envObject = asObject(step.environment, `runner profile steps[${index}].environment`);
      environment = {};
      for (const [key, rawValue] of Object.entries(envObject)) {
        if (!/^[A-Z_][A-Z0-9_]{0,127}$/.test(key)) throw new Error(`runner profile steps[${index}].environment has invalid key: ${key}`);
        const envValue = nonEmpty(rawValue, `runner profile steps[${index}].environment.${key}`);
        if (envValue.length > 4096 || envValue.includes('\n') || envValue.includes('\r')) throw new Error(`runner profile steps[${index}].environment.${key} is invalid`);
        environment[key] = envValue;
      }
    }
    return {
      id: stepId,
      imageRef,
      args: [...step.args] as string[],
      acceptedExitCodes: [...new Set(step.acceptedExitCodes as number[])],
      timeoutMs,
      outputs: (step.outputs as string[]).map((output, outputIndex) => safeRelative(output, `runner profile steps[${index}].outputs[${outputIndex}]`)),
      ...(environment ? { environment } : {})
    };
  });

  const seenAssets = new Set<string>();
  const assets = value.assets.map((item, index) => {
    const asset = asObject(item, `runner profile assets[${index}]`);
    const path = safeRelative(asset.path, `runner profile assets[${index}].path`);
    if (seenAssets.has(path)) throw new Error(`Duplicate runner profile asset: ${path}`);
    seenAssets.add(path);
    return { path, sha256: hash(asset.sha256, `runner profile assets[${index}].sha256`) };
  });
  let intelligence: RunnerProfileManifestV1['intelligence'];
  if (value.intelligence !== undefined) {
    const raw = asObject(value.intelligence, 'runner profile intelligence');
    const builtAt = nonEmpty(raw.builtAt, 'runner profile intelligence.builtAt');
    const importedAt = nonEmpty(raw.importedAt, 'runner profile intelligence.importedAt');
    if (Number.isNaN(Date.parse(builtAt)) || Number.isNaN(Date.parse(importedAt))) throw new Error('runner profile intelligence timestamps must be ISO dates');
    const maxAgeHours = Number(raw.maxAgeHours);
    if (!Number.isFinite(maxAgeHours) || maxAgeHours <= 0 || maxAgeHours > 24 * 365) throw new Error('runner profile intelligence.maxAgeHours invalid');
    if (!Array.isArray(raw.sources) || raw.sources.length === 0 || raw.sources.some((source) => typeof source !== 'string' || !source.trim())) throw new Error('runner profile intelligence.sources invalid');
    const digest = hash(raw.sha256, 'runner profile intelligence.sha256');

    let path: string | undefined;
    let assetPaths: string[] | undefined;
    if (raw.assetPaths !== undefined) {
      if (!Array.isArray(raw.assetPaths) || raw.assetPaths.length === 0) throw new Error('runner profile intelligence.assetPaths must be a non-empty array');
      assetPaths = [...new Set(raw.assetPaths.map((entry, index) => safeRelative(entry, `runner profile intelligence.assetPaths[${index}]`)))].sort();
      if (assetPaths.length !== raw.assetPaths.length) throw new Error('runner profile intelligence.assetPaths contains duplicates');
      const selected = assetPaths.map((assetPath) => {
        const declared = assets.find((asset) => asset.path === assetPath);
        if (!declared) throw new Error(`runner profile intelligence references undeclared asset: ${assetPath}`);
        return declared;
      });
      const canonical = selected.map((asset) => `${asset.path}\0${asset.sha256}\0`).join('');
      if (sha256(canonical) !== digest) throw new Error('runner profile intelligence asset-set digest mismatch');
    } else {
      path = safeRelative(raw.path, 'runner profile intelligence.path');
      const declared = assets.find((asset) => asset.path === path);
      if (!declared || declared.sha256 !== digest) throw new Error('runner profile intelligence must reference a matching declared asset');
    }

    intelligence = {
      provider: nonEmpty(raw.provider, 'runner profile intelligence.provider'),
      id: nonEmpty(raw.id, 'runner profile intelligence.id'),
      schema: nonEmpty(raw.schema, 'runner profile intelligence.schema'),
      builtAt,
      importedAt,
      ...(path ? { path } : {}),
      ...(assetPaths ? { assetPaths } : {}),
      sha256: digest,
      maxAgeHours,
      sources: [...raw.sources] as string[]
    };
  }
  return { schemaVersion: 1, id, version, rulesIdentity, steps, assets, ...(intelligence ? { intelligence } : {}) };
}


async function assertDeclaredProfileFiles(directory: string, declared: Set<string>, relativeRoot = ''): Promise<void> {
  const current = relativeRoot ? resolve(directory, relativeRoot) : directory;
  for (const entry of await readdir(current, { withFileTypes: true })) {
    const relativePath = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) throw new Error(`Runner profile contains symbolic link: ${relativePath}`);
    if (entry.isDirectory()) {
      await assertDeclaredProfileFiles(directory, declared, relativePath);
      continue;
    }
    if (!entry.isFile()) throw new Error(`Runner profile contains unsupported filesystem entry: ${relativePath}`);
    if (relativePath !== 'profile.json' && !declared.has(relativePath)) throw new Error(`Runner profile contains undeclared file: ${relativePath}`);
  }
}

async function assertInside(root: string, path: string): Promise<string> {
  const resolved = await realpath(path);
  const rel = relative(root, resolved);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) throw new Error(`Runner profile path escapes profile directory: ${path}`);
  return resolved;
}

export class RunnerProfileRegistry {
  constructor(private readonly root: string, private readonly now: () => Date = () => new Date()) {}

  async load(profileId: string): Promise<LoadedRunnerProfile> {
    validateProfileId(profileId);
    const directory = resolve(this.root, profileId);
    const rootReal = await realpath(resolve(this.root));
    const dirReal = await realpath(directory);
    const rel = relative(rootReal, dirReal);
    if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) throw new Error('Runner profile directory escapes registry root');
    const manifestPath = resolve(dirReal, 'profile.json');
    const manifestBytes = await readFile(manifestPath);
    const manifest = parseManifest(JSON.parse(manifestBytes.toString('utf8')) as unknown);
    if (manifest.id !== profileId) throw new Error(`Runner profile id mismatch: expected ${profileId}, got ${manifest.id}`);
    await assertDeclaredProfileFiles(dirReal, new Set(manifest.assets.map((asset) => asset.path)));
    for (const asset of manifest.assets) {
      const absolute = resolve(dirReal, asset.path);
      const st = await lstat(absolute);
      if (!st.isFile() || st.isSymbolicLink()) throw new Error(`Runner profile asset is not a regular file: ${asset.path}`);
      const safe = await assertInside(dirReal, absolute);
      const actual = sha256(await readFile(safe));
      if (actual !== asset.sha256) throw new Error(`Runner profile asset hash mismatch: ${asset.path}`);
    }
    if (manifest.intelligence) {
      const built = Date.parse(manifest.intelligence.builtAt);
      const imported = Date.parse(manifest.intelligence.importedAt);
      const now = this.now().getTime();
      if (built > now + 5 * 60_000 || imported > now + 5 * 60_000) throw new Error('Runner profile intelligence timestamp is in the future');
      if (imported < built) throw new Error('Runner profile intelligence import time predates its build time');
      const ageHours = (now - built) / 3_600_000;
      if (ageHours > manifest.intelligence.maxAgeHours) throw new Error(`Runner profile intelligence is stale: ${ageHours.toFixed(1)}h > ${manifest.intelligence.maxAgeHours}h`);
    }
    return { manifest, profileDigest: sha256(manifestBytes), directory: dirname(manifestPath) };
  }
}
