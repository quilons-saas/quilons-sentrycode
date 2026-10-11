import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

test('production runtime image includes Git and Docker CLI required by repository scans and managed runner', async () => {
  const dockerfile = await readFile(resolve(process.cwd(), 'Dockerfile'), 'utf8');
  const stageMarkers = [...dockerfile.matchAll(/^FROM node:22-alpine.*$/gm)];
  assert.ok(stageMarkers.length >= 2, 'expected separate build and runtime Node Alpine stages');

  const runtimeStageStart = stageMarkers[stageMarkers.length - 1]!.index;
  assert.notEqual(runtimeStageStart, undefined);

  const runtimeStage = dockerfile.slice(runtimeStageStart);
  assert.match(
    runtimeStage,
    /^RUN apk add --no-cache git docker-cli$/m,
    'runtime image must install Git for repository assurance and Docker CLI for the installation-owned scanner runner',
  );
});
