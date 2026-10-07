import test from 'node:test';
import assert from 'node:assert/strict';
import { dockerMountArgs } from '../src/execution/docker-executor.js';

const base = {
  installationId: 'install-1', epoch: 'epoch-1',
  inputDirectory: '/runner-work/jobs/run-1/input', outputDirectory: '/runner-work/jobs/run-1/output', profileDirectory: '/runner-profiles/syft-grype'
};

test('managed runner uses named-volume subpaths instead of host path assumptions', () => {
  const args = dockerMountArgs({ ...base, workVolumeName: 'sc-work', workVolumeRoot: '/runner-work', profileVolumeName: 'sc-profiles', profileVolumeRoot: '/runner-profiles' });
  assert.ok(args.includes('type=volume,src=sc-work,dst=/input,volume-subpath=jobs/run-1/input,readonly'));
  assert.ok(args.includes('type=volume,src=sc-work,dst=/output,volume-subpath=jobs/run-1/output'));
  assert.ok(args.includes('type=volume,src=sc-profiles,dst=/profile,volume-subpath=syft-grype,readonly'));
  assert.equal(args.some((arg) => arg.includes('type=bind,src=/runner-work')), false);
});

test('volume translation rejects paths outside the installation-owned volume', () => {
  assert.throws(() => dockerMountArgs({ ...base, inputDirectory: '/elsewhere/input', workVolumeName: 'sc-work', workVolumeRoot: '/runner-work' }), /outside configured volume root/);
});
