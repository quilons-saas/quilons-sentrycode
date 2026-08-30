import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('Rust and Go native SAST are enabled by default',()=>{
  assert.ok(DEFAULT_CONFIG.sast.languages.includes('rust'));
  assert.ok(DEFAULT_CONFIG.sast.languages.includes('go'));
});
