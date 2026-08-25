import test from 'node:test';
import assert from 'node:assert/strict';
import { reportEvents } from '../src/compliance/events.js';
import type { ScanReport } from '../src/core/types.js';

 test('compliance events are governed envelopes without database details', () => {
  const report = { schemaVersion:'1.0.0', runId:'run-x', startedAt:'x', completedAt:'y', repository:{root:'/x',repository:'r',commitSha:null,branch:null,isDirty:false}, scanners:[], policy:{decision:'PASS',findings:[],counts:{info:0,low:0,medium:0,high:0,critical:0},waivedCount:0,reasons:[],audit:[]}, evidence:[] } as ScanReport;
  const events = reportEvents({ tenant:'t', project:'p' }, report);
  assert.deepEqual(events.map((item) => item.type), ['sentrycode.scan.completed','sentrycode.evidence.available']);
  assert.ok(events.every((item) => item.tenant === 't' && item.project === 'p'));
  assert.equal(JSON.stringify(events).includes('database'), false);
});
