import assert from 'node:assert/strict';
import test from 'node:test';
import { renderSarif } from '../src/reporting/sarif.js';
import type { ScanReport } from '../src/core/types.js';

test('SARIF serializes normalized findings', () => {
  const report={schemaVersion:'1.0.0',runId:'r',startedAt:'2026-08-25T00:00:00Z',completedAt:'2026-08-25T00:00:01Z',repository:{root:'.',repository:'demo',commitSha:'abc',branch:'main',isDirty:false},scanners:[{scanner:'sast',findings:[{schemaVersion:'1.0.0',id:'f',type:'sast',scanner:'sast',ruleId:'js-eval',title:'eval',description:'bad',severity:'high',location:{path:'a.ts',line:3,column:2},fingerprint:'fp',detectedAt:'2026-08-25T00:00:00Z'}],evidence:[],durationMs:1}],policy:{decision:'FAIL',findings:[],counts:{info:0,low:0,medium:0,high:1,critical:0},waivedCount:0,reasons:[],audit:[]},evidence:[]} satisfies ScanReport;
  const sarif=JSON.parse(renderSarif(report)); assert.equal(sarif.version,'2.1.0'); assert.equal(sarif.runs[0].results[0].ruleId,'sast:js-eval');
});
