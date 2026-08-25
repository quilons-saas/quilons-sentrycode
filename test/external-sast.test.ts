import test from 'node:test';
import assert from 'node:assert/strict';
import { findingsFromSarif } from '../src/scanners/external-sast/scanner.js';

test('external SARIF SAST findings normalize into SentryCode authority',()=>{
  const parsed=findingsFromSarif({version:'2.1.0',runs:[{tool:{driver:{name:'Semgrep',version:'1'}},results:[{ruleId:'js.sql',level:'error',message:{text:'SQL injection'},locations:[{physicalLocation:{artifactLocation:{uri:'src/a.ts'},region:{startLine:4,startColumn:2}}}]}]}]},'2026-08-25T00:00:00.000Z');
  assert.equal(parsed.findings.length,1); assert.equal(parsed.findings[0]?.scanner,'external-sast'); assert.equal(parsed.findings[0]?.severity,'high'); assert.equal(parsed.findings[0]?.location?.path,'src/a.ts'); assert.deepEqual(parsed.toolNames,['Semgrep']);
});
