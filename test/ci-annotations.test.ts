import test from 'node:test';
import assert from 'node:assert/strict';
import { renderCiAnnotations } from '../src/ci/annotations.js';
import type { ScanReport } from '../src/core/types.js';

test('renders GitHub annotation from normalized finding', () => {
  const report={ policy:{findings:[{waived:false,finding:{severity:'high',ruleId:'x',title:'Bad',location:{path:'src/a.ts',line:3}}}]}} as unknown as ScanReport;
  const text=renderCiAnnotations(report,{provider:'github',detected:true,pullRequest:true});
  assert.match(text,/::error file=src\/a\.ts,line=3::x: Bad/);
});
