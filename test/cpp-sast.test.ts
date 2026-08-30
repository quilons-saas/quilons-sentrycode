import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SastScanner } from '../src/scanners/sast/scanner.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('native SAST detects C and C++ unsafe APIs',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-cpp-sast-')); await mkdir(join(root,'src'));
  await writeFile(join(root,'src','bad.c'),'#include <stdio.h>\nvoid f(char *x){ char b[8]; strcpy(b,x); system(x); }\n');
  await writeFile(join(root,'src','bad.cpp'),'#include <cstdio>\nvoid g(char *x){ char b[8]; sprintf(b,"%s",x); int r=rand(); }\n');
  const result=await new SastScanner().scan({repository:{root,repository:'demo',commitSha:'abc',branch:'main',isDirty:false},config:structuredClone(DEFAULT_CONFIG),now:()=>new Date('2026-08-30T00:00:00Z')});
  assert.ok(result.findings.some(f=>f.ruleId==='c-strcpy'&&f.metadata?.language==='c'));
  assert.ok(result.findings.some(f=>f.ruleId==='c-system-call'&&f.metadata?.language==='c'));
  assert.ok(result.findings.some(f=>f.ruleId==='c-sprintf'&&f.metadata?.language==='cpp'));
  assert.ok(result.findings.some(f=>f.ruleId==='c-insecure-rand'&&f.metadata?.language==='cpp'));
});
