import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SastScanner } from '../src/scanners/sast/scanner.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('native SAST detects Java and C# security patterns',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-java-dotnet-sast-')); await mkdir(join(root,'src'));
  await writeFile(join(root,'src','Bad.java'),`class Bad { void run(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); } }\n`);
  await writeFile(join(root,'src','Bad.cs'),`using System.Diagnostics; class Bad { void Run(string cmd) { Process.Start(cmd); } }\n`);
  const result=await new SastScanner().scan({repository:{root,repository:'demo',commitSha:'abc',branch:'main',isDirty:false},config:structuredClone(DEFAULT_CONFIG),now:()=>new Date('2026-08-30T00:00:00Z')});
  assert.ok(result.findings.some(f=>f.ruleId==='java-runtime-exec'));
  assert.ok(result.findings.some(f=>f.ruleId==='csharp-process-start'));
  assert.ok(result.findings.some(f=>f.metadata?.language==='java'));
  assert.ok(result.findings.some(f=>f.metadata?.language==='csharp'));
});
