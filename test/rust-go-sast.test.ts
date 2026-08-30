import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SastScanner } from '../src/scanners/sast/scanner.js';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';

test('native SAST detects Rust and Go security patterns',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-rust-go-sast-')); await mkdir(join(root,'src'));
  await writeFile(join(root,'src','bad.rs'),`use std::process::Command;\nfn f(x:&str){ let _=Command::new("sh").arg("-c").arg(x).output(); unsafe { let _:u32=std::mem::transmute(1.0f32); } }\n`);
  await writeFile(join(root,'src','bad.go'),`package demo\nimport ("crypto/md5"; "crypto/tls"; "os/exec")\nfunc f(x string){ exec.Command("sh","-c",x); _=tls.Config{InsecureSkipVerify:true}; _=md5.New() }\n`);
  const result=await new SastScanner().scan({repository:{root,repository:'demo',commitSha:'abc',branch:'main',isDirty:false},config:structuredClone(DEFAULT_CONFIG),now:()=>new Date('2026-08-30T00:00:00Z')});
  assert.ok(result.findings.some(f=>f.ruleId==='rust-shell-command'&&f.metadata?.language==='rust'));
  assert.ok(result.findings.some(f=>f.ruleId==='rust-transmute'&&f.metadata?.language==='rust'));
  assert.ok(result.findings.some(f=>f.ruleId==='go-shell-command'&&f.metadata?.language==='go'));
  assert.ok(result.findings.some(f=>f.ruleId==='go-tls-insecure-skip-verify'&&f.metadata?.language==='go'));
  assert.ok(result.findings.some(f=>f.ruleId==='go-weak-digest'&&f.metadata?.language==='go'));
});
