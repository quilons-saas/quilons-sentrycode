import assert from 'node:assert/strict';
import test from 'node:test';
import { parseDependencyFiles } from '../src/dependencies/discover.js';

const now='2026-08-30T00:00:00.000Z';

test('discovers Cargo lock dependencies and marks direct/dev crates',()=>{
  const snapshot=parseDependencyFiles({
    'Cargo.toml': `[package]\nname="demo"\nversion="1.0.0"\n[dependencies]\nserde = "1"\n[dev-dependencies]\nproptest = "1"\n`,
    'Cargo.lock': `[[package]]\nname = "serde"\nversion = "1.0.219"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "proptest"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "itoa"\nversion = "1.0.15"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`
  },now);
  const serde=snapshot.components.find(x=>x.ecosystem==='cargo'&&x.name==='serde');
  assert.equal(serde?.version,'1.0.219');
  assert.equal(serde?.direct,true);
  assert.equal(serde?.dev,false);
  assert.equal(serde?.purl,'pkg:cargo/serde@1.0.219');
  assert.equal(snapshot.components.find(x=>x.name==='proptest')?.dev,true);
  assert.equal(snapshot.components.find(x=>x.name==='itoa')?.direct,false);
});

test('discovers Go modules and preserves direct versus indirect',()=>{
  const snapshot=parseDependencyFiles({
    'go.mod': `module example.com/demo\n\ngo 1.24\n\nrequire (\n github.com/google/uuid v1.6.0\n golang.org/x/crypto v0.36.0 // indirect\n)\nrequire github.com/stretchr/testify v1.10.0\n`
  },now);
  const uuid=snapshot.components.find(x=>x.ecosystem==='go'&&x.name==='github.com/google/uuid');
  assert.equal(uuid?.version,'v1.6.0');
  assert.equal(uuid?.direct,true);
  assert.equal(uuid?.purl,'pkg:golang/github.com/google/uuid@v1.6.0');
  assert.equal(snapshot.components.find(x=>x.name==='golang.org/x/crypto')?.direct,false);
  assert.equal(snapshot.components.find(x=>x.name==='github.com/stretchr/testify')?.direct,true);
});
