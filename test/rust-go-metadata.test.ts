import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { enrichDependencyMetadata } from '../src/dependencies/metadata.js';
import type { DependencyComponent } from '../src/core/types.js';

test('local Cargo and Go caches enrich license metadata without network access',async()=>{
  const root=await mkdtemp(join(tmpdir(),'sentrycode-rust-go-meta-'));
  const cargoHome=join(root,'cargo'); const cargoCrate=join(cargoHome,'registry','src','index.local','serde-1.0.219');
  await mkdir(cargoCrate,{recursive:true}); await writeFile(join(cargoCrate,'Cargo.toml'),'[package]\nname="serde"\nversion="1.0.219"\nlicense="MIT OR Apache-2.0"\n');
  const goCache=join(root,'gomod'); const goModule=join(goCache,'github.com','google','uuid@v1.6.0');
  await mkdir(goModule,{recursive:true}); await writeFile(join(goModule,'LICENSE'),'Copyright\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n');
  const oldCargo=process.env.CARGO_HOME,oldGo=process.env.GOMODCACHE; process.env.CARGO_HOME=cargoHome;process.env.GOMODCACHE=goCache;
  const components:DependencyComponent[]=[
    {ecosystem:'cargo',name:'serde',version:'1.0.219',direct:true,dev:false,source:'Cargo.lock',purl:'pkg:cargo/serde@1.0.219'},
    {ecosystem:'go',name:'github.com/google/uuid',version:'v1.6.0',direct:true,dev:false,source:'go.mod',purl:'pkg:golang/github.com/google/uuid@v1.6.0'}
  ];
  try{
    const enriched=await enrichDependencyMetadata(root,components,{offline:true});
    assert.equal(enriched[0]?.license,'MIT OR Apache-2.0');
    assert.equal(enriched[1]?.license,'MIT');
  } finally {
    if(oldCargo===undefined)delete process.env.CARGO_HOME;else process.env.CARGO_HOME=oldCargo;
    if(oldGo===undefined)delete process.env.GOMODCACHE;else process.env.GOMODCACHE=oldGo;
  }
});
