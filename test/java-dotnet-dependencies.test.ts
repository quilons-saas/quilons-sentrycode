import assert from 'node:assert/strict';
import test from 'node:test';
import { parseDependencyFiles } from '../src/dependencies/discover.js';

const now='2026-08-30T00:00:00.000Z';

test('discovers Maven and Gradle dependencies with Maven purls',()=>{
  const snapshot=parseDependencyFiles({
    'pom.xml': `<project><properties><jackson.version>2.17.2</jackson.version></properties><dependencies>
      <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${'${jackson.version}'}</version></dependency>
      <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>5.10.3</version><scope>test</scope></dependency>
    </dependencies></project>`,
    'gradle.lockfile': 'org.slf4j:slf4j-api:2.0.13=runtimeClasspath\n'
  },now);
  assert.equal(snapshot.components.length,2);
  const jackson=snapshot.components.find(x=>x.name==='com.fasterxml.jackson.core:jackson-databind');
  assert.equal(jackson?.ecosystem,'maven');
  assert.equal(jackson?.version,'2.17.2');
  assert.equal(jackson?.purl,'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.2');
  assert.equal(snapshot.components.find(x=>x.name==='org.slf4j:slf4j-api')?.direct,false);
});

test('discovers NuGet csproj, lock, and assets dependencies',()=>{
  const snapshot=parseDependencyFiles({
    'App.csproj': `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
    'packages.lock.json': JSON.stringify({version:1,dependencies:{'net8.0':{'Serilog':{type:'Direct',resolved:'3.1.1'},'System.Memory':{type:'Transitive',resolved:'4.5.5'}}}}),
    'obj/project.assets.json': JSON.stringify({libraries:{'Polly/8.4.1':{type:'package',path:'polly/8.4.1'}},project:{frameworks:{'net8.0':{dependencies:{Polly:{target:'Package'}}}}}})
  },now);
  assert.equal(snapshot.components.find(x=>x.name==='Newtonsoft.Json')?.purl,'pkg:nuget/Newtonsoft.Json@13.0.3');
  assert.equal(snapshot.components.find(x=>x.name==='Serilog')?.direct,true);
  assert.equal(snapshot.components.find(x=>x.name==='System.Memory')?.direct,false);
  assert.equal(snapshot.components.find(x=>x.name==='Polly')?.version,'8.4.1');
});
