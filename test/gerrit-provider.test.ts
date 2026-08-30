import test from 'node:test';
import assert from 'node:assert/strict';
import { GerritProvider, gerritAuthFromEnv, gerritReviewMessage } from '../src/git/gerrit-provider.js';
import type { Finding } from '../src/core/types.js';

const finding:Finding={schemaVersion:'1.0.0',id:'f1',type:'sast',scanner:'sast',ruleId:'unsafe.eval',title:'Unsafe eval',description:'Avoid eval',severity:'high',location:{path:'src/a.ts',line:9},fingerprint:'fp',detectedAt:'2026-08-30T00:00:00.000Z'};

test('Gerrit provider reads labels and publishes inline review with vote',async()=>{
  const previous=globalThis.fetch; const requests:Array<{url:string;init:RequestInit}>=[];
  globalThis.fetch=async(input,init={})=>{
    requests.push({url:String(input),init});
    if((init.method??'GET')==='GET') return new Response(")]}'\n"+JSON.stringify({_number:123,project:'acme/widget',branch:'main',subject:'Change',current_revision:'abc',labels:{'Code-Review':{all:[{value:2}]},Verified:{value:1}}}),{status:200});
    return new Response(")]}'\n{}",{status:200});
  };
  try{
    const provider=new GerritProvider({apiBaseUrl:'https://gerrit.example',auth:{mode:'bearer',token:'secret'}});
    const state=await provider.inspect('123','abc');
    assert.equal(state.labels['Code-Review'],2); assert.equal(state.labels.Verified,1);
    const result=await provider.publishReview({changeNumber:'123',revision:'abc',message:'SentryCode PASS',findings:[finding],label:'Verified',vote:1});
    assert.equal(result.published,true); assert.equal(requests.length,2);
    assert.match(requests[0]!.url,/\/a\/changes\/123\/detail\?o=DETAILED_LABELS&o=CURRENT_REVISION$/);
    assert.equal((requests[0]!.init.headers as Record<string,string>).authorization,'Bearer secret');
    const body=JSON.parse(String(requests[1]!.init.body));
    assert.equal(body.labels.Verified,1); assert.equal(body.comments['src/a.ts'][0].line,9); assert.equal(body.comments['src/a.ts'][0].unresolved,true);
  } finally { globalThis.fetch=previous; }
});

test('Gerrit auth is fail-closed and review summary is deterministic',()=>{
  assert.throws(()=>gerritAuthFromEnv({authMode:'bearer',tokenEnv:'MISSING',usernameEnv:'U',passwordEnv:'P'},{}),/MISSING/);
  assert.deepEqual(gerritAuthFromEnv({authMode:'basic',tokenEnv:'T',usernameEnv:'U',passwordEnv:'P'},{U:'alice',P:'pw'}),{mode:'basic',username:'alice',password:'pw'});
  assert.match(gerritReviewMessage('FAIL',[finding]),/critical=0, high=1/);
});
