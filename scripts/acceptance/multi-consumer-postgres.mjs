import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import pg from 'pg';
import { createPostgresApplicationStateStore } from '../../dist/application/postgres.js';
import { deliverPendingConsumerDeliveries, enqueueConsumerDeliveries } from '../../dist/consumers/delivery.js';

const execFileAsync=promisify(execFile);
const root=resolve(fileURLToPath(new URL('../..',import.meta.url)));
const name=`sentrycode-multi-consumer-${Date.now().toString(36)}`.toLowerCase();
const password=randomBytes(24).toString('base64url');
let started=false;
let port=0;
let connectionString='';
const auditRoot=await mkdtemp(join(tmpdir(),'sentrycode-multi-consumer-'));

function pass(message){process.stdout.write(`PASS ${message}\n`);}
function fail(message){throw new Error(message);}
async function docker(args){return execFileAsync('docker',args,{cwd:root,windowsHide:true,maxBuffer:20*1024*1024});}
async function freePort(){return new Promise((ok,bad)=>{const server=createServer();server.once('error',bad);server.listen(0,'127.0.0.1',()=>{const address=server.address();if(!address||typeof address==='string'){server.close();bad(new Error('could not allocate port'));return;}const value=address.port;server.close((error)=>error?bad(error):ok(value));});});}
async function waitPostgres(){const deadline=Date.now()+120000;let last='';while(Date.now()<deadline){try{await docker(['exec',name,'pg_isready','-U','sentrycode','-d','sentrycode']);return;}catch(error){last=error instanceof Error?error.message:String(error);}await new Promise((resolveWait)=>setTimeout(resolveWait,1000));}fail(`PostgreSQL readiness timeout: ${last}`);}

const craMessage={consumerId:'cra',adapterId:'cra',adapterContractVersion:'1.0.0',messageId:'shared-finding',tenant:'acceptance',project:'multi-consumer',findingId:'finding-1',runId:'run-1',payload:{kind:'cra',findingId:'finding-1'}};
const cyberMessage={consumerId:'cyber',adapterId:'cyber',adapterContractVersion:'cyber.security-evidence.v1',messageId:'shared-finding',tenant:'acceptance',project:'multi-consumer',findingId:'finding-1',runId:'run-1',payload:{kind:'cyber',findingId:'finding-1'}};
const okPublisher={async publish(){return{statusCode:202};}};
const failPublisher={async publish(){throw new Error('consumer unavailable');}};

try{
  await docker(['version']);
  port=await freePort();
  connectionString=`postgresql://sentrycode:${encodeURIComponent(password)}@127.0.0.1:${port}/sentrycode`;
  await docker(['run','-d','--name',name,'-e','POSTGRES_DB=sentrycode','-e','POSTGRES_USER=sentrycode','-e',`POSTGRES_PASSWORD=${password}`,'-p',`127.0.0.1:${port}:5432`,'postgres:17-alpine']);
  started=true;
  await waitPostgres();
  pass('isolated PostgreSQL is ready');

  // Build a real upgrade path from schema 2 with historical CRA delivery state.
  const pool=new pg.Pool({connectionString,max:1,connectionTimeoutMillis:5000});
  const migration1=await readFile(resolve(root,'migrations','001_application_state.sql'),'utf8');
  const migration2=await readFile(resolve(root,'migrations','002_cra_report_delivery.sql'),'utf8');
  await pool.query(migration1);
  await pool.query(migration2);
  await pool.query(`INSERT INTO sentrycode_cra_report_delivery(report_id,tenant,project,finding_id,run_id,payload,status,attempt_count) VALUES($1,$2,$3,$4,$5,$6::jsonb,'failed',1)`,['legacy-report','legacy-tenant','legacy-project','legacy-finding','legacy-run',JSON.stringify({legacy:true})]);
  await pool.end();

  let store=await createPostgresApplicationStateStore(connectionString);
  const schema=await store.migrate();
  if(schema!==4)fail(`expected schema 4, received ${schema}`);
  const migrated=await store.listPendingConsumerDeliveries('cra','legacy-tenant','legacy-project',3,new Date().toISOString(),100);
  const legacy=migrated.find((item)=>item.messageId==='legacy-report');
  if(!legacy||legacy.adapterContractVersion!=='1.0.0'||legacy.attemptCount!==1)fail(`legacy CRA migration mismatch: ${JSON.stringify(legacy)}`);
  pass('schema 2 CRA delivery history migrated into versioned generic delivery state');

  const queued=await enqueueConsumerDeliveries(store,[craMessage,cyberMessage]);
  if(queued.filter((item)=>item.created).length!==2)fail('expected two independent consumer deliveries');
  const cra=await deliverPendingConsumerDeliveries({store,publisher:okPublisher,consumerId:'cra',tenant:'acceptance',project:'multi-consumer',options:{maxAttempts:3,retryDelayMs:0},root:auditRoot,auditLogFile:'.sentrycode/acceptance-audit.jsonl',now:new Date()});
  const cyber=await deliverPendingConsumerDeliveries({store,publisher:failPublisher,consumerId:'cyber',tenant:'acceptance',project:'multi-consumer',options:{maxAttempts:3,retryDelayMs:0},root:auditRoot,auditLogFile:'.sentrycode/acceptance-audit.jsonl',now:new Date()});
  if(cra.delivered!==1||cra.failed!==0||cyber.delivered!==0||cyber.failed!==1)fail(`failure isolation mismatch CRA=${JSON.stringify(cra)} Cyber=${JSON.stringify(cyber)}`);
  pass('CRA success is isolated from Cyber delivery failure');
  await store.close();

  await docker(['restart',name]);
  await waitPostgres();
  store=await createPostgresApplicationStateStore(connectionString);
  const craAfterRestart=await deliverPendingConsumerDeliveries({store,publisher:okPublisher,consumerId:'cra',tenant:'acceptance',project:'multi-consumer',options:{maxAttempts:3,retryDelayMs:0},root:auditRoot,auditLogFile:'.sentrycode/acceptance-audit.jsonl',now:new Date()});
  const cyberAfterRestart=await deliverPendingConsumerDeliveries({store,publisher:okPublisher,consumerId:'cyber',tenant:'acceptance',project:'multi-consumer',options:{maxAttempts:3,retryDelayMs:0},root:auditRoot,auditLogFile:'.sentrycode/acceptance-audit.jsonl',now:new Date(Date.now()+1000)});
  if(craAfterRestart.attempted!==0)fail(`CRA was duplicated after restart: ${JSON.stringify(craAfterRestart)}`);
  if(cyberAfterRestart.delivered!==1||cyberAfterRestart.failed!==0)fail(`Cyber retry after restart failed: ${JSON.stringify(cyberAfterRestart)}`);
  pass('retry state survives PostgreSQL/container restart without duplicating delivered consumer');

  const duplicate=await enqueueConsumerDeliveries(store,[craMessage]);
  if(duplicate[0]?.created!==false)fail('idempotent duplicate unexpectedly created a new delivery');
  let collision=false;
  try{await enqueueConsumerDeliveries(store,[{...craMessage,tenant:'wrong-tenant'}]);}catch(error){collision=/idempotency collision/.test(error instanceof Error?error.message:String(error));}
  if(!collision)fail('delivery idempotency collision did not fail closed');
  pass('idempotency and tenant binding fail closed');

  await store.close();
  process.stdout.write('\nSENTRYCODE MULTI-CONSUMER POSTGRES ACCEPTANCE: PASS\n');
}catch(error){
  process.stderr.write(`\nSENTRYCODE MULTI-CONSUMER POSTGRES ACCEPTANCE: FAIL\n${error instanceof Error?error.stack??error.message:String(error)}\n`);
  process.exitCode=1;
}finally{
  if(started){try{await docker(['rm','-f',name]);pass('isolated PostgreSQL container removed');}catch(error){process.stderr.write(`WARN cleanup failed: ${error instanceof Error?error.message:String(error)}\n`);process.exitCode=1;}}
  await rm(auditRoot,{recursive:true,force:true});
}
