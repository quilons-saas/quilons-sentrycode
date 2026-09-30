import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_CONFIG } from '../src/config/defaults.js';
import { describeConsumerAdapters, listConfiguredConsumers, requiredScannerUnion } from '../src/consumers/registry.js';

test('legacy CRA reporting is exposed through the compatibility consumer registry without changing runtime delivery', () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.craReporting.enabled = true;
  config.craReporting.endpoint = 'https://cra.example/invoke';
  config.craReporting.assessmentId = 'assessment-1';
  config.craReporting.severities = ['critical'];
  const consumers = listConfiguredConsumers(config);
  assert.equal(consumers.length, 1);
  assert.equal(consumers[0]!.consumerId, 'cra');
  assert.equal(consumers[0]!.adapter, 'cra');
  assert.equal(consumers[0]!.context.assessmentId, 'assessment-1');
  assert.deepEqual(consumers[0]!.scanProfile.severities, ['critical']);
});

test('explicit CRA consumer replaces only the registry compatibility projection, not legacy config', () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.craReporting.enabled = true;
  config.craReporting.assessmentId = 'legacy-assessment';
  config.consumers = [{ consumerId:'cra', adapter:'cra', enabled:true, endpoint:'https://new.example', tokenEnv:'NEW_TOKEN', timeoutMs:1, maxAttempts:1, retryDelayMs:0, scanProfile:{requiredScanners:['dependencies'],evidenceTypes:[],severities:['high'],findingTypes:[]}, context:{assessmentId:'new-assessment'} }];
  const consumers = listConfiguredConsumers(config);
  assert.equal(consumers.length, 1);
  assert.equal(consumers[0]!.context.assessmentId, 'new-assessment');
  assert.equal(config.craReporting.assessmentId, 'legacy-assessment');
});

test('unknown adapters are visible but unavailable and do not contribute required scanners yet', () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.consumers = [
    { consumerId:'cra', adapter:'cra', enabled:true, endpoint:'', tokenEnv:'', timeoutMs:15000, maxAttempts:5, retryDelayMs:30000, scanProfile:{requiredScanners:['dependencies','sast'],evidenceTypes:[],severities:['high'],findingTypes:[]}, context:{} },
    { consumerId:'future', adapter:'not-installed', enabled:true, endpoint:'', tokenEnv:'', timeoutMs:15000, maxAttempts:5, retryDelayMs:30000, scanProfile:{requiredScanners:['future-scanner'],evidenceTypes:[],severities:[],findingTypes:[]}, context:{} }
  ];
  const statuses = describeConsumerAdapters(config);
  assert.deepEqual(statuses.map((item) => [item.consumer.consumerId, item.available]), [['cra', true], ['future', false]]);
  assert.deepEqual(requiredScannerUnion(config), ['dependencies', 'git-assurance', 'sast', 'secrets']);
});


test('Cyber adapter is installed and contributes declared scanners to the union', () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.policy.requiredScanners = [];
  config.consumers = [{ consumerId:'cyber', adapter:'cyber', enabled:true, endpoint:'https://cyber.example/invoke', tokenEnv:'CYBER_TOKEN', timeoutMs:1000, maxAttempts:3, retryDelayMs:0, scanProfile:{requiredScanners:['dependencies','provenance'],evidenceTypes:[],severities:[],findingTypes:[]}, context:{buildId:'build-1'} }];
  const statuses = describeConsumerAdapters(config);
  assert.deepEqual(statuses.map((item) => [item.consumer.consumerId, item.available]), [['cyber', true]]);
  assert.deepEqual(requiredScannerUnion(config), ['dependencies', 'provenance']);
});
