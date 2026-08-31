# SentryCode -> CRA technical finding reporting contract

SentryCode retains its existing governed Compliance capability API and local evidence store. CRA may continue to read runs, findings, evidence, policy state and waiver state through the existing versioned `/v1` API.

CRA reporting is an additive outbound integration. It is disabled by default and does not change standalone SentryCode operation.

## Responsibility boundary

SentryCode reports technical facts and authoritative evidence references. CRA determines whether those facts have regulatory significance under the Cyber Resilience Act. The SentryCode report contract deliberately contains no CRA violation or compliance verdict field.

## Identity reuse

CRA reporting reuses the existing governed Compliance identity (`compliance.tenant` and `compliance.project`) instead of defining a second tenant/project identity model.

## Configuration

```json
{
  "compliance": {
    "tenant": "customer-a",
    "project": "product-x"
  },
  "craReporting": {
    "enabled": false,
    "endpoint": "",
    "tokenEnv": "SENTRYCODE_CRA_TOKEN",
    "timeoutMs": 15000,
    "severities": ["high", "critical"],
    "findingTypes": []
  }
}
```

`severities` and `findingTypes` define materiality inputs for the later finding-selection slice. Slice 1 does not deliver reports.

Environment overrides supported by the existing configuration loader pattern:

- `SENTRYCODE_CRA_ENDPOINT`
- `SENTRYCODE_DISABLE_CRA_REPORTING=true`

## Contract

`src/compliance/cra-reporting.ts` defines the versioned `CraFindingReport` contract and a pure builder that reuses:

- `ComplianceIdentity`;
- the existing SentryCode `Finding` / `AppliedFinding` representation;
- `ScanReport` repository and CI correlation data;
- existing evidence records and `/v1/runs/{runId}/evidence` read capability;
- the existing SentryCode plugin identity and Compliance API version;
- the existing stable ID utility.

A report cannot be built unless the technical finding has at least one authoritative evidence record linked to it.

## Existing read APIs retained

This slice does not modify the existing endpoints, including:

- `GET /v1/runs`
- `GET /v1/runs/{runId}`
- `GET /v1/runs/{runId}/findings`
- `GET /v1/runs/{runId}/evidence`
- `GET /v1/runs/{runId}/policy`
- `GET /v1/runs/{runId}/waivers`

Proactive selection and delivery to CRA are intentionally deferred to later slices.

## Material finding selection

Slice 21 adds pure candidate selection over the existing policy-applied SentryCode findings. It does not introduce a CRA regulatory mapping layer.

- `craReporting.severities` limits candidates by the existing technical finding severity.
- `craReporting.findingTypes` limits candidates by the existing SentryCode finding type. An empty list means all finding types.
- An empty severity list selects no findings.
- Waived findings remain technical facts and may still be reported; their existing waiver status and waiver ID are carried in the report.
- A selected finding must already have authoritative SentryCode evidence linked through `EvidenceRecord.findingIds`; report creation fails closed when that link is absent.

This slice only selects and builds report contracts. Delivery, retry and acknowledgement remain deferred. Existing `/v1` read APIs are unchanged.

## Durable CRA delivery (Slice 22)

CRA proactive delivery reuses SentryCode's existing PostgreSQL application-state layer. It does not create a second evidence store.

When `craReporting.enabled` is true, SentryCode first persists the normal authoritative Compliance publication so the report's existing `/v1/runs/{runId}/evidence` reference remains resolvable. The CRA delivery queue stores only the versioned technical-finding report plus delivery state.

The PostgreSQL migration `002_cra_report_delivery.sql` adds `sentrycode_cra_report_delivery` with stable `report_id` identity, tenant/project scope, attempt state, response status, retry timing and error state. The stable Slice 20/21 report ID is the idempotency key; a delivered report is not selected for delivery again.

Delivery reuses the existing HTTP publishing implementation in `src/compliance/publisher.ts`: the shared POST helper supplies the configured bearer token, capability-version header and timeout. CRA delivery does not invent a second HTTP/authentication stack.

`craReporting` now also supports:

```json
{
  "maxAttempts": 5,
  "retryDelayMs": 30000
}
```

Failed reports remain in PostgreSQL and can be selected on a later SentryCode execution after the retry delay, without rebuilding or rerunning the original scan. Selection stops after `maxAttempts`, providing a bounded retry policy.

Delivery state is deliberately separate from the technical scan decision. A CRA endpoint or PostgreSQL outage is surfaced as CRA integration unavailability and audited, but it does not rewrite a SentryCode PASS/WARN/FAIL result.

The existing tamper-evident enterprise audit chain records CRA queue creation, successful delivery, delivery failure and integration unavailability. The PostgreSQL queue is operational state only; authoritative findings/evidence remain in the existing SentryCode evidence plane.

A successful HTTP response is the currently defined delivery acknowledgement and its status code is retained. No CRA-specific receipt identifier is parsed because no authoritative CRA receipt response contract has been defined; adding one must follow the normal versioned-contract process rather than guessing an API field.

All existing `/v1` Compliance read APIs remain unchanged and continue to be the authoritative pull path for CRA when it needs full evidence.


## Direct evidence retrieval (Slice 23)

CRA may resolve a specific evidence ID directly without fetching the complete evidence envelope for the run:

```text
GET /v1/runs/{runId}/evidence/{evidenceId}
```

The endpoint reuses the existing governed `/v1` authentication, tenant/project scope enforcement, immutable Compliance store and integrity verification path. It does not introduce a second evidence model or storage mechanism.

The existing bulk endpoint remains supported for compatibility:

```text
GET /v1/runs/{runId}/evidence
```

`CraFindingReport.evidenceReference.evidenceIds` remains the authoritative list of evidence records associated with the reported technical finding. CRA may request any of those IDs through the direct evidence route. The report contract itself is unchanged; no duplicate evidence locator representation is added.
