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
