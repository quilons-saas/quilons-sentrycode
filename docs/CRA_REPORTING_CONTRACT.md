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
