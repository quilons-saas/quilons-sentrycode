# Slice 21 - CRA Material Finding Selection and Report Creation

## Analysis performed before implementation

The existing implementation was inspected before changing code. The slice reuses the current policy-applied `AppliedFinding` collection, `ScanReport`, CRA report builder, Compliance identity, evidence links and stable ID implementation. No new scanner, finding representation, evidence store, regulatory mapping layer or pipeline architecture was introduced.

## Implemented

- Pure CRA materiality evaluation using the existing `craReporting.severities` and `craReporting.findingTypes` configuration.
- Empty finding-type configuration means all existing SentryCode finding types are eligible.
- Empty severity configuration means no findings are selected.
- Selection operates on the already policy-applied findings in a completed `ScanReport`.
- Waived findings remain selectable technical facts and retain their existing governed waiver state in the CRA report.
- Batch report creation reuses the Slice 20 `buildCraFindingReport` contract builder.
- Selected findings fail closed if no authoritative SentryCode evidence record references the finding.
- No CRA regulatory interpretation or CRA-specific violation mapping is introduced.

## Explicitly not implemented in this slice

- Network delivery to CRA.
- Retry/backoff, delivery persistence, acknowledgement or operational delivery state.
- Automatic invocation from the scan/CLI pipeline.
- Synthetic findings for release-gate state or evidence-only conditions.
- Changes to existing Compliance read APIs or evidence storage.

## Architectural invariants preserved

- SentryCode reports technical facts only.
- CRA owns Cyber Resilience Act interpretation.
- Existing SentryCode findings and evidence are reused rather than duplicated.
- Existing Compliance APIs remain unchanged.
- Standalone operation has no CRA runtime dependency.
