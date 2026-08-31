# Slice 20 - CRA Reporting Contract and Configuration

## Scope

Adds the versioned technical-finding report contract and configuration foundation required for proactive SentryCode -> CRA reporting.

## Reuse-first implementation

The slice does not introduce a second evidence model, identity model, finding model, ID generator, or read API. It reuses the existing Compliance identity, ScanReport/Finding/EvidenceRecord types, stable ID utility, plugin identity, Compliance API version, local evidence model and `/v1` read capabilities.

## Implemented

- Versioned `CraFindingReport` technical contract.
- Deterministic CRA report identity.
- Evidence reference back to existing SentryCode `/v1/runs/{runId}/evidence` capability.
- Existing tenant/project identity reuse.
- Repository, commit/branch and available CI correlation context.
- Active/waived technical status derived from existing policy findings.
- Additive `craReporting` configuration, disabled by default.
- Candidate severity and finding-type materiality inputs for the next slice.
- CRA endpoint/token-environment/timeout configuration.
- Documentation that SentryCode reports technical facts only and CRA owns regulatory interpretation.

## Explicitly not implemented in this slice

- CRA relevance/materiality selection logic.
- Automatic report generation from the scan pipeline.
- Network delivery to CRA.
- Retry/backoff or delivery persistence.
- CRA acknowledgements.
- Changes to existing Compliance read APIs.

## Architectural invariants preserved

- Standalone SentryCode has no CRA runtime dependency.
- Existing Compliance capability APIs remain available.
- No direct cross-product database access.
- SentryCode remains authoritative for its technical evidence.
- CRA determines Cyber Resilience Act consequences.
