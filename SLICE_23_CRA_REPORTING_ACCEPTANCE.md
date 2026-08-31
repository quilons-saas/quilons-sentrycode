# Slice 23 — CRA direct evidence retrieval and final integration acceptance

## Analysis conclusion

The existing Compliance evidence API already returns integrity-verified authoritative evidence for a run, and CRA reports already carry the exact `evidenceIds` associated with a finding. The only approved API gap was the lack of a direct evidence-by-ID read route.

## Implementation

- Added `GET /v1/runs/{runId}/evidence/{evidenceId}`.
- Reused `SentryCodeComplianceService.getEvidence()` and the existing immutable `LocalComplianceStore`; no second lookup/storage subsystem was introduced.
- Reused the existing server authentication and tenant/project scope boundary.
- Retained the existing bulk `/v1/runs/{runId}/evidence` endpoint.
- Kept the CRA finding report contract unchanged; its existing `evidenceIds` identify records that CRA may now retrieve directly.
- Added tests for direct service lookup, HTTP retrieval, missing evidence and scope isolation.

## Architecture

No architecture change was made. This is an additive read API operation over the existing governed evidence plane.
