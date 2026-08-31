# Slice 22 - CRA delivery, PostgreSQL retry state, idempotency and audit

## Analysis decision

The pre-slice investigation found that SentryCode already had reusable HTTP publishing, bearer-token configuration, stable IDs, the tamper-evident enterprise audit chain and PostgreSQL application state. The only missing durable capability was outbound CRA delivery state. Following explicit approval, Slice 22 extends the existing PostgreSQL application-state architecture rather than creating a filesystem outbox or a second evidence store.

## Implemented

- Added PostgreSQL migration 002 for durable CRA report delivery state.
- Extended the existing `ApplicationStateStore` / PostgreSQL store with CRA enqueue, pending-selection and attempt-recording operations.
- Reused the stable `CraFindingReport.reportId` as the idempotency key.
- Added bounded persisted retry using `maxAttempts` and `retryDelayMs`.
- Reused the existing HTTP publisher implementation through one shared POST helper; no second HTTP/auth stack was created.
- Added a CRA HTTP publisher that sends the existing Slice 20/21 technical-finding contract.
- Added delivery orchestration that queues reports, retries due pending/failed reports, and never resends a delivered report.
- Reused the existing tamper-evident enterprise audit chain for queue/delivery/failure/unavailable events.
- Integrated CRA reporting after authoritative Compliance evidence storage so `/v1/runs/{runId}/evidence` references remain resolvable.
- Preserved the existing Compliance remote publication behavior and all existing read APIs.
- Kept CRA delivery outcome separate from SentryCode's technical scan decision.

## Deliberately not implemented

- No CRA regulatory interpretation or CRA violation verdicts.
- No new evidence model or evidence database.
- No filesystem fallback outbox.
- No background worker/event-bus architecture.
- No invented CRA receipt-ID field. HTTP success/status is retained until CRA defines a versioned acknowledgement contract.

## Validation added

- PostgreSQL delivery schema/idempotency-state assertions.
- Queue idempotency and no resend after successful delivery.
- Persistent failed state and later recovery without rebuilding the original report.
- Retry-delay enforcement and maximum-attempt bound.
- Existing CRA configuration tests updated for retry controls.

## Acceptance harness correction

Standalone Docker acceptance now derives the expected PostgreSQL schema version from the numbered migration files instead of hard-coding schema version 1. This keeps acceptance aligned with the existing migration mechanism as new schema versions are added. No production runtime architecture changed.
