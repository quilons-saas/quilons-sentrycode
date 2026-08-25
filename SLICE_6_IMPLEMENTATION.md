# Slice 6 — QUILONS Compliance Plugin and Evidence Integration

Slice 6 turns standalone SentryCode into a governed QUILONS Compliance plugin without making the Compliance shell, CRA, or any other module a runtime dependency of scanning.

## Implemented

- Versioned plugin manifest (`quilons.sentrycode`, API `1.0.0`).
- Capability descriptors for scan, findings, evidence, policy, waiver status, health/readiness.
- Versioned tenant/project-scoped evidence envelope suitable for QUILONS Compliance and CRA consumption.
- SentryCode-owned immutable local publication store under `.sentrycode/compliance/` (ignored by Git).
- Tenant/project isolation by cryptographic scope key; a run ID from one scope is not readable from another scope.
- Governed events: `sentrycode.scan.completed` and `sentrycode.evidence.available`.
- Optional outbound HTTP evidence publication to a configured QUILONS Compliance endpoint.
- Built-in read-only capability HTTP API for the Compliance shell.
- API bearer-token enforcement when binding beyond loopback.
- Health/readiness probes for QUILONS Installer.
- Installer plugin metadata under `integrations/installer/`.
- CLI commands for manifest, health, readiness, publication, run listing/readback and API serving.
- Configuration/environment overrides for tenant/project, endpoint and plugin API exposure.

## Architectural boundary

SentryCode owns its authoritative state. QUILONS Compliance and CRA consume versioned capabilities/evidence/events only. No direct cross-module database access is introduced. SentryCode continues to work when Compliance and CRA are absent.
