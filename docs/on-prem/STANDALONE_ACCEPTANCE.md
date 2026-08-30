# SentryCode Standalone Whole-Product Acceptance

The standalone acceptance harness validates the production deployment as a real two-container system rather than relying only on unit or static tests.

## Run

From the repository root with Docker Desktop / Docker Engine running:

```sh
npm run acceptance:docker
```

The harness creates an **isolated Compose project**, generates temporary high-entropy PostgreSQL/viewer/admin secrets, chooses an unused loopback port, builds the production SentryCode image, and creates dedicated temporary volumes. It does not reuse the normal SentryCode Compose project or its volumes.

## Acceptance gates

The harness fails unless all of the following are true:

1. Docker Engine and Docker Compose are available.
2. SentryCode and PostgreSQL start from a clean isolated deployment.
3. `/api/v1/ready` reports the Web service ready, PostgreSQL connected, and schema version 1.
4. Liveness remains public while the operational API rejects anonymous access.
5. The viewer token can read but cannot perform administrator mutations.
6. The administrator token resolves to the administrator role.
7. A PostgreSQL-backed repository registration succeeds.
8. Integration metadata can be persisted using a secret reference rather than a credential value.
9. PostgreSQL-backed state survives a SentryCode container restart.
10. State also survives a restart of both SentryCode and PostgreSQL.
11. Governed operational backup and retention endpoints execute.
12. Enterprise diagnostics and Automotive operational status are available.
13. Administrative writes appear in the application audit trail.
14. The isolated containers, network and volumes are destroyed after acceptance.

On failure, recent container logs are printed before cleanup.

Use `node scripts/acceptance/standalone-docker.mjs --keep` only for troubleshooting. This retains the isolated acceptance deployment and the temporary environment file so the failure can be inspected manually. Do not use `--keep` in CI.

## What this acceptance does not claim

The harness does not certify a customer's external identity provider, external scanner, QUILONS Compliance deployment, or organization-specific policy configuration. Those systems require environment-specific integration acceptance. OIDC token cryptography and server-side RBAC have deterministic automated tests in the normal test suite; the whole-product Docker harness proves the local-token production path and the deployed RBAC boundary.
