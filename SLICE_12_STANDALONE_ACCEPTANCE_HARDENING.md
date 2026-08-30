# SentryCode Standalone UI — Slice 5 / Repository Slice 12 Acceptance & Hardening

## Purpose

Close the standalone SentryCode product implementation with executable production acceptance instead of declaring readiness from unit tests alone.

## Implemented

- Isolated whole-product Docker acceptance harness (`npm run acceptance:docker`).
- Fresh temporary secrets, loopback port, Compose project and volumes per acceptance run.
- Real SentryCode + PostgreSQL image build/start/readiness validation.
- Anonymous/viewer/administrator API and RBAC validation against the running container.
- PostgreSQL-backed repository and integration persistence checks.
- SentryCode-only restart persistence check.
- SentryCode + PostgreSQL restart persistence check.
- Operational backup and retention endpoint checks.
- Enterprise diagnostics, Automotive operational state and application-audit checks.
- Failure log capture and automatic container/network/volume cleanup.
- Production container hardening with read-only root filesystem, no-new-privileges, dropped Linux capabilities, init process and explicit graceful-stop period.
- PostgreSQL client connection timeout so readiness/admin paths fail promptly when the database is unreachable.
- Whole-product acceptance documentation.

## Acceptance boundary

A final standalone-product PASS requires both:

1. normal repository validation (`npm run check`, `npm test`, `npm run build`, `npm run package:smoke`), and
2. `npm run acceptance:docker` on a Docker-capable host.

External OIDC providers, external analyzers and customer Compliance deployments remain deployment-specific integration acceptance, not hidden prerequisites for standalone SentryCode operation.
