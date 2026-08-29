# SentryCode Standalone UI — Slice 4 Enterprise & Container Implementation

## Scope

This slice completes the main standalone-server productization layer on top of the existing CLI, UI and PostgreSQL administration foundation.

Implemented:

- Production multi-stage Dockerfile.
- Non-root SentryCode runtime container.
- Separate PostgreSQL container in production Docker Compose.
- Persistent SentryCode and PostgreSQL volumes.
- Internal-only PostgreSQL network exposure.
- Container liveness and application readiness endpoints.
- Automatic database migration before container server startup.
- Graceful SIGINT/SIGTERM Web UI shutdown.
- Local viewer and administrator token modes.
- Optional enterprise OIDC access-token validation using RS256/JWKS, issuer, audience and expiry/nbf checks.
- PostgreSQL principal registry as the authoritative OIDC role assignment.
- Server-enforced RBAC roles: viewer, engineer, security_admin, administrator.
- Principal administration UI for administrators.
- Automotive operations page exposing imported MISRA/AUTOSAR counts, deviations and evidence targets without redistributing rule text or making certification claims.
- Enterprise diagnostics, audit-chain state, vulnerability-intelligence status and Compliance connection status.
- Governed UI actions for file/evidence backup, restore, retention and OSV intelligence sync.
- Integration metadata now accepts endpoint/URL plus secret references without storing credentials.
- Docker deployment and security documentation.
- Tests for container separation and server-side RBAC.

## Trust boundaries

- PostgreSQL stores operational/admin state and does not replace signed evidence authority.
- UI authorization is enforced by the server.
- OIDC role claims are not used directly; SentryCode's principal registry determines the role.
- The browser stores the current access token only in sessionStorage.
- PostgreSQL backup remains a database-native concern (`pg_dump`/managed backup), explicitly separate from SentryCode file/evidence backups.
- Automotive UI shows analyzer-derived rule IDs/evidence only and does not claim regulatory certification.

## Validation in implementation environment

- `npm run check`: PASS.
- `npm test`: 77/77 PASS.
- `npm run build`: PASS.
- JavaScript syntax check for the standalone UI: PASS.
- Docker runtime execution must be validated on the Windows/Docker host because Docker is not available in the implementation sandbox.
