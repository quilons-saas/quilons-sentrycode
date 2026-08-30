# SentryCode Standalone Docker Deployment

SentryCode server mode is deployed as two containers:

- `sentrycode`: Web UI, versioned API and SentryCode runtime.
- `sentrycode-postgres`: open-source PostgreSQL application-state database.

The containers communicate on an internal Docker network. PostgreSQL is not published to the host by the production Compose file.

## Quick start

Copy `deploy/sentrycode.env.example` to a local `.env` file, replace every placeholder secret, then run:

```sh
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

The default UI address is `http://127.0.0.1:7787`.

The SentryCode container applies PostgreSQL migrations before starting the server. The database and SentryCode state both use named persistent volumes.

## Authentication

`SENTRYCODE_UI_TOKEN` provides viewer access to a non-loopback Web UI/API deployment.

`SENTRYCODE_UI_ADMIN_TOKEN` provides local administrator access. It must be a separate high-entropy secret.

Enterprise OIDC is optional. Configure:

- `SENTRYCODE_OIDC_ISSUER`
- `SENTRYCODE_OIDC_AUDIENCE`
- optionally `SENTRYCODE_OIDC_JWKS_URI`

If the JWKS URI is omitted, SentryCode uses OpenID Connect discovery. OIDC tokens are signature/issuer/audience/time validated. Authorization roles are assigned in SentryCode's PostgreSQL principal registry; token-supplied role claims are not trusted as the SentryCode role authority.

Roles:

- viewer
- engineer
- security_admin
- administrator

## Health and readiness

- `GET /api/v1/health` is a minimal liveness probe.
- `GET /api/v1/ready` reports Web UI and PostgreSQL readiness without exposing database credentials.

## Persistence

The PostgreSQL data volume contains application/admin state. The SentryCode data volume contains `.sentrycode` operational state such as evidence, audit material and vulnerability intelligence.

Evidence remains governed by SentryCode's signed/tamper-evident evidence model; PostgreSQL does not replace the evidence authority.

## Backup

The UI can create governed backups of SentryCode file/evidence state and apply evidence retention. PostgreSQL must be backed up separately using `pg_dump` or the customer's platform-native PostgreSQL backup mechanism. Database restore must be handled using PostgreSQL-native tooling rather than by copying database files from the SentryCode container.

## Repository mounts

Repositories registered for administration must be reachable from the SentryCode container at the registered path. Mount source read-only for scanning-only use. A repository must be writable only when administrators intentionally use UI features that materialize SentryCode configuration, policy or waivers into that repository.

## Security

The runtime image runs as the non-root `sentrycode` user. The production Compose file exposes only the SentryCode HTTP port and does not publish PostgreSQL. Secrets should be supplied by the deployment environment or secret manager and must not be committed to configuration files.

## Whole-product acceptance

Before accepting a standalone deployment, run `npm run acceptance:docker` from a Docker-capable host. The harness creates an isolated project and temporary volumes, validates the deployed authentication/RBAC and PostgreSQL persistence paths including service restarts, then tears the acceptance environment down. See `STANDALONE_ACCEPTANCE.md`.
