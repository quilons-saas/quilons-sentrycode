# SentryCode PostgreSQL application state

SentryCode uses PostgreSQL for durable standalone-server administration state. PostgreSQL is a separate deployment unit and is not embedded in the SentryCode runtime container.

## Boundaries

PostgreSQL stores repository registrations, managed scanner settings, policy assignments, waiver workflow state, principals/RBAC metadata, integration metadata and application audit indexes. It does **not** replace SentryCode's signed/tamper-evident evidence store. Evidence remains authoritative in the governed evidence store and may be indexed by application state in later releases.

Repository-effective UI changes are materialized to `.sentrycode` files in registered repositories so CLI/CI executions consume the same policy/configuration contracts. If signed configuration enforcement is enabled, UI materialization fails closed rather than modifying signed repository configuration.

## Development/private deployment

Start the dedicated database container:

```powershell
$env:SENTRYCODE_POSTGRES_PASSWORD = "use-a-long-random-password"
docker compose -f deploy/docker-compose.postgres.yml up -d
$env:SENTRYCODE_DATABASE_URL = "postgresql://sentrycode:$env:SENTRYCODE_POSTGRES_PASSWORD@127.0.0.1:54327/sentrycode"
node .\dist\cli\main.js database migrate
node .\dist\cli\main.js database status
```

Enable Web UI administration with a separate session/admin secret:

```powershell
$env:SENTRYCODE_UI_ADMIN_TOKEN = "use-a-different-long-random-token"
node .\dist\cli\main.js ui --no-open
```

The browser does not receive database credentials. State-changing requests require the admin token in local-admin mode. Enterprise OIDC/RBAC authentication is completed in the next enterprise deployment slice.
