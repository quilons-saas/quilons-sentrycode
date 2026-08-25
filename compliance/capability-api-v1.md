# SentryCode Compliance Capability API v1

Base path: `/v1`. The API is read-only from the QUILONS Compliance consumer perspective. SentryCode remains authoritative for its findings, policy decisions, waivers, and evidence. No consumer is permitted direct database/file-store access.

- `GET /v1/health`
- `GET /v1/ready`
- `GET /v1/manifest`
- `GET /v1/runs?tenant=...&project=...`
- `GET /v1/runs/{runId}?tenant=...&project=...`
- `GET /v1/runs/{runId}/findings?tenant=...&project=...`
- `GET /v1/runs/{runId}/evidence?tenant=...&project=...`
- `GET /v1/runs/{runId}/policy?tenant=...&project=...`
- `GET /v1/runs/{runId}/waivers?tenant=...&project=...`

Tenant and project are mandatory for run data. Storage scopes are hashed and isolated. Non-loopback binding requires bearer authentication. The token is supplied through the configured environment-variable name and is never stored in the repository configuration.

## Multi-tenant authorization (Slice 9)

For shared/multi-tenant deployments, configure `compliance.authMode` as `hmac`. The bearer token is a SentryCode capability token containing tenant, project, issuer, audience and expiry claims. Run-data routes derive the authoritative scope from those claims. Supplying a conflicting `tenant` or `project` query parameter returns `403 scope_forbidden`.

Static bearer-token mode remains available for local or single-scope deployments. It must not be used as the tenant-authorization mechanism for a shared multi-tenant Compliance service.
