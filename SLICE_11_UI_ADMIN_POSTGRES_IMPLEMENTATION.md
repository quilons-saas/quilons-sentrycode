# Slice 11 — PostgreSQL-backed standalone administration

This slice extends the standalone UI foundation with durable, write-capable administration while preserving SentryCode's existing CLI/core/evidence trust boundaries.

Implemented:
- PostgreSQL application-state abstraction and schema migration v1.
- Separate `sentrycode-postgres` Docker Compose deployment definition.
- Repository registrations scoped by tenant/project.
- Managed scanner settings with required/optional and fail/warn/ignore enforcement metadata.
- Managed policy assignments with hierarchy scope, versioning and locked-field metadata.
- Governed waiver request/approve/reject/revoke workflow state.
- Integration metadata and secret-reference fields (secrets themselves are not stored in the UI payload).
- Principal/RBAC persistence foundation.
- Application audit metadata plus existing SentryCode hash-chain audit events for UI writes.
- `sentrycode database migrate` and `sentrycode database status`.
- Versioned `/api/v1/admin/*` API.
- Local-admin write protection using `SENTRYCODE_UI_ADMIN_TOKEN`.
- Repository materialization of UI-managed policies, scanner settings and active waivers.
- Signed-config fail-closed protection for UI materialization.
- Standalone UI administration for repositories, scanners, policies, waivers and integrations.
- Engineering views for vulnerabilities, licenses, release gates and evidence navigation.

Evidence remains in the existing integrity-verified SentryCode evidence store; PostgreSQL is not an alternate evidence authority.
