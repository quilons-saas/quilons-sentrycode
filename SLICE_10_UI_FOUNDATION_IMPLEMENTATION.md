# SentryCode Standalone UI — Slice 1 Implementation

This slice introduces the first standalone professional SentryCode Web UI without making QUILONS Compliance a runtime dependency.

Implemented:
- `sentrycode ui` browser-launching local console and `sentrycode serve` headless server mode.
- Same-process static Web UI + versioned `/api/v1` operational API.
- No UI database: operational views are derived from SentryCode's existing integrity-verified local evidence/run store.
- Overview dashboard, repository inventory, run history/details, unified findings, policy/scanner configuration view, settings/trust state.
- PASS/WARN/FAIL, severity, waiver, scanner failure and evidence-integrity visibility.
- Light/dark professional desktop-first responsive design.
- Loopback-by-default; non-loopback UI service requires `SENTRYCODE_UI_TOKEN`.
- Content-Security-Policy, no-store API responses and browser-side read-only boundary for Slice 1.
- UI assets included in the distributable npm package.
- Backend tests for verified-store derivation, scope fail-closed behavior, asset/API serving and non-loopback authentication.

Deferred intentionally to subsequent slices:
- Governed policy editing and write-side RBAC/audit workflows.
- Waiver request/approval/rejection/revocation administration.
- Dedicated SBOM, vulnerability, license, release-gate and searchable evidence explorers.
- Integration administration, OIDC/RBAC completion, Automotive operational UI and Docker productization.

The UI does not duplicate scanner or policy decision logic. It consumes existing SentryCode contracts and verified persisted publications.
