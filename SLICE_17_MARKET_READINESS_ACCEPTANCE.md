# Slice 17 — Cross-Language Market-Readiness Acceptance

Status: implemented.

This slice closes the market-readiness validation layer after first-class Gerrit and native ecosystem expansion.

## Acceptance coverage

- Native SAST matrix: JavaScript, TypeScript, Python, Java, C#, C, C++, Rust and Go.
- Dependency ecosystem matrix: npm, PyPI, Maven, NuGet, Conan, vcpkg, Cargo and Go modules.
- Package URL normalization for every supported dependency ecosystem.
- CycloneDX 1.5 and SPDX 2.3 serialization across the full dependency matrix.
- Monorepo/service classification regression coverage for every supported service family.
- Existing policy, waiver, release-gate, offline intelligence, evidence-integrity, Gerrit, Docker, PostgreSQL and RBAC regression tests remain mandatory.
- Executable `npm run acceptance:market` gate.
- Existing `npm run acceptance:docker` remains the standalone deployment gate.

No new decision engine was introduced; the slice verifies the existing governed SentryCode enforcement pipeline end-to-end.
