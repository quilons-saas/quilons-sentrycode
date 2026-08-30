# Slice 18 — Cross-Language Market-Readiness Hardening

This correction closes the final expanded cross-language market-readiness gaps identified in the full-repository review at `a92f660`.

Implemented in this slice:

- Git-ref dependency diff discovery across every supported ecosystem, including nested/monorepo manifests and lock files.
- CycloneDX 1.5 dependency relationships and available package hashes.
- SPDX 2.3 dependency relationships, available checksums, and product-version metadata aligned to SentryCode 0.1.0.
- Denied-registry policy in addition to existing registry allowlisting.
- Deterministic governed dependency-maintenance metadata with stale/deprecated/missing-metadata enforcement.
- Go `replace` and `exclude` handling so the assessed component matches the effective module selection.
- Cargo workspace-aware direct dependency classification by combining member manifests with the resolved workspace lock and Cargo lock checksums/relationships where present.
- Maven `dependencyManagement` resolution for direct dependencies without inline versions.
- Python resolved-lock ingestion for Poetry and uv in addition to pinned requirements.
- Expanded acceptance tests covering cross-ref ecosystem changes, governance, effective Go modules, Maven management, Python locks, SBOM relationships and hashes.

The built-in language rules remain a deterministic **baseline SAST**. Deeper specialist language analyzers continue to integrate through the governed SARIF adapter and participate in the same scanner-failure, policy, waiver, release-gate, evidence, CI and reporting boundaries.
