# Slice 16 — Rust + Go ecosystem implementation

Implemented first-class Rust and Go support across dependency assurance, native SAST, SBOM/policy/evidence, vulnerability intelligence and monorepo discovery.

## Rust
- `Cargo.toml` direct/dev dependency classification.
- resolved `Cargo.lock` inventory and Cargo package URLs.
- OSV `crates.io` synchronization.
- local Cargo cache license enrichment without network access.
- native Rust SAST rules for shell execution, transmute and unchecked UTF-8.
- Cargo service-root classification.

## Go
- `go.mod` direct/indirect dependency discovery; `go.sum` is recognized as project evidence.
- Go module package URLs.
- OSV `Go` synchronization.
- local Go module-cache license enrichment without network access.
- native Go SAST rules for shell execution, disabled TLS verification and weak digests.
- Go module service-root classification.

Both ecosystems feed the existing CycloneDX/SPDX SBOM, dependency/license/vulnerability policy, waivers, release gates, incremental CI execution and signed evidence pipeline.

Validation in implementation workspace: TypeScript check PASS, 101/101 tests PASS, build PASS.
