# SentryCode Cross-Language Market-Readiness Acceptance

This acceptance gate is the final v0.1 market-readiness check for the supported language and package ecosystem matrix.

## Supported native source languages

- JavaScript and TypeScript
- Python
- Java
- .NET / C#
- C
- C++
- Rust
- Go

## Supported dependency ecosystems

- npm
- PyPI
- Maven / Gradle
- NuGet
- Conan
- vcpkg
- Cargo
- Go modules

## Acceptance command

```bash
npm run acceptance:market
```

The command performs TypeScript validation, the complete regression suite, a production build, and an executable cross-language acceptance harness. The harness verifies native SAST coverage, dependency normalization and Package URLs, and both CycloneDX 1.5 and SPDX 2.3 serialization across the full ecosystem matrix.

For standalone deployment acceptance, run separately:

```bash
npm run acceptance:docker
```

A market-ready release requires both acceptance commands to pass.

## Enforcement boundaries

Language support is not treated as a SAST-only capability. Dependency ecosystems feed the same SentryCode dependency, vulnerability, license, SBOM, waiver, release-gate, CI/incremental and signed-evidence paths already used by the product.

C/C++ automotive MISRA/AUTOSAR findings remain complementary external-analyzer evidence and are not replaced by generic native SAST.

Gerrit remains a first-class governed CI/review integration and is covered by the complete regression suite.
