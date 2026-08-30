# Slice 15 — C and C++ ecosystem support

Implemented first-class C/C++ support across SentryCode's existing assurance pipeline.

## Project and dependency discovery

- CMake/Conan/vcpkg service classification for monorepos.
- Conan dependencies from `conanfile.txt`, common `conanfile.py` forms, and resolved `conan.lock` references.
- vcpkg dependencies from exact manifest versions, `vcpkg-lock.json`, and resolved `vcpkg_installed/vcpkg/status`.
- Conan and vcpkg Package URLs are emitted into the existing CycloneDX 1.5 and SPDX 2.3 SBOM generators.
- Dependency allow/deny/version policy, vulnerability matching, license policy, waivers, release gates and evidence operate on the normalized C/C++ components.
- Unversioned vcpkg manifest constraints are not converted into invented installed versions; resolved lock/status data is preferred.

## Native C/C++ SAST

Native scanning now recognizes C and C++ source/header extensions and detects high-risk APIs including shell execution, `gets`, unbounded string copy/concatenation, `sprintf`, insecure temporary naming and non-cryptographic `rand`. Existing external SARIF import remains complementary for compiler/analyzer-specific coverage.

## Automotive compatibility

The existing automotive evidence adapter remains the authoritative route for MISRA C/C++, AUTOSAR C++ and related external analyzer findings. Native SAST does not claim to replace licensed or specialist automotive analyzers.

## Validation

- TypeScript check: PASS
- Full automated tests: 94/94 PASS
- Build: PASS
