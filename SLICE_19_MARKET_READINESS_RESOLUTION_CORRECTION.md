# Slice 19 — Market-readiness resolution correction

This bounded correction closes the dependency/SBOM accuracy findings from the final review of `c48be0a`.

Implemented:

- npm v2/v3 direct dependency classification from root lock metadata instead of flattened `node_modules` placement;
- project-local Python lock/directness association, including Poetry dependency tables;
- Cargo lock/workspace isolation plus workspace-inherited and renamed package directness;
- version-specific Go `replace` semantics and `go.sum` checksum ingestion;
- locally available Maven imported-BOM dependency-management resolution;
- deterministic regression coverage for each corrected case.

No new product surface is introduced. The change tightens the factual accuracy of dependency, SBOM, policy, and Git-ref evidence used by the existing market-readiness gate.
