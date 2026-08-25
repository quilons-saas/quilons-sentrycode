# SentryCode Slice 2 — SBOM, Dependency, License & Vulnerability Engine

## Implemented

- Node/npm dependency discovery from `package-lock.json`.
- Pinned Python discovery from `requirements.txt` and PEP 621 `pyproject.toml` dependency arrays.
- Normalized dependency component model with ecosystem, version, direct/dev flags, source, license and purl.
- CycloneDX 1.5 SBOM generation.
- SPDX 2.3 SBOM generation.
- Git-ref dependency snapshots and added/removed/upgraded/downgraded dependency diffing.
- Dependency deny/allow policy.
- Version restriction policy.
- Approved registry policy.
- License allow/deny/review/unknown policy with package overrides.
- Offline vulnerability database abstraction and affected-version matching.
- Known-exploited severity escalation policy.
- Normalized `dependency`, `license`, and `vulnerability` findings.
- Evidence: `sbom.generated`, `dependency.check`, `license.check`, `vuln.scan`.
- CLI: `sentrycode sbom` and `sentrycode dependencies diff`.
- Existing `scan`/`check` now run both secret and dependency assurance scanners.
- High-entropy secret heuristic hardened against registry URL / artifact-path false positives discovered during integration smoke testing.

## Validation performed

- TypeScript strict check: PASS.
- Focused Node test suite: 16/16 PASS.
- CycloneDX generation against a real temporary Git repository: PASS.
- SPDX generation against a real temporary Git repository: PASS.
- Full policy scan of safe dependency fixture: PASS / exit 0.
- Evidence set contains secret, SBOM, dependency, license and vulnerability evidence: PASS.
- Git-ref dependency diff correctly classified an npm upgrade: PASS.

## Deliberate boundaries

- No mandatory commercial vulnerability/scanning service was introduced.
- Local vulnerability intelligence format is intentionally provider-neutral; later sync/adapters can populate the same normalized advisory model.
- Python dependencies without a resolved/pinned version are not assigned a guessed version.
- Full package-manager coverage (Poetry/PDM/uv/pip lock formats, pnpm/yarn) remains for later expansion.
- Rich semver/PEP 440 parsing is not claimed; Slice 2 implements the bounded range syntax required for current policy and local advisory fixtures.
