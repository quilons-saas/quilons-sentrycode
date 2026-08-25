# SentryCode Slice 4 Implementation

## Scope

Slice 4 adds code-level static analysis, Git assurance, build provenance, signed attestations, and SARIF output while preserving the Slice 1–3 finding, evidence, policy, waiver, and release-gate authority model.

## Implemented

### Native SAST
- Scanner plugin `sast`.
- Initial TypeScript/JavaScript rules: dynamic eval, shell command execution, non-cryptographic randomness.
- Initial Python rules: dynamic eval, `subprocess` with `shell=True`, unsafe pickle deserialization.
- Findings use the existing normalized SentryCode finding contract and therefore participate in hierarchical policy, waivers, and release gating.
- Evidence type: `sast.scan`.

### Git assurance
- Scanner plugin `git-assurance`.
- Commit author name/email capture.
- Commit-signature status and optional signed-commit enforcement.
- Optional clean-working-tree enforcement.
- Optional allowed author-email-domain policy.
- Evidence type: `commit.verification`.
- Provider-neutral `GitGovernanceProvider` boundary for future branch protection / required review checks.

### Provenance and build evidence
- Scanner plugin `provenance`.
- Build/repository metadata evidence even when no build artifact is configured.
- Configurable artifact SHA-256 hashing.
- Evidence types: `build.attestation`, `provenance.attestation`.
- in-toto Statement v1 with SLSA provenance v1 predicate type.
- Optional PEM private-key signing and public-key signature verification.
- Tampered statements fail verification.

### CLI
- `scan` / `check` now run SAST + Git assurance + provenance in addition to prior scanners.
- `--format sarif` for scan/check/policy-evaluate/release-check output.
- `provenance attest --artifact ... [--key ...] [--output ...]`.
- `provenance verify --attestation ... --public-key ...`.

### Configuration
New additive sections:
- `sast`
- `gitAssurance`
- `provenance`

SAST and Git assurance are required scanners in the default policy baseline. Provenance is enabled but not required by default because artifact production is build-specific.

## Tests added
- Native SAST rule detection.
- Unsigned commit enforcement.
- Artifact hashing, signing, verification, and tamper detection.
- SARIF serialization from normalized findings.

## Architectural boundaries preserved
- Scanner plugins do not make final release decisions.
- Policy remains the enforcement authority.
- Findings/evidence remain scanner-neutral contracts.
- No Git provider is required by core.
- No paid/cloud dependency is required.
- No source code is transmitted externally.
