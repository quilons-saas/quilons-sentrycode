# QUILONS SentryCode

**Catch compliance issues at code level — before merge, before release, before audit.**

SentryCode is a standalone developer/CI compliance engine and a future plugin for QUILONS Compliance. It scans repositories, normalizes findings and evidence, evaluates governed policy, and can act as a deterministic release gate.

## Requirements

- Node.js 20+
- Git
- Optional: OPA binary when Rego policy evaluation is enabled

## Development

```bash
npm install
npm run check
npm test
npm run build
```

## Core commands

```bash
sentrycode scan .
sentrycode check .
sentrycode sbom . --format cyclonedx --output artifacts/sbom.cdx.json
sentrycode sbom . --format spdx --output artifacts/sbom.spdx.json
sentrycode dependencies diff . --base origin/main --head HEAD

sentrycode policy validate .
sentrycode policy evaluate .
sentrycode release check .
```

Add `--service NAME` to policy-aware commands when evaluating a monorepo/service-specific policy scope.

## Configuration

Repository configuration lives at `.sentrycode/config.json`. If it is absent, built-in defaults are used. See `.sentrycode/examples/config.json`.

Policy documents are loaded from `.sentrycode/policies` by default. The hierarchy is:

```text
organization
  -> tenant
  -> project
  -> repository
  -> service
```

A parent policy can lock enforcement fields so a lower-level policy cannot override them. Policy resolution produces a deterministic SHA-256 fingerprint recorded in `policy.eval` and `release.gate` evidence.

Supported enforcement fields:

- `failOn`
- `warnOn`
- `requiredScanners`
- `scannerFailureModes`

Scanner failure behavior is policy controlled with `fail`, `warn`, or `ignore`. Required scanners that are skipped/disabled are treated as not having run.

## Governed waivers

Waivers are read from `.sentrycode/waivers.json` by default. They remain visible in results and can be governed with:

- approval requirement
- ticket/reference requirement
- maximum duration
- repository/service scope
- scanner/rule/path/fingerprint scope
- explicit expiry

Rejected and applied waiver decisions are recorded in the policy audit trail.

## OPA / Rego

OPA is optional and disabled by default. When enabled, SentryCode invokes the configured OPA binary with the repository, scanner results, effective built-in policy, and built-in decision as input.

SentryCode keeps the **stricter** result between the built-in policy engine and OPA. Rego therefore cannot silently weaken mandatory SentryCode enforcement.

See `.sentrycode/examples/release.rego`.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | PASS or WARN / successful command |
| 1 | Policy or release-gate failure |
| 2 | Runtime failure |
| 3 | Configuration or usage failure |

## Slice 1 — foundation and secrets

- repository context
- configuration
- scanner plugin boundary
- normalized findings/evidence
- secrets scanning with redaction
- console/JSON reporting
- baseline policy and waivers
- deterministic exit codes

## Slice 2 — dependency assurance

- npm `package-lock.json`
- pinned Python `requirements.txt`
- pinned PEP 621 `pyproject.toml`
- CycloneDX 1.5
- SPDX 2.3
- Git-ref dependency diffing
- dependency allow/deny/version/registry policy
- license policy
- offline vulnerability database
- `sbom.generated`, `dependency.check`, `license.check`, `vuln.scan` evidence

Unpinned Python constraints are intentionally not converted into invented installed versions.

## Slice 3 — policy-as-code and release gate

- versioned hierarchical policy documents
- organization/tenant/project/repository/service policy scopes
- parent policy field locking
- deterministic effective-policy fingerprint
- required/optional scanner failure semantics
- governed waiver approval/ticket/duration/scope rules
- policy audit records
- optional OPA/Rego integration
- `policy validate`
- `policy evaluate`
- `release check`
- `policy.eval` evidence
- `release.gate` evidence

The release gate is based on the same normalized findings, evidence and effective policy used by normal SentryCode scans.

## Slice 4: SAST, Git assurance, provenance and attestations

SentryCode now includes native security-analysis and provenance capabilities in the standard scan pipeline:

- TypeScript/JavaScript and Python SAST rules for high-risk constructs such as dynamic `eval`, shell execution, unsafe pickle deserialization, and security-sensitive weak randomness.
- Git assurance evidence for commit author identity, commit signature state, clean-working-tree policy, and configurable author email domains.
- A Git-provider governance adapter boundary for future branch-protection/review checks without coupling core to GitHub/GitLab/Azure DevOps.
- `build.attestation` and `provenance.attestation` evidence generated from repository/build context.
- Artifact SHA-256 hashing with in-toto Statement v1 / SLSA provenance-shaped attestations.
- Optional PEM-key signing and signature verification using Node cryptography.
- SARIF 2.1.0 output from normalized SentryCode findings.

Examples:

```bash
sentrycode scan . --format sarif --output sentrycode.sarif
sentrycode provenance attest . --artifact dist/app.js --key private.pem --output provenance.json
sentrycode provenance verify . --attestation provenance.json --public-key public.pem
```

The built-in SAST rules are intentionally a selected baseline, not a claim to replace every specialist static-analysis engine. Future scanner integrations plug into the same normalized finding/evidence boundary.
