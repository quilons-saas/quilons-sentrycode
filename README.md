# QUILONS SentryCode

**Catch compliance issues at code level — before merge, before release, before audit.**

SentryCode is a standalone developer/CI compliance engine and a governed plugin for QUILONS Compliance. It scans repositories, normalizes findings and evidence, evaluates governed policy, and can act as a deterministic release gate.

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

## Slice 5: CI/CD, monorepos and incremental execution

SentryCode now detects GitHub Actions, GitLab CI, Azure DevOps, Jenkins and generic CI environments without making the core engine provider-specific.

Key behavior:

- `check` and `scan` automatically use incremental Git diffing when a trustworthy base ref is available.
- `--base REF` / `--head REF` explicitly control the comparison range.
- `--full` forces a complete scan.
- Secrets and native SAST restrict file reads to changed files during incremental runs.
- Dependency/license/vulnerability, Git assurance and provenance checks continue to evaluate repository-level state rather than reusing cached compliance decisions.
- Successful clean-repository runs persist only the last successful commit in `.sentrycode/cache/incremental.json`; findings and PASS/FAIL decisions are never replayed from cache.
- Scanner plugins execute concurrently with deterministic result ordering and configurable per-scanner timeout.
- `sentrycode services` discovers configured service roots and npm workspaces.
- `--service NAME` scopes changed-file scanning and policy context to a service.
- GitHub and Azure DevOps receive native log annotations; GitLab/Jenkins/generic CI receive stable SentryCode annotation lines.
- Environment overrides are supported for CI provider, incremental refs and scanner timeout.

Configuration precedence for supported runtime overrides is:

`CLI options > SENTRYCODE_* environment > repository config > built-in defaults`

Useful examples:

```bash
sentrycode check . --ci --format sarif --output .sentrycode/out/sentrycode.sarif
sentrycode check . --base origin/main --head HEAD
sentrycode check . --full
sentrycode services . --format json
sentrycode check . --service api --base origin/main
```

Reference CI templates are in `integrations/`.


## QUILONS Compliance plugin

SentryCode remains standalone but can publish its authoritative scan evidence into the QUILONS Compliance integration boundary.

```bash
sentrycode compliance manifest . --format json
sentrycode compliance health .
sentrycode compliance ready .
sentrycode compliance publish . --tenant tenant-a --project project-a
sentrycode compliance runs . --tenant tenant-a --project project-a --format json
sentrycode compliance serve .
```

The read-only capability API is versioned under `/v1`. Tenant/project scope is mandatory for run data. The API binds to loopback by default; non-loopback exposure requires a bearer token. QUILONS Compliance/CRA must not read SentryCode's storage directly.

## Slice 7: offline/on-prem enterprise hardening

SentryCode now has an explicit offline/on-prem operational profile rather than merely avoiding cloud dependencies.

- `SENTRYCODE_OFFLINE=true` or `offline.enabled` enables fail-closed offline behavior.
- Vulnerability intelligence can be imported from digest-verified local bundles and may require a trusted public-key signature.
- Repository configuration can be signed and verified; signed-config enforcement blocks normal execution when integrity verification fails.
- Compliance publications carry per-run SHA-256 integrity manifests and tampered evidence is rejected on read.
- Enterprise operations include diagnostics, backup, restore, retention, and append-only JSONL audit events.
- No source code is transmitted by these enterprise operations.

Examples:

```bash
sentrycode intelligence import . --bundle vuln-bundle.json
sentrycode config sign . --key private.pem
sentrycode config verify . --public-key public.pem
sentrycode enterprise diagnostics .
sentrycode enterprise backup .
sentrycode enterprise restore . --backup .sentrycode/backups/backup-...
sentrycode enterprise retention .
```

See `docs/on-prem/OFFLINE_OPERATIONS.md` for operational guidance.

## Slice 8: automotive compliance pack

Automotive assurance is adapter-driven. SentryCode imports rule-ID based native JSON or SARIF output from approved MISRA C, MISRA C++ and AUTOSAR C++ analyzers, applies governed deviations, and emits evidence aligned to ISO/SAE 21434 and UNECE R155/R156 engineering assurance. SentryCode does not redistribute proprietary rule text or claim that a scan alone establishes regulatory compliance.

## Slice 9: product completion and trust

Slice 9 closes the first product-completion blockers identified after the Slice 1–8 review.

### Standalone distribution

`@quilons/sentrycode` is now packable/installable as a normal CLI package. Customer repositories install SentryCode rather than building the SentryCode source repository:

```bash
npm install --save-dev @quilons/sentrycode@0.1.0
npx --no-install sentrycode check .
```

`npm run package:smoke` builds a package tarball, installs it into an unrelated temporary repository, and executes the installed CLI. CI templates under `integrations/` follow the same external-package model.

### Preventing secrets before Git history

```bash
sentrycode hooks install .
sentrycode secrets staged .
sentrycode secrets history .
```

The pre-commit hook scans staged/index content, not merely the working tree. The pre-push hook runs the normal policy gate. Historical scanning is bounded by `secrets.historyMaxCommits`.

### External SAST

Native SAST remains a baseline. Specialist scanners can run outside or through SentryCode and provide SARIF 2.1.0. Configure `sast.external` with either an analyzer command plus arguments or an existing SARIF path. Results are normalized into the same SentryCode finding/evidence authority as native rules.

### Service-scoped dependency assurance

`--service` now scopes dependency/SBOM discovery to the selected monorepo service as well as file-level scanning/policy. npm license metadata missing from lockfiles is enriched from local installed package manifests without source-code egress.

### Vulnerability intelligence lifecycle

```bash
sentrycode intelligence sync .
sentrycode intelligence sync . --service api
sentrycode intelligence bundle . --output vuln-bundle.json --key private.pem
sentrycode intelligence import . --bundle vuln-bundle.json --public-key public.pem
```

Online synchronization queries OSV.dev for the exact dependency versions discovered in the repository and writes SentryCode's local advisory DB. Air-gapped deployments continue to consume digest-verified, optionally signed bundles.

### Tenant-bound Compliance authorization

For multi-tenant QUILONS Compliance deployments, set `compliance.authMode` to `hmac` and provide `SENTRYCODE_PLUGIN_HMAC_SECRET`. Tokens contain tenant/project, issuer, audience and expiry claims. Run-data routes derive authority from those claims and reject query-parameter scope escalation.

```bash
sentrycode compliance token . --tenant tenant-a --project project-a --ttl 900
```

Static bearer mode remains available for local/single-scope compatibility.

### Stronger integrity

Compliance evidence manifests can be signed with `integrity.evidenceSigningPrivateKeyFile` and verified using `integrity.evidenceSigningPublicKeyFile`. The enterprise audit log is now hash-chained; rewriting a prior event invalidates subsequent chain verification:

```bash
sentrycode enterprise audit verify .
```

### GitHub governance

When `gitAssurance.github.enabled` is true, SentryCode queries GitHub branch protection using the configured token environment variable and can enforce protected branches, minimum approving reviews and required status checks. Provider API state is normalized through the existing Git governance boundary.
