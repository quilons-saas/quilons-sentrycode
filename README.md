# QUILONS SentryCode

**Catch compliance issues at code level — before merge, before release, before audit.**

SentryCode is a standalone developer/CI compliance engine and a future plugin for QUILONS Compliance. Slice 1 establishes a working end-to-end foundation with repository discovery, configuration, scanner plugins, normalized findings/evidence, policy evaluation, waivers, reports, stable exit codes, and a real secrets scanner.

## Requirements

- Node.js 20+
- Git

## Development

```bash
npm install
npm run check
npm test
npm run build
```

## Run

```bash
npm start -- scan .
npm start -- scan . --format json
npm start -- check . --format json --output .sentrycode/out/report.json
```

After `npm run build`, the compiled CLI is available at `dist/cli/main.js`.

## Configuration

Optional repository configuration lives at `.sentrycode/config.json`. If it is absent, safe built-in defaults are used. See `.sentrycode/examples/config.json`.

Waivers are read from `.sentrycode/waivers.json` by default. Waivers are explicit, scoped, and expiry-bound. Expired waivers do not apply.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | PASS or WARN |
| 1 | Policy failure |
| 2 | Runtime/scanner failure |
| 3 | Configuration/usage failure |

## Slice 1 architecture

```text
CLI
  -> repository context
  -> configuration
  -> scanner plugins
       -> secrets scanner
  -> normalized findings + evidence
  -> waiver application
  -> policy decision
  -> console / JSON report
  -> deterministic exit code
```

Secrets are redacted in output. The scanner never intentionally prints full matched secret values.

## Slice 2 dependency assurance

SentryCode now includes dependency, SBOM, license, and offline vulnerability assurance for Node/npm and pinned Python dependencies.

```bash
# Full policy scan (secrets + dependencies/licenses/vulnerabilities)
sentrycode scan .

# Generate standards-based SBOM artifacts
sentrycode sbom . --format cyclonedx --output artifacts/sbom.cdx.json
sentrycode sbom . --format spdx --output artifacts/sbom.spdx.json

# PR/release dependency change analysis between Git refs
sentrycode dependencies diff . --base origin/main --head HEAD
```

Dependency policy is configured under `dependencies`, `licenses`, and `vulnerabilities` in `.sentrycode/config.json`. Vulnerability matching uses a local versioned JSON advisory database (`.sentrycode/vulnerability-db.json` by default), so mandatory scanning does not require a paid service or network connection.

Supported discovery in this slice:

- npm `package-lock.json` (lockfile v2/v3 `packages` plus legacy fallback)
- pinned Python `requirements.txt` entries (`name==version`)
- pinned PEP 621 `pyproject.toml` dependency entries (`name==version`)

Unpinned Python constraints are intentionally not converted into invented installed versions; they are omitted from the component snapshot until a resolved lock/environment source is available.
