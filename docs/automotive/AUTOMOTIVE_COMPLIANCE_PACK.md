# QUILONS SentryCode Automotive Compliance Pack

The Automotive Compliance Pack imports results from approved automotive static-analysis tools and normalizes them into SentryCode findings, policy decisions, waivers/deviations, and evidence.

## Supported rule families

- MISRA C
- MISRA C++
- AUTOSAR C++

SentryCode intentionally does **not** embed or redistribute copyrighted rule text. Import documents contain rule identifiers, tool metadata, source locations, severities and analyzer messages. Organizations remain responsible for licensing the rule sets and analyzers they use.

## Evidence targets

The pack emits non-certifying engineering evidence mappings for:

- ISO/SAE 21434 cybersecurity engineering
- UNECE R155 cybersecurity / CSMS-related engineering evidence
- UNECE R156 software-update / SUMS-related engineering evidence when imported findings are tagged `software-update`

These mappings are evidence aids, not a claim that a scan alone establishes regulatory or standards compliance.

## Input format

Place JSON or SARIF 2.1.0 files under `.sentrycode/automotive/findings/` (configurable). Native JSON uses `schemaVersion: 1`, a `standard`, `tool` metadata and `findings[]`. SARIF runs must set `run.properties.automotiveStandard` to `misra-c`, `misra-cpp`, or `autosar-cpp`.

## Deviations

Approved deviations are stored separately in `.sentrycode/automotive/deviations.json`. They can be scoped by standard, rule ID, finding fingerprint and path. When `requireDeviationApproval` is enabled, both `approver` and `approvedAt` are required and expired deviations do not apply.

## Policy

Automotive scanning is disabled by default. Enable it in config and, where a project requires fail-closed execution, add `automotive` to `policy.requiredScanners` with an appropriate scanner failure mode.
