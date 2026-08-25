# SentryCode Slice 9 — Product Completion & Trust

Baseline: `d3e01ef` (Slice 8).

## Implemented

- Packable/installable standalone npm CLI; external-repository package smoke test.
- CI templates consume installed SentryCode instead of building the SentryCode source tree.
- Pre-commit staged secret scanning, pre-push policy gate, bounded Git-history secret scanning.
- Reusable in-memory secret detector with redaction retained as an invariant.
- Service-scoped dependency/SBOM discovery and local npm license metadata enrichment.
- External SARIF 2.1.0 SAST adapter; normalized findings/evidence, no second authority.
- OSV.dev exact-version synchronization into the local SentryCode vulnerability DB.
- Offline vulnerability bundle generation with digest and optional signature.
- HMAC tenant/project-bound Compliance capability tokens with issuer/audience/expiry checks.
- Compliance API scope derives from signed claims and rejects tenant/project escalation.
- Signed Compliance evidence integrity manifests using configured asymmetric keys.
- Hash-chained enterprise audit events with optional asymmetric signatures plus explicit chain/signature verification.
- GitHub branch-protection provider enforcing protected branch, minimum reviews and required status checks.
- New product-completion regression coverage plus package-install E2E smoke.

## Security boundaries retained

- Scanner findings remain normalized before policy enforcement.
- Source code is not sent to OSV; only package name/ecosystem/version queries are sent when online sync is explicitly invoked.
- Static Compliance bearer mode is retained for local compatibility; HMAC mode is the multi-tenant mode.
- GitHub governance requires an explicit provider token and does not give GitHub direct access to SentryCode evidence.
- Secret values remain redacted in findings and reports.
- Missing required scanners and offline intelligence continue to fail closed under existing policy semantics.

## Validation performed in staging

- Strict TypeScript test compilation: PASS.
- Full regression suite: 64/64 PASS.
- External package install + installed CLI execution: PASS.
