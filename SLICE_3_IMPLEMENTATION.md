# SentryCode Slice 3 Implementation

## Scope

Slice 3 adds the policy-as-code and release-gating layer on top of the Slice 1/2 scanner foundation.

## Implemented

### Hierarchical policy
- Versioned JSON policy documents.
- Levels: organization, tenant, project, repository, service.
- Scope matching for tenant/project/repository/service.
- Effective date windows.
- Deterministic precedence.
- Parent field locks for:
  - failOn
  - warnOn
  - requiredScanners
  - scannerFailureModes
- Effective-policy SHA-256 fingerprint.

### Scanner execution policy
- Scanner results now explicitly distinguish success, failure and skipped.
- Scanner exceptions are normalized into scanner results instead of becoming an undifferentiated process crash.
- Required skipped scanners are treated as not run.
- Per-scanner failure modes:
  - fail
  - warn
  - ignore

### Governed waivers
- Fingerprint/rule/path/scanner scope.
- Repository/service scope.
- Ticket/reference.
- Author and approver.
- createdAt / approvedAt / expiresAt.
- Approval requirement.
- Ticket requirement.
- Maximum waiver duration.
- Applied and rejected waiver audit records.

### Policy-as-code / OPA
- Optional OPA binary integration.
- Configurable query and Rego policy files.
- Repository/scanner/effective-policy input.
- Supports OPA results as PASS/WARN/FAIL, boolean or `{decision}`.
- Built-in and OPA decisions are combined by retaining the stricter result.

### Evidence and release gating
- `policy.eval` evidence on every scan.
- Release decision model.
- `release.gate` evidence.
- Policy fingerprint carried into release decisions/evidence.
- Release audit record.

### CLI
- `sentrycode policy validate`
- `sentrycode policy evaluate`
- `sentrycode release check`
- `--service NAME` for service-scoped evaluation.

## Validation performed in implementation environment

- Strict TypeScript source check: PASS.
- Focused/regression tests: 26/26 PASS.
- Hierarchical policy resolution smoke: PASS.
- Release gate smoke: PASS.
- `policy.eval` evidence presence: PASS.
- `release.gate` evidence presence: PASS.
- Existing Slice 1/2 tests remain green.

The package should still be validated on the target Windows development environment using:

```powershell
npm run check
npm test
npm run build
```
