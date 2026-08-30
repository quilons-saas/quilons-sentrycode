# Gerrit integration

SentryCode supports Gerrit as a first-class CI/review provider. It detects Gerrit change/patchset context, reads review labels through Gerrit's REST API, enforces required label thresholds, publishes a review summary and inline findings, and can cast a configured release-gate vote.

## Repository configuration

```json
{
  "schemaVersion": 1,
  "ci": { "provider": "gerrit", "annotations": true },
  "gitAssurance": {
    "gerrit": {
      "enabled": true,
      "apiBaseUrl": "https://gerrit.example.com",
      "authMode": "bearer",
      "tokenEnv": "SENTRYCODE_GERRIT_TOKEN",
      "usernameEnv": "SENTRYCODE_GERRIT_USERNAME",
      "passwordEnv": "SENTRYCODE_GERRIT_PASSWORD",
      "requiredLabels": { "Code-Review": 2, "Verified": 1 },
      "publishReview": true,
      "voteLabel": "Verified",
      "passVote": 1,
      "warnVote": 0,
      "failVote": -1,
      "notify": "OWNER_REVIEWERS",
      "failClosed": true,
      "timeoutMs": 15000
    }
  }
}
```

Use `authMode: bearer` with `SENTRYCODE_GERRIT_TOKEN`, or `authMode: basic` with the configured username/password environment variables. Credential values are never stored in SentryCode application state.

`SENTRYCODE_GERRIT_URL` can override `apiBaseUrl`. The `*_TOKEN_ENV`, `*_USERNAME_ENV`, and `*_PASSWORD_ENV` overrides can change the names of the secret-bearing environment variables.

## Gerrit/Jenkins environment

Automatic Gerrit detection recognizes `GERRIT_CHANGE_NUMBER`, `GERRIT_PATCHSET_NUMBER`, `GERRIT_PATCHSET_REVISION`, `GERRIT_REFSPEC`, `GERRIT_BRANCH`, and `GERRIT_PROJECT`. These are the conventional variables exposed by Gerrit-triggered Jenkins jobs and similar integrations.

A Gerrit run is fail-closed when configured assurance is enabled but change context, credentials, the API, or required labels are unavailable. Set `failClosed: false` only when Gerrit assurance is explicitly advisory.

## Review publication

When `publishReview` is enabled, SentryCode posts:

- the overall PASS/WARN/FAIL decision;
- an aggregate finding summary;
- inline comments for findings with source locations;
- the configured vote on `voteLabel`.

High/critical inline findings are posted unresolved. Publication is recorded in SentryCode's governed audit chain as `gerrit.review.published`.
