# SentryCode v0.1 Release Acceptance

A release candidate is acceptable only when all of the following pass from a clean checkout:

1. `npm ci`
2. `npm run check`
3. `npm test`
4. `npm run build`
5. `npm run package:smoke`

`package:smoke` is the external-consumer boundary: it creates the distributable tarball, installs that tarball into an unrelated temporary repository, and executes the installed `sentrycode` binary. CI templates must install the packaged product; they must not build the SentryCode source repository inside customer pipelines.

For multi-tenant Compliance deployments, HMAC scoped authorization is required. For evidence/audit tamper resistance, configure an evidence signing key pair. For disconnected operation, vulnerability intelligence must be supplied by the governed bundle workflow.
