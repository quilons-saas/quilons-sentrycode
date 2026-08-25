# SentryCode Offline / On-Prem Operations

SentryCode can run without a live QUILONS cloud dependency. In offline mode, vulnerability intelligence is supplied through controlled local bundles and the dependency scanner fails closed if its configured database is unavailable.

## Intelligence updates

Import a prepared bundle with `sentrycode intelligence import --bundle FILE`. Bundles carry a database digest; deployments may additionally require a trusted public-key signature.

## Configuration integrity

Repositories may require a detached signature for `.sentrycode/config.json`. Use `sentrycode config sign --key PRIVATE.pem` and `sentrycode config verify --public-key PUBLIC.pem`. When `integrity.requireSignedConfig` is enabled, normal SentryCode execution verifies the configuration before scanning.

## Evidence integrity

Published Compliance runs include an `integrity.json` hash manifest. Reads verify the manifest and reject tampered run content.

## Backup, restore and retention

`enterprise backup` snapshots SentryCode operational state, `enterprise restore --backup PATH` restores it, and `enterprise retention` removes state older than the configured retention period.

## Diagnostics

`enterprise diagnostics` checks configuration, vulnerability database availability/schema, required signature material, repository writeability, and package metadata without transmitting source code.
