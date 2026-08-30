# Gerrit CI reference

Run SentryCode in the checked-out Gerrit patchset workspace. Gerrit-triggered Jenkins normally supplies the required `GERRIT_*` variables automatically.

```sh
export SENTRYCODE_GERRIT_TOKEN="$GERRIT_SENTRYCODE_TOKEN"
npx @quilons/sentrycode check . --ci --format console
```

For release gating use:

```sh
npx @quilons/sentrycode release check . --ci --format json --output .sentrycode/reports/release.json
```

Configure the Gerrit endpoint, required labels, review publication, and vote behavior in `.sentrycode/config.json`. See `docs/integrations/GERRIT.md`.
