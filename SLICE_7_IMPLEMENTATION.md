# Slice 7 — Offline / On-Prem Enterprise Hardening

Implemented:

- explicit offline execution profile and `SENTRYCODE_OFFLINE=true`
- fail-closed offline vulnerability intelligence requirement
- digest-verified vulnerability intelligence bundle import
- optional public-key verification for intelligence bundles
- detached configuration signing and verification
- enforced signed configuration mode
- append-only JSONL enterprise audit trail
- per-run Compliance evidence integrity manifests and tamper rejection
- operational backup and restore
- configurable backup/evidence retention
- on-prem/offline diagnostics command
- example enterprise configuration and offline operations documentation

New CLI surfaces:

- `sentrycode intelligence import`
- `sentrycode config sign`
- `sentrycode config verify`
- `sentrycode enterprise diagnostics`
- `sentrycode enterprise backup`
- `sentrycode enterprise restore`
- `sentrycode enterprise retention`
