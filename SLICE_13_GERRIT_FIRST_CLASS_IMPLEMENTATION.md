# Slice 13 — First-class Gerrit integration

This slice closes the prior Gerrit gap. Gerrit is no longer an integration-registry label only.

Implemented:
- native Gerrit CI/change/patchset environment detection;
- Gerrit REST provider with bearer and basic authentication;
- DETAILED_LABELS/current-revision inspection;
- configurable required Gerrit label thresholds;
- fail-closed assurance behavior;
- SentryCode review summary publication;
- source-line Gerrit comments for normalized findings;
- configurable PASS/WARN/FAIL label votes;
- governed `gerrit.review.published` audit event;
- environment/Docker secret wiring;
- standalone UI configuration metadata for Gerrit operational settings;
- CI and configuration documentation;
- deterministic provider/config/context/assurance tests.

Credential values remain outside PostgreSQL and repository config. Config stores only environment-variable names/secret references.
