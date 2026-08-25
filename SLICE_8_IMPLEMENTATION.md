# Slice 8 — Automotive Compliance Pack

Implemented an adapter-driven automotive compliance pack on top of the existing SentryCode scanner/policy/evidence architecture.

## Capabilities

- MISRA C, MISRA C++ and AUTOSAR C++ source-tool profiles.
- Native JSON import format for licensed/approved analyzer findings.
- SARIF 2.1.0 import with `run.properties.automotiveStandard`.
- No embedded or redistributed copyrighted MISRA/AUTOSAR rule text.
- Normalized `automotive.rule.violation` findings.
- Configurable severity normalization from analyzer output.
- Approved engineering deviation records with rule/fingerprint/path scope and expiry.
- `automotive.rule.check` and `automotive.deviation` evidence.
- Non-certifying engineering evidence mappings for ISO/SAE 21434 and UNECE R155.
- UNECE R156 software-update evidence mapping for findings tagged `software-update`.
- Automotive findings/evidence automatically participate in the existing policy, release-gate, Compliance publication and evidence-integrity flows.
- Compliance plugin manifest and Installer capability metadata advertise automotive evidence surfaces.

## Important product boundary

SentryCode does not claim that importing rule findings establishes MISRA/AUTOSAR conformance or UNECE/ISO compliance. The originating analyzer/rule-set license remains external, and SentryCode provides governed enforcement, traceability and evidence around those results.
