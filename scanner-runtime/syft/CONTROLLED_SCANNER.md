# Controlled Syft A3 policy-clean runtime

A3 FIX7 deliberately narrows the production controlled Syft runtime to JavaScript/npm cataloging.

Reason: the broader A3 build proved that five prohibited HashiCorp-family modules remained in the compiled binary:
aws-sdk-go-base/v2, go-cleanhttp, go-getter, go-version, and golang-lru/v2.

This is not a waiver. The permissive-only gate remains unchanged. Broader ecosystem catalogers must be added only
after each exact cataloger path is shown to compile without prohibited modules.

Current production-controlled coverage:
- package.json
- npm lockfiles
- directory-only input
- network-disabled runtime
- CycloneDX 1.5 output

This A3 unit is not Slice 2C closure. Python, Go, Java, Rust, C/C++ controlled Syft coverage remains to be added
or satisfied through another policy-clean architecture before Slice 2C can close.
