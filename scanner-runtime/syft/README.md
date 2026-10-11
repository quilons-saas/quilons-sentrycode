# QUILONS controlled Syft runtime

This directory is production build infrastructure for the QUILONS-controlled Syft runtime used by SentryCode.

Authoritative upstream:
- Syft v1.54.0
- commit cc326e45a6213360266dda4b30cc68095946d676

The first controlled patch removes the `github.com/hashicorp/go-multierror -> github.com/hashicorp/errwrap`
chain from the reduced Syft library surface by replacing `multierror.Append` in `syft/file/location.go`
with the Go standard-library `errors.Join`.

The patcher is deliberately fail-closed: it refuses to modify a source file unless the expected v1.54.0
source structure is present exactly once.

`build-policy-probe.ps1` checks out the exact upstream commit, applies the patch, compiles the reduced
Syft source package surface in the pinned Go toolchain, and rejects the build if either prohibited module
is present in Go build metadata.

This is source implementation infrastructure. The production scanner command/image and full scanner
functionality acceptance are completed in subsequent Slice 2C implementation steps before commit.