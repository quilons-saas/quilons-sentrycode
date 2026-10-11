import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const read = (rel) => fs.readFileSync(path.join(root, rel), "utf8");

test("A18 executes inside the existing Probe before controlled go build", () => {
  const build = read("build-controlled-grype.ps1");
  const marker = "# A18 FIX6: exact post-A17 residual-root reduction.";
  const goBuild = 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /work/quilons-grype .';

  const markerIndex = build.indexOf(marker);
  const buildIndex = build.indexOf(goBuild);

  assert.ok(markerIndex >= 0, "A18 Probe marker missing");
  assert.ok(buildIndex >= 0, "controlled go build marker missing");
  assert.ok(markerIndex < buildIndex, "A18 must execute before controlled go build");
  assert.equal((build.match(/A18 FIX6: exact post-A17 residual-root reduction/g) ?? []).length, 1);
});

test("A18 targets exactly the two A17-proven roots", () => {
  const build = read("build-controlled-grype.ps1");

  assert.ok(build.includes("github.com/anchore/grype/grype/pkg"));
  assert.ok(build.includes("github.com/masahiro331/go-mvn-version"));
  assert.ok(build.includes("controlled_maven_compare.go"));
  assert.ok(build.includes("pythonNormalizePattern"));
});

test("A18 does not use Node inside the builder", () => {
  const build = read("build-controlled-grype.ps1");
  const start = build.indexOf("# A18 FIX6: exact post-A17 residual-root reduction.");
  const end = build.indexOf(
    'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /work/quilons-grype .'
  );
  const block = build.slice(start, end);

  assert.doesNotMatch(block, /\bnode\b/i);
  assert.match(block, /\bgofmt\b/);
});

test("A18 production-source guards exclude Go test files", () => {
  const build = read("build-controlled-grype.ps1");
  const start = build.indexOf("# A18 FIX6: exact post-A17 residual-root reduction.");
  const end = build.indexOf(
    'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /work/quilons-grype .'
  );
  const block = build.slice(start, end);
  const exclusions = block.match(/--exclude='\*_test\.go'/g) ?? [];
  assert.equal(exclusions.length, 2);
});
test("A18 import-only guards preserve attribution comments", () => {
  const build = read("build-controlled-grype.ps1");
  const start = build.indexOf("# A18 FIX6: exact post-A17 residual-root reduction.");
  const end = build.indexOf(
    'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /work/quilons-grype .'
  );
  const block = build.slice(start, end);

  const guards =
    block.match(/grep -R -n -E --include='\*\.go' --exclude='\*_test\.go'/g) ?? [];

  assert.equal(guards.length, 2);
  assert.ok(block.includes("// Derived from github.com/masahiro331/go-mvn-version"));
  assert.ok(block.includes('"github\\.com/masahiro331/go-mvn-version"'));
  assert.ok(block.includes('"github\\.com/hashicorp/go-multierror"'));
  assert.ok(block.includes('"github\\.com/hashicorp/errwrap"'));
});
test("A18 name import guard keeps literal shell directory variable", () => {
  const build = read("build-controlled-grype.ps1");

  assert.equal(
    (build.match(/"\$A18_NAME_DIR" >\/tmp\/a18-name-blocked\.txt/g) ?? []).length,
    1
  );

  assert.equal(
    (build.match(/"" >\/tmp\/a18-name-blocked\.txt/g) ?? []).length,
    0
  );
});
test("controlled Grype build script and literal Probe remain LF-only", async () => {
  const fs = await import("node:fs");
  const path = await import("node:path");
  const buildPath = path.join(process.cwd(), "scanner-runtime", "grype", "build-controlled-grype.ps1");
  const raw = fs.readFileSync(buildPath);

  assert.equal(raw.includes(Buffer.from("\r")), false, "build script must not contain CR bytes");

  const build = raw.toString("utf8");
  const assignmentStart = build.indexOf("$Probe");
  const hereStart = build.indexOf("@'", assignmentStart);
  const hereEnd = build.indexOf("'@", hereStart + 2);

  assert.ok(assignmentStart >= 0 && hereStart >= 0 && hereEnd > hereStart);
  const probe = build.slice(hereStart + 2, hereEnd);
  assert.equal(probe.includes("\r"), false, "literal Probe must not contain CR characters");
  assert.ok(probe.includes("set -eu"));
});
test("controlled Grype preserves failed work and cleans only successful work", () => {
  const build = read("build-controlled-grype.ps1");

  assert.ok(build.includes("$BuildSucceeded = $false"));
  assert.ok(build.includes("$BuildSucceeded = $true"));
  assert.ok(build.includes("if ($BuildSucceeded) {"));
  assert.ok(build.includes("PRESERVED FAILED WORK DIRECTORY"));
  assert.ok(build.includes("Controlled Grype binary failed unchanged nine-module gate."));
});
test("controlled Grype emits compiled import edges before unchanged policy gate", () => {
  const build = read("build-controlled-grype.ps1");

  const deps = build.indexOf("go list -deps . | sort > /work/go-list-deps.txt");
  const edges = build.indexOf(
    "go list -deps -f '{{.ImportPath}}|{{join .Imports \",\"}}' . | sort > /work/go-dep-edges.txt"
  );
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(deps >= 0);
  assert.ok(edges > deps);
  assert.ok(policy > edges);
  assert.ok(build.includes("Controlled Grype binary failed unchanged nine-module gate."));
});
test("controlled Grype emits compiler-selected source evidence for both residual roots", () => {
  const build = read("build-controlled-grype.ps1");

  assert.ok(build.includes("/work/a21-name-package.json"));
  assert.ok(build.includes("/work/a21-version-package.json"));
  assert.ok(build.includes("/work/a21-name-selected.txt"));
  assert.ok(build.includes("/work/a21-version-selected.txt"));
  assert.ok(build.includes("/work/a21-name-relevant-imports.txt"));
  assert.ok(build.includes("/work/a21-version-relevant-imports.txt"));

  const edges = build.indexOf("/work/go-dep-edges.txt");
  const selected = build.indexOf("/work/a21-name-package.json");
  const policyExecution = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(edges >= 0);
  assert.ok(selected > edges);
  assert.ok(policyExecution > selected);
});
test("A18 mutates the exact Grype tree selected by the wrapper replace directive", () => {
  const build = read("build-controlled-grype.ps1");

  assert.ok(build.includes('replace github.com/anchore/grype => /tmp/grype'));
  assert.ok(build.includes('A18_GRYPE_ROOT="/tmp/grype"'));
  assert.ok(build.includes('A18_NAME_DIR="$A18_GRYPE_ROOT/grype/db/v6/name"'));
  assert.ok(build.includes('A18_VERSION_DIR="$A18_GRYPE_ROOT/grype/version"'));

  assert.ok(!build.includes("A18_GRYPE_ROOTS="));
  assert.ok(!build.includes("A18_GRYPE_ROOT_COUNT="));
  assert.ok(!build.includes("*/github.com/anchore/grype@v0.120.0/grype/db/v6/name/resolver.go"));
});
test("controlled Grype emits selected-source evidence for the post-A22 residual root", () => {
  const build = read("build-controlled-grype.ps1");

  for (const marker of [
    "/work/a23-db-v6-package.json",
    "/work/a23-vulnerability-package.json",
    "/work/a23-db-v6-selected.txt",
    "/work/a23-vulnerability-selected.txt",
    "/work/a23-db-v6-relevant-imports.txt",
    "/work/a23-vulnerability-relevant-imports.txt",
  ]) {
    assert.ok(build.includes(marker), marker);
  }

  const edges = build.indexOf("/work/go-dep-edges.txt");
  const a23 = build.indexOf("/work/a23-db-v6-package.json");
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(edges >= 0);
  assert.ok(a23 > edges);
  assert.ok(policy > a23);
});
test("controlled Grype preserves exact source contracts for the final residual vulnerability edge", () => {
  const build = read("build-controlled-grype.ps1");

  for (const marker of [
    "/work/a24-vulnerability-provider.go",
    "/work/a24-vulnerability-vulnerability.go",
    "/work/a24-vulnerability-metadata.go",
    "/work/a24-vulnerability-advisory.go",
    "/work/a24-vulnerability-fix.go",
    "/work/a24-vulnerability-severity.go",
    "/work/a24-db-v6-vulnerability-importers.txt",
    "/work/a24-vulnerability-pkg-usages.txt",
  ]) {
    assert.ok(build.includes(marker), marker);
  }

  const edges = build.indexOf("/work/go-dep-edges.txt");
  const a24 = build.indexOf("/work/a24-vulnerability-provider.go");
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(edges >= 0);
  assert.ok(a24 > edges);
  assert.ok(policy > a24);
});
test("A25 removes only the broad grype/pkg method from vulnerability.Provider", () => {
  const build = read("build-controlled-grype.ps1");

  assert.ok(build.includes('A25_PROVIDER="/tmp/grype/grype/vulnerability/provider.go"'));
  assert.ok(build.includes('grypePkg "github.com/anchore/grype/grype/pkg"'));
  assert.ok(build.includes('PackageSearchNames(grypePkg.Package) []string'));
  assert.ok(build.includes("a25-vulnerability-provider"));
  assert.ok(build.includes("FindVulnerabilities(criteria ...Criteria) ([]Vulnerability, error)"));
  assert.ok(build.includes("MetadataProvider"));
  assert.ok(build.includes("io.Closer"));

  const a25 = build.indexOf('A25_PROVIDER="/tmp/grype/grype/vulnerability/provider.go"');
  const controlledBuild = build.indexOf(
    'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /work/quilons-grype .'
  );
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(a25 >= 0);
  assert.ok(controlledBuild > a25);
  assert.ok(policy > controlledBuild);
});
test("controlled Grype emits qualifier source evidence for the post-A25 residual edge", () => {
  const build = read("build-controlled-grype.ps1");

  for (const marker of [
    "/work/a26-qualifier-package.json",
    "/work/a26-qualifier-selected.txt",
    "/work/a26-qualifier-all-go-files.txt",
    "/work/a26-qualifier-pkg-usages.txt",
    "/work/a26-qualifier-production-source.txt",
  ]) {
    assert.ok(build.includes(marker), marker);
  }

  const a25 = build.indexOf('A25_PROVIDER="/tmp/grype/grype/vulnerability/provider.go"');
  const a26 = build.indexOf("/work/a26-qualifier-package.json");
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(a25 >= 0);
  assert.ok(a26 > a25);
  assert.ok(policy > a26);
});
test("controlled Grype emits qualifier call-site evidence before reducing Qualifier", () => {
  const build = read("build-controlled-grype.ps1");

  for (const marker of [
    "/work/a27-qualifier-usage-all.txt",
    "/work/a27-qualifier-usage-compiled-packages.txt",
    "/work/a27-qualifier-implementations.txt",
    "/work/a27-db-vulnerability-qualifier-usages.txt",
  ]) {
    assert.ok(build.includes(marker), marker);
  }

  const a26 = build.indexOf("/work/a26-qualifier-package.json");
  const a27 = build.indexOf("/work/a27-qualifier-usage-all.txt");
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(a26 >= 0);
  assert.ok(a27 < a26);
  assert.ok(policy > a27);
});
test("A28 reduces qualifier to a data-only contract in the controlled build", () => {
  const build = read("build-controlled-grype.ps1");

  assert.ok(build.includes('A28_QUALIFIER="/tmp/grype/grype/pkg/qualifier/qualifier.go"'));
  assert.ok(build.includes("type Qualifier interface{}"));
  assert.ok(build.includes("a28-qualifier-interface"));
  assert.ok(build.includes("Satisfied(p pkg.Package) (bool, error)"));

  const a28 = build.indexOf('A28_QUALIFIER="/tmp/grype/grype/pkg/qualifier/qualifier.go"');
  const controlledBuild = build.indexOf(
    'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /work/quilons-grype .'
  );
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(a28 >= 0);
  assert.ok(controlledBuild > a28);
  assert.ok(policy > controlledBuild);
});
test("controlled Grype emits exact db/v6 search symbol usage before reducing search", () => {
  const build = read("build-controlled-grype.ps1");

  for (const marker of [
    "/work/a30-dbv6-search-usages.txt",
    "/work/a30-dbv6-legacy-search-symbols.txt",
    "/work/a30-dbv6-narrow-search-symbols.txt",
    "/work/a30-dbv6-search-caller-source.txt",
    "/work/a30-legacy-search-candidates.txt",
  ]) {
    assert.ok(build.includes(marker), marker);
  }

  const a30 = build.indexOf("/work/a30-dbv6-search-usages.txt");
  const a29 = build.indexOf("# A29: exact source evidence for the post-A28 residual chain:");
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(a30 >= 0);
  assert.ok(a29 > a30);
  assert.ok(policy > a29);
});
test("controlled Grype emits v5 namespace resolver contract evidence before reduction", () => {
  const build = read("build-controlled-grype.ps1");

  for (const marker of [
    "/work/a31-${A31_SAFE}-selected.txt",
    "/work/a31-${A31_SAFE}-contract-usages.txt",
    "/work/a31-${A31_SAFE}-production-source.txt",
    "/work/a31-resolver-call-sites.txt",
    "github.com/anchore/grype/grype/db/v5/namespace/cpe",
    "github.com/anchore/grype/grype/db/v5/namespace/distro",
    "github.com/anchore/grype/grype/db/v5/namespace/language",
  ]) {
    assert.ok(build.includes(marker), marker);
  }

  const a31 = build.indexOf("/work/a31-resolver-call-sites.txt");
  const a30 = build.indexOf("# A30: prove exact db/v6 usage of grype/search before any search-package reduction.");
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(a31 >= 0);
  assert.ok(a30 > a31);
  assert.ok(policy > a30);
});
test("A32 removes only the A31-proven unused v5 namespace resolver contract", () => {
  const build = read("build-controlled-grype.ps1");

  for (const marker of [
    'A32_NS_ROOT="/tmp/grype/grype/db/v5/namespace"',
    'A32_CPE="$A32_NS_ROOT/cpe/namespace.go"',
    'A32_DISTRO="$A32_NS_ROOT/distro/namespace.go"',
    'A32_LANGUAGE="$A32_NS_ROOT/language/namespace.go"',
    '{"status":"pass","reduction":"a32-v5-namespace-resolver"',
    "unused Resolver() contract/state",
  ]) {
    assert.ok(build.includes(marker), marker);
  }

  for (const preserved of [
    'func (n *Namespace) DistroType() distro.Type {',
    'func (n *Namespace) Version() string {',
    'func (n *Namespace) Language() syftPkg.Language {',
    'func (n *Namespace) PackageType() syftPkg.Type {',
  ]) {
    assert.ok(build.includes(preserved), preserved);
  }

  const a32 = build.indexOf("# A32: remove A31-proven unused v5 Namespace Resolver() contract/state.");
  const a33 = build.indexOf("# A33: final dependency graph after all controlled-source reductions, immediately before compile.");
  const compileCandidates = [...build.matchAll(/^.*\bgo\s+build\b.*\/work\/quilons-grype.*$/gm)];
  assert.equal(compileCandidates.length, 1);
  const compile = compileCandidates[0].index;
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(a32 >= 0);
  assert.ok(a33 > a32);
  assert.ok(compile > a33);
  assert.ok(policy > compile);
});
test("A33 emits the final reduced dependency graph immediately before controlled compile", () => {
  const build = read("build-controlled-grype.ps1");

  for (const marker of [
    "/work/a33-final-prebuild-dep-edges.txt",
    "/work/a33-final-prebuild-deps.txt",
    "/work/a33-final-prebuild-key-edges.txt",
    '{"status":"pass","diagnostic":"a33-final-prebuild-graph"',
  ]) {
    assert.ok(build.includes(marker), marker);
  }

  const a32 = build.indexOf("# A32: remove A31-proven unused v5 Namespace Resolver() contract/state.");
  const a33 = build.indexOf("/work/a33-final-prebuild-dep-edges.txt");
  const compileCandidates = [...build.matchAll(/^.*\bgo\s+build\b.*\/work\/quilons-grype.*$/gm)];
  assert.equal(compileCandidates.length, 1);

  const compile = compileCandidates[0].index;
  const policy = build.indexOf(
    "-ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt'))"
  );

  assert.ok(a32 >= 0);
  assert.ok(a33 > a32);
  assert.ok(compile > a33);
  assert.ok(policy > compile);
});
test("L-01 verifier still enumerates all nine prohibited modules", () => {
  const verifier = read("tools/verify-policy-modules.mjs");
  const expected = [
    "github.com/anchore/go-version",
    "github.com/hashicorp/aws-sdk-go-base/v2",
    "github.com/hashicorp/errwrap",
    "github.com/hashicorp/go-cleanhttp",
    "github.com/hashicorp/go-getter",
    "github.com/hashicorp/go-multierror",
    "github.com/hashicorp/go-version",
    "github.com/hashicorp/golang-lru/v2",
    "github.com/hashicorp/hcl/v2",
  ];

  for (const moduleName of expected) {
    assert.ok(verifier.includes(moduleName), `missing blocked module ${moduleName}`);
  }
});
test("A32 relocation does not leave a stray standalone quote before A31", () => {
  const build = read("build-controlled-grype.ps1");

  const a31 = build.indexOf(
    "# A31: exact source evidence for v5 namespace subpackages retained by the v6 search-query adapter."
  );
  assert.ok(a31 >= 0);

  const prefix = build.slice(Math.max(0, a31 - 120), a31);
  assert.ok(!prefix.endsWith("\n'\n"));
});
