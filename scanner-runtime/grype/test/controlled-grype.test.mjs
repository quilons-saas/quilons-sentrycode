import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const main = new URL("../cmd/quilons-grype/main.go", import.meta.url);
const patch = new URL("../tools/patch-grype.mjs", import.meta.url);

test("controlled Grype is local-v6-only and fails closed", async () => {
  const source = await readFile(main, "utf8");
  assert.match(source, /v6\.NewReader\(v6\.Config\{DBDirPath:/);
  assert.match(source, /required Grype v6 database missing/);
  assert.match(source, /unsupported package ecosystem .* required coverage fails closed/);
  assert.match(source, /unsupported Grype version format/);
  assert.doesNotMatch(source, /http\.Get|https:\/\//);
});

test("controlled Grype preserves Grype-compatible finding shape", async () => {
  const source = await readFile(main, "utf8");
  for (const field of [
    '`json:"matches"`',
    '`json:"vulnerability"`',
    '`json:"artifact"`',
    '`json:"matchDetails,omitempty"`',
    '`json:"relatedVulnerabilities,omitempty"`',
    '`json:"fix"`',
    '`json:"purl"`',
  ]) {
    assert.match(source, new RegExp(field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(source, /Descriptor:\s+descriptor\{Name:\s+"grype",\s+Version:\s+upstreamVersion\}/);
});

test("controlled Grype patch removes only proven L-01 source branches", async () => {
  const source = await readFile(patch, "utf8");
  assert.match(source, /grype\/db\/v6\/vulnerability_provider\.go/);
  assert.match(source, /github\.com\/anchore\/go-version/);
  assert.match(source, /github\.com\/Masterminds\/semver\/v3/);
  assert.match(source, /StrictNewVersion/);
  assert.match(source, /semverConstraint = value/);
});
test("controlled Grype semver replacement preserves Bitnami numeric fallback", async () => {
  const source = await readFile(patch, "utf8");
  assert.match(source, /verObj\.Major\(\), verObj\.Minor\(\), verObj\.Patch\(\)/);
  assert.match(source, /verObj\.Segments\(\)/);
  assert.match(source, /bitnami_version\.go/);
});
test("controlled Grype Bitnami patch records obsolete strings import removal", async () => {
  const source = await readFile(patch, "utf8");
  assert.match(source, /bitnami_version\.go/);
  assert.match(source, /"strings"/);
  assert.match(source, /verObj\.Major\(\), verObj\.Minor\(\), verObj\.Patch\(\)/);
});
test("controlled Grype reduced Reader preserves required internal hydration contracts", async () => {
  const build = await readFile(new URL("../build-controlled-grype.ps1", import.meta.url), "utf8");
  assert.match(build, /ProviderStoreReader/);
  assert.match(build, /OperatingSystemStoreReader/);
  assert.match(build, /attachBlobValue\(\.\.\.blobable\) error/);
  assert.match(build, /func \(s \*store\) GetDB\(\) \*gorm\.DB/);
  assert.match(build, /providerStore: newProviderStore\(db\)/);
  assert.match(build, /operatingSystemStore: osStore/);
  assert.doesNotMatch(build, /func NewWriter\(cfg Config\)/);
});
test("accepts standard CycloneDX 1.5 top-level metadata", async () => {
  const source = await readFile(new URL("../cmd/quilons-grype/main.go", import.meta.url), "utf8");

  assert.doesNotMatch(source, /DisallowUnknownFields\(\)/);
  assert.match(source, /if doc\.BOMFormat != "CycloneDX"/);
  assert.match(source, /if doc\.SpecVersion != "1\.5"/);
});

test("ignores CycloneDX file components without package identity while package validation remains strict", async () => {
  const source = await readFile(new URL("../cmd/quilons-grype/main.go", import.meta.url), "utf8");

  assert.match(source, /strings\.EqualFold\(strings\.TrimSpace\(component\.Type\), "file"\)/);
  assert.match(source, /strings\.TrimSpace\(component\.PURL\) == ""/);

  assert.match(source, /component name is required/);
  assert.match(source, /component version is required/);
  assert.match(source, /component purl is required/);
});

test("serializes zero findings as an empty matches array", async () => {
  const source = await readFile(new URL("../cmd/quilons-grype/main.go", import.meta.url), "utf8");

  assert.match(source, /matches := make\(\[\]grypeMatch, 0\)/);
  assert.match(source, /Matches:\s+matches/);
});

test("filters rejected or withdrawn vulnerabilities by v6 handle metadata", async () => {
  const source = await readFile(new URL("../cmd/quilons-grype/main.go", import.meta.url), "utf8");

  assert.match(source, /strings\.EqualFold\(strings\.TrimSpace\(string\(vuln\.Status\)\), "rejected"\)/);
  assert.match(source, /vuln\.WithdrawnDate != nil/);
  assert.doesNotMatch(source, /Withdrawn:/);
});

test("controlled Grype atomic output is runner-readable before rename", async () => {
  const source = await readFile(main, "utf8");
  const closeAt = source.indexOf("if err := tmp.Close(); err != nil");
  const chmodAt = source.indexOf("if err := os.Chmod(tmpName, 0o644); err != nil");
  const renameAt = source.indexOf("if err := os.Rename(tmpName, path); err != nil");

  assert.ok(closeAt >= 0, "expected temp close guard");
  assert.ok(chmodAt > closeAt, "chmod must occur after close");
  assert.ok(renameAt > chmodAt, "rename must occur after chmod");
  assert.match(source, /return fmt\.Errorf\("set output permissions: %w", err\)/);
});
