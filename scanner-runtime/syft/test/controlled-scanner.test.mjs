import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const mainPath = new URL("../cmd/quilons-syft/main.go", import.meta.url);

test("controlled scanner enables all A11-accepted ecosystem families", async () => {
  const source = await readFile(mainPath, "utf8");

  for (const family of ["javascript", "python", "rust", "cpp", "golang", "java"]) {
    assert.match(source, new RegExp(`pkg/cataloger/${family}`));
  }

  assert.match(source, /javascript\.NewPackageCataloger\(\)/);
  assert.match(source, /javascript\.NewLockCataloger\(javascriptConfig\)/);
  assert.match(source, /python\.NewPackageCataloger\(pythonConfig\)/);
  assert.match(source, /rust\.NewCargoLockCataloger\(\)/);
  assert.match(source, /cpp\.NewConanCataloger\(\)/);
  assert.match(source, /golang\.NewGoModuleFileCataloger\(goConfig\)/);
  assert.match(source, /java\.NewPomCataloger\(javaConfig\)/);
  assert.match(source, /java\.NewGradleLockfileCataloger\(\)/);

  assert.match(source, /WithSearchRemoteLicenses\(false\)/);
  assert.match(source, /WithGuessUnpinnedRequirements\(false\)/);
  assert.match(source, /WithVcpkgAllowGitClone\(false\)/);
  assert.match(source, /WithSearchLocalModCacheLicenses\(false\)/);
  assert.match(source, /WithSearchLocalVendorLicenses\(false\)/);
  assert.match(source, /WithUsePackagesLib\(false\)/);
  assert.match(source, /WithUseNetwork\(false\)/);
  assert.match(source, /WithUseMavenLocalRepository\(false\)/);
  assert.match(source, /WithResolveTransitiveDependencies\(false\)/);

  assert.match(source, /coverageIdentity = "javascript-npm,python,rust,c-cpp,go,java,linux-os,alpine-apk,debian-dpkg,redhat-rpm"/);
});

test("controlled scanner remains directory-only with QUILONS-native CycloneDX 1.5", async () => {
  const source = await readFile(mainPath, "utf8");
  assert.match(source, /directorysource\.NewFromPath/);
  assert.doesNotMatch(source, /syft\/format\/cyclonedxjson/);
  assert.match(source, /Encoder:\s+"quilons-native-cyclonedx"/);
  assert.match(source, /cycloneDXVersion = "1\.5"/);
  assert.match(source, /BOMFormat:\s+"CycloneDX"/);
  assert.match(source, /SpecVersion:\s+cycloneDXVersion/);
});

test("native CycloneDX preserves identity, licenses, dependency relations and atomic output", async () => {
  const source = await readFile(mainPath, "utf8");
  assert.match(source, /Name:\s+p\.Name/);
  assert.match(source, /Version:\s+p\.Version/);
  assert.match(source, /PURL:\s+p\.PURL/);
  assert.match(source, /p\.Licenses\.ToSlice\(\)/);
  assert.match(source, /artifact\.DependencyOfRelationship/);
  assert.match(source, /os\.CreateTemp/);
  assert.match(source, /temp\.Sync\(\)/);
  assert.match(source, /os\.Chmod\(tempName,\s*0o644\)/);
  assert.match(source, /os\.Rename/);
});
test("controlled scanner enables governed Linux OS and distro package inventory", async () => {
  const source = await readFile(mainPath, "utf8");

  for (const family of ["alpine", "debian", "redhat"]) {
    assert.match(source, new RegExp(`pkg/cataloger/${family}`));
  }

  assert.match(source, /_\s+"modernc\.org\/sqlite"/);
  assert.match(source, /linux\.IdentifyRelease\(resolver\)/);
  assert.match(source, /alpine\.NewDBCataloger\(\)/);
  assert.match(source, /debian\.NewDBCataloger\(\)/);
  assert.match(source, /redhat\.NewDBCataloger\(\)/);
});

test("native CycloneDX emits detected Linux distro as operating-system component", async () => {
  const source = await readFile(mainPath, "utf8");

  assert.match(source, /distro \*linux\.Release/);
  assert.match(source, /Type:\s+"operating-system"/);
  assert.match(source, /"os:" \+ osName/);
  assert.match(source, /Name:\s+osName/);
  assert.match(source, /Version:\s+osVersion/);
  assert.match(source, /Description:\s+distro\.PrettyName/);
  assert.match(source, /CPE:\s+distro\.CPEName/);
  assert.match(source, /Name:\s+"syft:distro:id"/);
  assert.match(source, /Name:\s+"syft:distro:versionID"/);
});

test("controlled Syft production patch keeps Debian DB inventory and excludes deb archive surface", async () => {
  const patchPath = new URL("../tools/a12-patch-syft.sh", import.meta.url);
  const patch = await readFile(patchPath, "utf8");

  assert.match(patch, /QUILONS A63: Debian installed-package DB-only reduction/);
  assert.match(patch, /NewDBCataloger/);
  assert.match(patch, /NewArchiveCataloger/);
  assert.match(patch, /parse_deb_archive\.go/);
  assert.match(patch, /errClippedFileListing/);
  assert.match(patch, /syft\/internal\/file/);
  assert.match(patch, /github\.com\/mholt\/archives/);
  assert.match(patch, /source drift/);
});

test("controlled scanner provisions Syft managed tempdir context for RPM DB cataloging", async () => {
  const source = await readFile(mainPath, "utf8");
  assert.match(source, /syft\/cataloging/);
  assert.match(source, /cataloging\.WithQuilonsTempDir\(ctx,\s*"quilons-syft"\)/);
  assert.match(source, /cleanupTempDir\(\)/);
  assert.match(source, /scannerVersion\s*=\s*"1\.54\.0-quilons\.6"/);
});
