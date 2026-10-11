import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..", "..");
const builderPath = path.join(root, "scanner-runtime", "release", "build-scanner-attribution.ps1");
const source = fs.readFileSync(builderPath, "utf8");

test("A9 exact-text attribution hardening remains fail-closed", () => {
  assert.match(source, /QUILONS_A9_LICENSE_HARDENING/);
  assert.match(source, /CC0-1\.0/);
  assert.match(source, /Public-Domain/);
  assert.match(source, /BSD-3-Clause/);
  assert.match(source, /BSD-2-Clause/);
  assert.match(source, /MPL-2\.0/);
  assert.match(source, /AGPL/);
  assert.match(source, /LGPL/);
  assert.match(source, /GPL/);
});

test("A9 does not add blocker package-name whitelists", () => {
  for (const forbidden of [
    "github.com/jinzhu/copier",
    "github.com/glebarez/sqlite",
    "github.com/opencontainers/go-digest",
    "github.com/therootcompany/xz",
    "modernc.org/memory",
    "modernc.org/sqlite",
    "github.com/cyphar/filepath-securejoin",
  ]) {
    assert.equal(source.includes(`'${forbidden}'`), false, `package whitelist detected for ${forbidden}`);
    assert.equal(source.includes(`"${forbidden}"`), false, `package whitelist detected for ${forbidden}`);
  }
});
test("A9 FileRecords enumerates directly under PowerShell 5.1", () => {
  assert.match(source, /foreach \(\$A9FileRecord in \$FileRecords\) \{/);
  assert.doesNotMatch(source, /foreach \(\$A9FileRecord in @\(\$FileRecords\)\) \{/);
});
test("A12 final status is computed after exact-text augmentation", () => {
  const a9 = source.indexOf("QUILONS_A9_LICENSE_HARDENING: augment classification");
  const recompute = source.indexOf("QUILONS_A12_STATUS_RECOMPUTE");
  const component = source.indexOf("$Results.Add([pscustomobject]");
  assert.ok(a9 >= 0);
  assert.ok(recompute > a9);
  assert.ok(component > recompute);
});

test("A12 file records retain an absolute collected path for exact-text classification", () => {
  assert.match(source, /absolutePath=\$File\.FullName/);
});

test("A12 blocked-module materialization is singular and uncorrupted", () => {
  assert.equal((source.match(/^\$BlockedModulesArray = @\(\)$/gm) ?? []).length, 1);
  assert.doesNotMatch(source, /BlockedModulesArrayArray/);
  assert.match(source, /blockedModules=\$BlockedModulesArray/);
});
test("A13 attribution progress instrumentation does not alter status policy", () => {
  assert.match(source, /QUILONS_A13_ATTRIBUTION_PROGRESS/);
  assert.match(source, /attribution start/);
  assert.match(source, /source acquisition OK/);
  assert.match(source, /source acquisition FAILED/);
  assert.match(source, /QUILONS_A12_STATUS_RECOMPUTE/);
});
test("A15 scanner-stage progress preserves attribution flow", () => {
  assert.match(source, /QUILONS_A15_SCANNER_STAGE_PROGRESS/);
  assert.match(source, /image save START/);
  assert.match(source, /image save END/);
  assert.match(source, /go version -m START/);
  assert.match(source, /go version -m END/);
  assert.match(source, /module attribution START/);
  assert.match(source, /module attribution END/);
  assert.match(source, /AcquireModuleLicenses \$Modules \$Id \$LicensesDir/);
});
test("A16 license acquisition is bounded to module-root attribution scope", () => {
  assert.match(source, /QUILONS_A16_LICENSE_SCOPE/);

  const match = source.match(/\$HelperBytes = \[Convert\]::FromBase64String\("([^"]+)"\)/);
  assert.ok(match, "embedded acquisition helper must exist");

  const helper = Buffer.from(match[1], "base64").toString("utf8");

  assert.doesNotMatch(helper, /find "\$dir" -type f/);
  assert.match(helper, /mindepth 2 -maxdepth 2/);
});

test("A16 preserves fail-closed attribution semantics", () => {
  const match = source.match(/\$HelperBytes = \[Convert\]::FromBase64String\("([^"]+)"\)/);
  assert.ok(match, "embedded acquisition helper must exist");

  const helper = Buffer.from(match[1], "base64").toString("utf8");

  assert.match(helper, /no module attribution files found/);
  assert.match(helper, /exit 32/);
  assert.match(source, /QUILONS_A12_STATUS_RECOMPUTE/);
});
test("A18 runner provenance is materialized before JSON serialization", () => {
  assert.match(source, /QUILONS_A18_RUNNER_PROVENANCE_PS51/);
  assert.match(source, /\$RunnerProvenance = \[pscustomobject\]@\{/);
  assert.doesNotMatch(source, /\$RunnerProvenance = \[ordered\]@\{/);
});

test("A18 runner provenance arrays are explicitly materialized", () => {
  assert.match(source, /\$RunnerFromLines \+= \$DockerfileLineText/);
  assert.match(source, /\$RunnerDockerCliLines \+= \$DockerfileLineText/);
  assert.match(source, /\$RunnerRepoDigests \+= \[string\]\$RunnerRepoDigest/);
});
test("A19 verifier strips UTF-8 BOM before JSON parse", () => {
  const verifierPath = new URL("../verify-scanner-attribution.mjs", import.meta.url);
  const verifierSource = fs.readFileSync(verifierPath, "utf8");
  assert.match(verifierSource, /QUILONS_A19_JSON_BOM/);
  assert.match(verifierSource, /replace\(\/\^\\uFEFF\/,\s*""\)/);
  assert.match(verifierSource, /parseJsonText\(/);
});

test("A19 builder writes JSON as UTF-8 without BOM", () => {
  assert.match(source, /QUILONS_A19_UTF8_NO_BOM/);
  assert.match(source, /New-Object System\.Text\.UTF8Encoding\(\$false\)/);
  assert.match(source, /WriteJsonUtf8NoBom/);
});
test("A20 BOM parser helper is non-recursive", () => {
  const verifierSource = fs.readFileSync(
    new URL("../verify-scanner-attribution.mjs", import.meta.url),
    "utf8"
  );

  assert.match(
    verifierSource,
    /function parseJsonText\(text\)\s*\{\s*return JSON\.parse\(String\(text\)\.replace\(\/\^\\uFEFF\/,\s*""\)\);\s*\}/s
  );

  assert.doesNotMatch(
    verifierSource,
    /function parseJsonText\(text\)\s*\{\s*return parseJsonText\(/s
  );
});