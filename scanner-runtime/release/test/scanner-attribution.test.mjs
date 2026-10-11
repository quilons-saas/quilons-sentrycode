import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
const root=path.resolve("scanner-runtime/release");const builder=fs.readFileSync(path.join(root,"build-scanner-attribution.ps1"),"utf8");const verifier=fs.readFileSync(path.join(root,"verify-scanner-attribution.mjs"),"utf8");
test("release attribution builder pins controlled scanner tags and excludes Grype DB distribution",()=>{assert.match(builder,/quilons-controlled-syft:slice2c-a3/);assert.match(builder,/quilons-controlled-grype:slice2c-a15/);assert.match(builder,/operator-provisioned and is NOT included/);assert.doesNotMatch(builder,/copy.*vulnerability\.db/i)});
test("release attribution gate blocks prohibited and unresolved licenses",()=>{assert.match(verifier,/blocked module/);assert.match(verifier,/component\.status!=="permitted"/);assert.match(verifier,/MPL-2\.0/);assert.match(verifier,/UNKNOWN/)});
test("release attribution gate requires CycloneDX 1.5 distribution artifacts",()=>{assert.match(verifier,/SCANNER_BINARY_SBOM\.cdx\.json/);assert.match(verifier,/SCANNER_IMAGE_SBOM\.cdx\.json/);assert.match(verifier,/DISTRIBUTION_SBOM\.cdx\.json/);assert.match(verifier,/CycloneDX/);assert.match(verifier,/1\.5/)});