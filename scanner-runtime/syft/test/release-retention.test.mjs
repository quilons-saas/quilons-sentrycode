import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const source = readFileSync(
  resolve("scanner-runtime/syft/build-controlled-scanner.ps1"),
  "utf8"
);

test("controlled Syft release mode explicitly retains a qualified image", () => {
  assert.match(source, /QUILONS_RETAIN_CONTROLLED_IMAGE/);
  assert.match(source, /RETAINED CONTROLLED SYFT IMAGE/);
  assert.match(
    source,
    /if\s*\(\s*\$env:QUILONS_RETAIN_CONTROLLED_IMAGE\s*-eq\s*'1'\s*\)/
  );
});

test("controlled Syft default build path still removes the temporary local image", () => {
  assert.match(
    source,
    /'image'\s*,\s*'rm'\s*,\s*'-f'\s*,\s*\$ImageTag/
  );
});