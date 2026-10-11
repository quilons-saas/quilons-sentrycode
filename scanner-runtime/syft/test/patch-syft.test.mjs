import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const patcher = fileURLToPath(new URL("../tools/patch-syft.mjs", import.meta.url));

function run(root) {
  return spawnSync(process.execPath, [patcher, root], { encoding: "utf8" });
}

const exactFixture = `package file

import (
\t"fmt"

\t"github.com/hashicorp/go-multierror"

\t"github.com/anchore/stereoscope/pkg/file"
\t"github.com/anchore/stereoscope/pkg/image"
)

type LocationMetadata struct {
\tAnnotations map[string]string
}

func (m *LocationMetadata) merge(other LocationMetadata) error {
\tvar errs error
\tfor k, v := range other.Annotations {
\t\tif otherV, ok := m.Annotations[k]; ok {
\t\t\tif v != otherV {
\t\t\t\terr := fmt.Errorf("unable to merge location metadata: conflicting values for key=%q: %q != %q", k, v, otherV)
\t\t\t\terrs = multierror.Append(errs, err)
\t\t\t\tcontinue
\t\t\t}
\t\t}
\t\tm.Annotations[k] = v
\t}
\treturn errs
}
`;

test("controlled Syft patch replaces multierror with standard-library errors.Join", async () => {
  const root = await mkdtemp(join(tmpdir(), "quilons-syft-patch-"));
  try {
    const dir = join(root, "syft", "file");
    await mkdir(dir, { recursive: true });
    const file = join(dir, "location.go");
    await writeFile(file, exactFixture, "utf8");

    const result = run(root);
    assert.equal(result.status, 0, result.stderr);

    const patched = await readFile(file, "utf8");
    assert.match(patched, /"errors"/);
    assert.match(patched, /errors\.Join\(errs, err\)/);
    assert.doesNotMatch(patched, /hashicorp\/go-multierror/);
    assert.doesNotMatch(patched, /multierror\.Append/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("controlled Syft patch fails closed when upstream source drifts", async () => {
  const root = await mkdtemp(join(tmpdir(), "quilons-syft-patch-drift-"));
  try {
    const dir = join(root, "syft", "file");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "location.go"), exactFixture.replace("multierror.Append", "multierror.AppendInto"), "utf8");

    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /source drift/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});