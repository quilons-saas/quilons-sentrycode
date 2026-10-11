import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const [sourceRoot] = process.argv.slice(2);
if (!sourceRoot) {
  console.error("usage: node patch-syft.mjs <syft-source-root>");
  process.exit(2);
}

const locationPath = resolve(sourceRoot, "syft/file/location.go");
let source = await readFile(locationPath, "utf8");

const oldImport = `"fmt"

\t"github.com/hashicorp/go-multierror"

\t"github.com/anchore/stereoscope/pkg/file"`;
const newImport = `"errors"
\t"fmt"

\t"github.com/anchore/stereoscope/pkg/file"`;

const oldCall = "errs = multierror.Append(errs, err)";
const newCall = "errs = errors.Join(errs, err)";

if (!source.includes(oldImport)) {
  throw new Error("Syft source drift: expected v1.54.0 location.go import block not found");
}
if (!source.includes(oldCall)) {
  throw new Error("Syft source drift: expected v1.54.0 multierror aggregation call not found");
}
if ((source.match(/github\.com\/hashicorp\/go-multierror/g) ?? []).length !== 1) {
  throw new Error("Syft source drift: expected exactly one go-multierror import in location.go");
}
if ((source.match(/multierror\.Append/g) ?? []).length !== 1) {
  throw new Error("Syft source drift: expected exactly one multierror.Append call in location.go");
}

source = source.replace(oldImport, newImport).replace(oldCall, newCall);

if (source.includes("github.com/hashicorp/go-multierror") || source.includes("multierror.Append")) {
  throw new Error("Syft controlled patch incomplete");
}
if (!source.includes(`"errors"`) || !source.includes("errors.Join(errs, err)")) {
  throw new Error("Syft controlled patch postcondition failed");
}

await writeFile(locationPath, source, "utf8");
console.log(JSON.stringify({
  patch: "syft-file-location-stdlib-errors-join",
  path: "syft/file/location.go",
  status: "applied"
}));