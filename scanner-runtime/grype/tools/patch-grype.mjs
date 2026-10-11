import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";

const root = process.argv[2];
if (!root) throw new Error("Grype source root is required");

async function replaceExact(path, replacements) {
  let source = await readFile(path, "utf8");
  for (const [from, to, count = 1] of replacements) {
    const matches = source.split(from).length - 1;
    if (matches !== count) {
      throw new Error(`${path}: expected ${count} occurrence(s) of ${JSON.stringify(from)}, got ${matches}`);
    }
    source = source.replace(from, to);
  }
  await writeFile(path, source);
}

const providerPath = join(root, "grype/db/v6/vulnerability_provider.go");
const providerText = await readFile(providerPath, "utf8");
if (!providerText.includes("func NewVulnerabilityProvider")) {
  throw new Error("v6 vulnerability provider source drift");
}
await rename(providerPath, providerPath + ".disabled");

const versionFiles = [
  "grype/version/bitnami_version.go",
  "grype/version/fuzzy_constraint.go",
  "grype/version/golang_version.go",
  "grype/version/jvm_version.go",
  "grype/version/semantic_version.go",
];

for (const rel of versionFiles) {
  const path = join(root, rel);
  await replaceExact(path, [
    ['hashiVer "github.com/anchore/go-version"', 'hashiVer "github.com/Masterminds/semver/v3"'],
  ]);
}

await replaceExact(join(root, "grype/version/golang_version.go"), [
  ["hashiVer.NewSemver(fixedUp)", "hashiVer.StrictNewVersion(fixedUp)"],
]);

await replaceExact(join(root, "grype/version/semantic_version.go"), [
  ["hashiVer.NewSemver(clean)", "hashiVer.StrictNewVersion(clean)"],
]);

await replaceExact(join(root, "grype/version/bitnami_version.go"), [
  [
    `\t\tvar segments []string
\t\tfor _, segment := range verObj.Segments() {
\t\t\tsegments = append(segments, fmt.Sprintf("%d", segment))
\t\t}
\t\t// drop any pre-release info
\t\traw = strings.Join(segments, ".")
`,
    `\t\t// drop any pre-release/build info while preserving the numeric release tuple
\t\traw = fmt.Sprintf("%d.%d.%d", verObj.Major(), verObj.Minor(), verObj.Patch())
`
  ],
]);

await replaceExact(join(root, "grype/version/bitnami_version.go"), [
  [
    `	"strings"
`,
    ``
  ],
]);
await replaceExact(join(root, "grype/version/fuzzy_constraint.go"), [
  ["semverConstraint = &value", "semverConstraint = value"],
]);

console.log(JSON.stringify({
  status: "pass",
  disabled: ["grype/db/v6/vulnerability_provider.go"],
  semverReplacement: "github.com/Masterminds/semver/v3",
  patchedVersionFiles: versionFiles,
}));
