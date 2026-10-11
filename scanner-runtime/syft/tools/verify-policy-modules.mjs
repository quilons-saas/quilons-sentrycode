import { readFile } from "node:fs/promises";

const [buildInfoPath] = process.argv.slice(2);
if (!buildInfoPath) {
  console.error("usage: node verify-policy-modules.mjs <go-version-m.txt>");
  process.exit(2);
}

const blocked = new Set([
  "github.com/anchore/go-version",
  "github.com/hashicorp/aws-sdk-go-base/v2",
  "github.com/hashicorp/errwrap",
  "github.com/hashicorp/go-cleanhttp",
  "github.com/hashicorp/go-getter",
  "github.com/hashicorp/go-multierror",
  "github.com/hashicorp/go-version",
  "github.com/hashicorp/golang-lru/v2",
  "github.com/hashicorp/hcl/v2"
]);

const text = await readFile(buildInfoPath, "utf8");
const hits = [];
for (const line of text.split(/\r?\n/)) {
  const match = line.match(/^\s*dep\s+(\S+)\s+(\S+)/);
  if (match && blocked.has(match[1])) {
    hits.push({ module: match[1], version: match[2] });
  }
}

if (hits.length) {
  console.error(JSON.stringify({ status: "blocked", blockedModuleCount: hits.length, hits }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({ status: "pass", blockedModuleCount: 0 }));
