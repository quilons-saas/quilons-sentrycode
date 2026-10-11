import { readFile } from "node:fs/promises";

const [buildInfoPath] = process.argv.slice(2);
if (!buildInfoPath) {
  console.error("usage: node verify-compiled-modules.mjs <go-version-m.txt>");
  process.exit(2);
}

const blocked = new Set([
  "github.com/hashicorp/errwrap",
  "github.com/hashicorp/go-multierror"
]);

const text = await readFile(buildInfoPath, "utf8");
const hits = [];

for (const line of text.split(/\r?\n/)) {
  const match = line.match(/^\s*dep\s+(\S+)\s+(\S+)/);
  if (!match) continue;
  if (blocked.has(match[1])) hits.push({ module: match[1], version: match[2] });
}

if (hits.length) {
  console.error(JSON.stringify({ status: "blocked", hits }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  status: "pass",
  blockedModuleCount: 0
}));