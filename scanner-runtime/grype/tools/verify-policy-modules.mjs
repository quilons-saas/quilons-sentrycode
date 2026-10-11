import { readFile } from "node:fs/promises";

const path = process.argv[2];
if (!path) throw new Error("go version -m file required");

const text = await readFile(path, "utf8");
const blocked = [
  "github.com/anchore/go-version",
  "github.com/hashicorp/aws-sdk-go-base/v2",
  "github.com/hashicorp/errwrap",
  "github.com/hashicorp/go-cleanhttp",
  "github.com/hashicorp/go-getter",
  "github.com/hashicorp/go-multierror",
  "github.com/hashicorp/go-version",
  "github.com/hashicorp/golang-lru/v2",
  "github.com/hashicorp/hcl/v2",
];

const present = blocked.filter((module) => text.includes(`\tdep\t${module}\t`) || text.includes(`\t=>\t${module}\t`));
if (present.length) {
  console.error(JSON.stringify({status:"blocked", blockedModuleCount:present.length, modules:present}));
  process.exit(9);
}
console.log(JSON.stringify({status:"pass", blockedModuleCount:0}));
