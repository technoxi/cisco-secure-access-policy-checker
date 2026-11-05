#!/usr/bin/env node
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.join(__dirname, "..");
const dir = path.join(root, "test", process.argv.includes("--browser") ? "browser" : "");
const files = fs.readdirSync(dir).filter((f) => f.endsWith(".js") && !f.startsWith("ui-")).sort();

let failed = 0;
for (const file of files) {
  const r = spawnSync(process.execPath, [path.join(dir, file)], { cwd: root, encoding: "utf8" });
  const ok = r.status === 0;
  console.log(`${ok ? "PASS" : "FAIL"}  ${path.relative(root, path.join(dir, file))}`);
  if (!ok) { failed++; console.log((r.stdout + r.stderr).split("\n").map((l) => "      " + l).join("\n")); }
}
console.log(`\n${files.length - failed}/${files.length} test files passed`);
process.exit(failed ? 1 : 0);
