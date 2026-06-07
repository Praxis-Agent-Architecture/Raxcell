#!/usr/bin/env node
import { chmodSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "win32") {
  const scriptDir = dirname(fileURLToPath(import.meta.url));
  for (const scriptName of ["cli.js", "windows-runner.js"]) {
    chmodSync(resolve(scriptDir, "../dist", scriptName), 0o755);
  }
}
