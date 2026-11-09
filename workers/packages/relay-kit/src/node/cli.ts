#!/usr/bin/env node
/** The `gray-assistant` executable: `runCli` and the process's exit code, nothing else. */
import { runCli } from "./main.ts";

runCli(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
});
