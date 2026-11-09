/**
 * Hand `@gray/relay-policy` the interpreter module it needs before it can validate a module.
 *
 * The interpreter is the workspace's vendored wasmi wrapper
 * (`workers/vendor/relay-policy-wasmi`), compiled from a pinned Rust crate and checked into the
 * repository. The CLI locates it relative to this source file, so it works from a checkout without
 * configuration; `--interpreter` overrides the path for an installed copy. The TEE initialises the
 * same bytes its own way; what matters here is that `preparePolicy` runs the same validator and
 * loader the TEE will, with no instrumenter in the path any more.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { initInterpreter } from "@gray/relay-policy";
import { RelayKitError } from "../errors.ts";

/** The interpreter checked into the workspace, relative to this file. */
export const DEFAULT_INTERPRETER_PATH = fileURLToPath(
  new URL("../../../../vendor/relay-policy-wasmi/relay_policy_wasmi.wasm", import.meta.url).toString(),
);

/** Initialise the policy interpreter from a file (the default is the workspace's). */
export function initWorkspaceInterpreter(path: string = DEFAULT_INTERPRETER_PATH): void {
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(readFileSync(path));
  } catch {
    throw new RelayKitError("io", `cannot read the policy interpreter ${path}`);
  }
  try {
    initInterpreter(bytes);
  } catch {
    throw new RelayKitError("relay_policy", "this runtime cannot load the policy interpreter");
  }
}
