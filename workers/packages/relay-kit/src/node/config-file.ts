/**
 * The one config file `gray-assistant run|doctor|status` reads: JSONC (comments are how every key is
 * documented in the skeleton `init` writes), validated by the daemon's zod schema and K3's source
 * schema. Relative paths are resolved against the config file's directory, so the same file works
 * from any working directory and inside the compose image.
 *
 * The schema is strict: an unknown member is a usage error, never silently ignored. Error messages
 * name the member path and never echo a value (a config can hold a path, and a bad path can be a
 * secret's location).
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { isObject, type JsonObject } from "@gray/json";
import { parse, printParseErrorCode, type ParseError } from "jsonc-parser";
import { parseRelayDaemonConfig, type RelayDaemonConfig } from "../daemon/config.ts";
import { RelayKitError } from "../errors.ts";
import { readFileText } from "./files.ts";
import { parseSourceConfig } from "./source/config.ts";
import type { ResolvedSourceConfig } from "./source/config-types.ts";

/** The largest config file this tool reads; the real one is a few kilobytes. */
export const MAX_CONFIG_BYTES = 1024 * 1024;

/** Where the agent's image and the host install put the config (deploy/relay/Dockerfile, compose.yaml, host/). */
export const HOST_CONFIG_PATH = "/etc/gray-assistant/gray-assistant.jsonc";
/** The config's file name when it sits in the working directory (`gray-assistant init` writes it so). */
export const LOCAL_CONFIG_NAME = "gray-assistant.jsonc";

/**
 * The config a command reads when it is given no `--config`: `$GRAY_ASSISTANT_CONFIG` (the image sets it), else
 * `/etc/gray-assistant/gray-assistant.jsonc` when it exists (the image's and the host install's path), else
 * `./gray-assistant.jsonc`. So every command runs as plain `gray-assistant status` on the relay's machine and in its container.
 */
export function defaultConfigPath(env: Readonly<Record<string, string | undefined>> = process.env, exists: (path: string) => boolean = existsSync): string {
  const fromEnv = env["GRAY_ASSISTANT_CONFIG"];
  if (fromEnv !== undefined && fromEnv.trim() !== "") return fromEnv;
  if (exists(HOST_CONFIG_PATH)) return HOST_CONFIG_PATH;
  return LOCAL_CONFIG_NAME;
}

/** One loaded config: the resolved raw document the daemon gets, and both parsed views. */
export interface LoadedRelayConfig {
  readonly path: string;
  readonly directory: string;
  /** The document with every relative path resolved to an absolute one. */
  readonly raw: JsonObject;
  readonly daemon: RelayDaemonConfig;
  readonly source: ResolvedSourceConfig;
}

/** Read and parse a JSONC document. A syntax error is one sentence; the file's text is never echoed. */
export function parseJsoncText(text: string, what: string): unknown {
  const errors: ParseError[] = [];
  const value = parse(text, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length > 0) {
    const first = errors[0] as ParseError;
    throw new RelayKitError("usage", `invalid ${what}: ${printParseErrorCode(first.error)} at offset ${first.offset}`);
  }
  return value;
}

function resolveMember(value: JsonObject, key: string, base: string): void {
  const current = value[key];
  if (typeof current === "string" && current.length > 0 && !isAbsolute(current)) value[key] = resolve(base, current);
}

function resolveNested(value: JsonObject, key: string, base: string, members: readonly string[]): void {
  const nested = value[key];
  if (!isObject(nested)) return;
  for (const member of members) resolveMember(nested as JsonObject, member, base);
}

/** Resolve every path member the config has, in one place, against the config file's directory. */
export function resolveConfigPaths(raw: JsonObject, directory: string): JsonObject {
  const out: JsonObject = { ...raw };
  resolveMember(out, "key", directory);
  resolveMember(out, "policy_bundle", directory);
  resolveMember(out, "state_file", directory);
  resolveMember(out, "status_file", directory);
  resolveNested(out, "source", directory, ["path", "token_file"]);
  resolveNested(out, "scheduler", directory, ["admin_token_file"]);
  const source = out["source"];
  if (isObject(source)) resolveNested(source, "logins", directory, ["dir"]);
  resolveNested(out, "stack", directory, ["issue_log"]);
  const stack = out["stack"];
  if (isObject(stack)) resolveNested(stack, "registry", directory, ["password_file"]);
  resolveNested(out, "tunnel", directory, ["server_ca", "frpc", "caddy", "data_dir"]);
  const tunnel = out["tunnel"];
  if (isObject(tunnel)) {
    resolveNested(tunnel, "acme", directory, ["ca_root"]);
    resolveNested(tunnel, "ct", directory, ["certspotter_api_key_file"]);
  }
  return out;
}

/** ` --config <path>` for a command line that must name this config, or nothing when the default finds it. */
export function configArgumentFor(path: string): string {
  return resolve(defaultConfigPath()) === resolve(path) ? "" : ` --config ${path}`;
}

/** Read, resolve and validate the one config file. */
export function loadRelayConfigFile(path: string): LoadedRelayConfig {
  const absolute = resolve(path);
  if (!existsSync(absolute)) {
    throw new RelayKitError(
      "io",
      `no relay config at ${absolute}: pass --config <file>, set GRAY_ASSISTANT_CONFIG, or put it at ${HOST_CONFIG_PATH} or ./${LOCAL_CONFIG_NAME}`,
    );
  }
  return parseRelayConfigText(readFileText(absolute, "relay config", MAX_CONFIG_BYTES), absolute);
}

/** Parse and validate a config's text as if it were the file at `absolute` (relative paths resolve beside it). */
export function parseRelayConfigText(text: string, absolute: string): LoadedRelayConfig {
  const value = parseJsoncText(text, "relay config");
  if (!isObject(value as never)) throw new RelayKitError("usage", "the relay config is not a JSON object");
  const directory = dirname(absolute);
  const raw = resolveConfigPaths(value as JsonObject, directory);
  const daemon = parseRelayDaemonConfig(raw);
  // The relay's logins live in the agent's state volume, beside state.json, unless the config says otherwise.
  const source = parseSourceConfig((raw as { source?: unknown }).source, { defaultLoginsDir: join(dirname(daemon.stateFile), "logins") });
  return { path: absolute, directory, raw, daemon, source };
}

/** Whether a config still carries a value `init` wrote as a placeholder (`doctor` refuses these). */
export function isPlaceholder(value: string, placeholder: string): boolean {
  return value === placeholder;
}

/** The text of a file, for diagnostics; a missing file is `null`, never an error. */
export function readOptionalText(path: string, maxBytes = MAX_CONFIG_BYTES): string | null {
  try {
    return readFileSync(path, "utf8").slice(0, maxBytes);
  } catch {
    return null;
  }
}
