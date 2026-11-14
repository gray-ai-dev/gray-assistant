/**
 * `gray-assistant accounts import <file>` (kit 1.6.2): the `file` source's accounts.json, put where the source reads it.
 *
 * A paired kit's file source reads `/var/lib/gray-assistant/accounts.json`, in the agent's state volume: the kit
 * directory is mounted read-only and holds no account. Nothing wrote that file: a relay had to find the docker volume's
 * path on the host and write into it as root (the staging rehearsal of 2026-11-14). This command takes the file from
 * where the relay can put it, checks it as the source will read it (the same parser, the source's `max_accounts`, the
 * config's relay), and writes it as the agent's user, 0600, by an atomic rename.
 *
 * The file comes from the host one of two ways (the container sees the kit directory at /run/secrets, read-only):
 *
 *     docker compose run --rm --no-deps agent accounts import /run/secrets/accounts.json     a file in the kit directory
 *     docker compose run --rm --no-deps -T agent accounts import - < accounts.json            piped, from anywhere
 *
 * The first needs the file readable by the agent's user in the container (uid 10001: owned by it, or mode 0644 for the
 * import), and the copy removed afterwards; the second needs neither. No credential is printed: a refusal names a
 * reason, never a value.
 */
import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { RelayKitError } from "../errors.ts";
import type { LoadedRelayConfig } from "./config-file.ts";
import { writeAtomicPrivateFile } from "./daemon/atomic-file.ts";
import { parseAccountsSourceText } from "./source/file.ts";
import { MAX_SOURCE_FILE_BYTES } from "./source/limits.ts";

/** The source reads at most this much. */
const MAX_IMPORT_BYTES = MAX_SOURCE_FILE_BYTES;

export interface ImportedAccounts {
  readonly relayId: string;
  /** Where the file source reads it: `source.path`. */
  readonly path: string;
  readonly accounts: number;
  /** A file was there before. */
  readonly replaced: boolean;
}

/** The command's own text for the piped form, in every refusal that the other form's ownership causes. */
export const IMPORT_PIPE_HINT = "docker compose run --rm --no-deps -T agent accounts import - < accounts.json";

function readSource(source: string, readStdin: () => Uint8Array): string {
  let bytes: Uint8Array;
  if (source === "-") {
    try {
      bytes = readStdin();
    } catch {
      throw new RelayKitError("io", `nothing could be read from standard input: pipe the file in (${IMPORT_PIPE_HINT})`);
    }
  } else {
    try {
      bytes = readFileSync(resolve(source));
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") throw new RelayKitError("io", `no file at ${source}: the container sees the kit directory at /run/secrets, so put accounts.json in the kit directory and name /run/secrets/accounts.json, or pipe it (${IMPORT_PIPE_HINT})`);
      if (code === "EACCES") throw new RelayKitError("io", `${source} is not readable by the agent's user in the container (uid 10001): pipe it instead (${IMPORT_PIPE_HINT}), or make it readable for the import (chmod 644) and remove it afterwards`);
      throw new RelayKitError("io", `${source} does not read`);
    }
  }
  if (bytes.length === 0) throw new RelayKitError("io", `${source === "-" ? "standard input" : source} is empty`);
  if (bytes.length > MAX_IMPORT_BYTES) throw new RelayKitError("io", `${source === "-" ? "standard input" : source} is larger than ${MAX_IMPORT_BYTES} bytes`);
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw new RelayKitError("io", `${source === "-" ? "standard input" : source} is not valid UTF-8`);
  }
}

/**
 * Check `source` (a path, or `-` for standard input) as the file source reads it and write it to `source.path`.
 * Throws a `RelayKitError` and writes nothing when the config's source is not `file`, the document does not parse as
 * accounts.json, or it names another relay.
 */
export function importAccountsFile(config: LoadedRelayConfig, source: string, deps: { readonly readStdin?: () => Uint8Array } = {}): ImportedAccounts {
  if (config.source.kind !== "file") {
    throw new RelayKitError("usage", `accounts import is for the file source, and this config's source is ${config.source.kind}: its accounts live in your relay software; gray-assistant accounts push reads them from there`);
  }
  const text = readSource(source, deps.readStdin ?? (() => readFileSync(0)));
  let parsed: ReturnType<typeof parseAccountsSourceText>;
  try {
    parsed = parseAccountsSourceText(text, { maxAccounts: config.source.maxAccounts });
  } catch (error) {
    const detail = error instanceof RelayKitError ? `${error.code}${error.detail === null ? "" : `: ${error.detail}`}` : "invalid";
    throw new RelayKitError("invalid_accounts", `the file is not an accounts.json the file source reads (${detail}); nothing was written. Its form: {"relay_id": "<this relay>", "accounts": [{"account_id", "vendor", "credential": {"type", "value"}}]}`);
  }
  if (parsed.relayId !== config.daemon.relayId) {
    throw new RelayKitError("invalid_accounts", `the file's relay_id is not this kit's relay (${config.daemon.relayId}); nothing was written`);
  }
  const path = config.source.path;
  let replaced = false;
  try {
    const existing = lstatSync(path);
    // Never through a link or onto a directory: the source refuses both when it reads.
    if (!existing.isFile() || existing.isSymbolicLink()) throw new RelayKitError("io", `${path} is not a regular file: remove it, then run the command again`);
    replaced = true;
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
  }
  try {
    writeAtomicPrivateFile(path, text);
  } catch {
    throw new RelayKitError("io", `cannot write ${path}: its directory must be writable by the agent's user (the state volume compose.yaml mounts)`);
  }
  return { relayId: parsed.relayId, path, accounts: parsed.accounts.length, replaced };
}
