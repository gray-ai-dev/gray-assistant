/**
 * `gray-assistant config set|unset`: one member of the relay config changed with the agent's own writer, so the operator
 * never edits the kit's 0600 file by hand (after `init --pair` it belongs to the agent's uid 10001, and an editor run
 * with sudo can leave it owned by root, which the agent then cannot read).
 *
 * The edit keeps every comment and the layout (jsonc-parser's `modify`, the parser the config is read with), and is
 * written only when the whole new document passes the same validation `run` applies (`parseRelayConfigText`): a value
 * the agent would refuse never reaches the file. The new text goes to a temporary file in the same directory with the
 * old file's mode (and owner, when running as root), then replaces it by rename. Nothing prints the value: a member
 * such as `source.url` can hold a secret.
 *
 * The agent reads its config when it starts: the change takes effect when the agent is restarted.
 */
import { accessSync, chownSync, chmodSync, constants, lstatSync, renameSync, rmSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { applyEdits, modify, type JSONPath } from "jsonc-parser";
import { RelayKitError } from "../errors.ts";
import { MAX_CONFIG_BYTES, parseJsoncText, parseRelayConfigText } from "./config-file.ts";
import { readFileText, writePrivateFile } from "./files.ts";

/** A member path as the command takes it: names joined by dots, a number for an array element (`stack.relay_images.0`). */
const SEGMENT = /^[A-Za-z0-9_-]{1,64}$/u;
const MAX_SEGMENTS = 8;

export function parseMemberPath(text: string): JSONPath {
  const segments = text.split(".");
  if (segments.length === 0 || segments.length > MAX_SEGMENTS || segments.some((segment) => !SEGMENT.test(segment))) {
    throw new RelayKitError("usage", "the member is a path of names joined by dots, e.g. scheduler.admin_token_file");
  }
  return segments.map((segment) => (/^(0|[1-9][0-9]{0,5})$/u.test(segment) ? Number(segment) : segment));
}

export interface ConfigEditResult {
  readonly path: string;
  readonly member: string;
  /** `unset` of a member the config did not have: the file is left as it was. */
  readonly changed: boolean;
}

/** Why a write failed, in words that say where the operator can run the command instead. */
function writeRefusal(path: string, error: unknown): RelayKitError {
  const code = (error as NodeJS.ErrnoException)?.code;
  if (code === "EROFS" || code === "EACCES" || code === "EPERM") {
    return new RelayKitError(
      "io",
      `cannot write ${path} (${code}). Inside the agent's container the config is mounted read-only: run the command ` +
        `on the host from the kit's directory, as the agent's user: docker compose run --rm --no-deps -v "$PWD:/work" ` +
        `agent config set --config /work/gray-assistant.jsonc <member> <value>`,
    );
  }
  return error instanceof RelayKitError ? error : new RelayKitError("io", `cannot write ${path}`);
}

/**
 * Set (`value` given) or remove (`value` undefined) one member of the config at `path`. `value` is any JSON value; the
 * CLI passes a string unless `--json` says the argument is JSON.
 */
export function editRelayConfig(path: string, member: string, value: unknown): ConfigEditResult {
  const absolute = resolve(path);
  const jsonPath = parseMemberPath(member);
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch {
    throw new RelayKitError("io", `no relay config at ${absolute}: pass --config <file>`);
  }
  if (stat.isSymbolicLink() || !stat.isFile()) throw new RelayKitError("io", `${absolute} is not a regular file`);
  const text = readFileText(absolute, "relay config", MAX_CONFIG_BYTES);
  parseJsoncText(text, "relay config");
  const edits = modify(text, jsonPath, value, { formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" } });
  if (edits.length === 0) return { path: absolute, member, changed: false };
  const next = applyEdits(text, edits);
  if (next.length > MAX_CONFIG_BYTES) throw new RelayKitError("usage", "the edited relay config is too large");
  // The whole document as the agent will read it; the refusal names the member, never its value.
  parseRelayConfigText(next, absolute);

  const temporary = join(dirname(absolute), `.${basename(absolute)}.${process.pid}.tmp`);
  try {
    // The directory must take the new file (a read-only mount does not): the refusal then says where to run instead.
    accessSync(dirname(absolute), constants.W_OK);
  } catch (error) {
    throw writeRefusal(absolute, error);
  }
  try {
    writePrivateFile(temporary, next, { force: true });
    chmodSync(temporary, stat.mode & 0o777);
    if (process.getuid?.() === 0 && (stat.uid !== 0 || stat.gid !== 0)) chownSync(temporary, stat.uid, stat.gid);
    renameSync(temporary, absolute);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw writeRefusal(absolute, error);
  }
  return { path: absolute, member, changed: true };
}
