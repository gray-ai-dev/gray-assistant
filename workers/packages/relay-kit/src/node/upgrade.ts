/**
 * `gray-assistant upgrade --dir <kit>`: move a kit directory written by any earlier kit to this one, from this kit's
 * image (`docker run --rm -v "$PWD:/work" <image> upgrade --dir /work`). Kits up to 1.1.1 called the program
 * `gray-relay`: config `gray-relay.jsonc`, state `/var/lib/gray-relay`, config mount `/etc/gray-relay`. Between 1.1.1
 * and this kit the config schema only gained the optional `chain` member (phase 2), so the move is the names:
 *
 * - the config: `gray-assistant.jsonc`, else `gray-relay.jsonc`; every string member under an old path is rewritten
 *   with jsonc-parser's `modify` (comments and layout kept, as `config set` does) and the result must pass the
 *   validation `run` and `doctor` apply (`parseRelayConfigText`). The new file is 0600, the old one kept as a backup.
 * - `compose.yaml`, when an `init --pair` of any kit wrote it: rewritten from `pairedComposeText` (init's template)
 *   with `image`, keeping its project name and its state volume's key, so the volume and the network stay. A file whose
 *   agent ran all the time (`restart:`) gets a note: remove that container, which this kit's image cannot run.
 *
 * Running it again changes nothing. No value of the config is printed: the result names files and members only.
 */
import { chmodSync, chownSync, existsSync, lstatSync, renameSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { applyEdits, modify, parseTree, type JSONPath, type Node } from "jsonc-parser";
import { isYamlMap, parseComposeText } from "@gray/lane-compose";
import { RelayKitError } from "../errors.ts";
import { INIT_FILES, PAIRED_COMPOSE_FILE, pairedComposeText, STATE_MOUNT } from "../init.ts";
import { MAX_CONFIG_BYTES, parseRelayConfigText } from "./config-file.ts";
import { readFileText, writePrivateFile } from "./files.ts";
import { PHASE1_TEXT } from "./doctor.ts";

/** The config file name of kits up to 1.1.1. */
export const OLD_CONFIG_FILE = "gray-relay.jsonc";
/** The old path prefixes and their names now (kit 1.2.0). */
const PATH_RENAMES: ReadonlyArray<readonly [string, string]> = [
  ["/var/lib/gray-relay", STATE_MOUNT],
  ["/etc/gray-relay/gray-relay.jsonc", "/etc/gray-assistant/gray-assistant.jsonc"],
  ["/etc/gray-relay", "/etc/gray-assistant"],
];
/** The first line of a compose file an `init --pair` wrote, under either name. */
const OWN_COMPOSE = /^# gray-(relay|assistant)'s agent, written by `gray-(relay|assistant) init --pair`/u;
/** A compose file of a kit whose agent ran all the time. */
const ALWAYS_ON = /^\s+restart:\s*\S/mu;
export const ALWAYS_ON_NOTE =
  "compose.yaml used to run the agent all the time (docker compose up -d, restart: unless-stopped); this kit runs one container per command (docker compose run --rm --no-deps agent <command>) and has no run command. Remove the old container once, in this directory: docker compose rm -sf agent (the state volume stays), and do not start it with docker compose up again";
const VOLUME_KEY = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/u;

export interface UpgradeOptions {
  readonly directory: string;
  /** The image the compose file runs: `--image`, else `$GRAY_ASSISTANT_IMAGE`; null: compose.yaml is not rewritten. */
  readonly image: string | null;
  /** This kit's version, the backups' suffix. */
  readonly version: string;
}

export interface UpgradeResult {
  readonly directory: string;
  readonly relayId: string;
  /** The config the install had: `gray-relay.jsonc` (kit 1.1.1 or older) or `gray-assistant.jsonc`. */
  readonly found: string;
  /** Files written, and the backups of what they replaced. */
  readonly written: readonly string[];
  readonly backups: readonly string[];
  /** The config members whose old path was rewritten (names only). */
  readonly members: readonly string[];
  /** The compose project kept, or null when compose.yaml was not rewritten. */
  readonly project: string | null;
  /** What the operator should know: a file left alone, an owner to fix. */
  readonly notes: readonly string[];
}

function renamed(value: string): string | null {
  for (const [from, to] of PATH_RENAMES) {
    if (value === from || value.startsWith(`${from}/`)) return `${to}${value.slice(from.length)}`;
  }
  return null;
}

/** Every string value under an old path, with its JSON path. */
function oldPathMembers(node: Node | undefined, path: JSONPath = [], out: Array<{ path: JSONPath; value: string }> = []): Array<{ path: JSONPath; value: string }> {
  if (node === undefined) return out;
  if (node.type === "string" && typeof node.value === "string" && renamed(node.value) !== null) out.push({ path, value: node.value });
  if (node.type === "object") {
    for (const property of node.children ?? []) {
      const [key, value] = property.children ?? [];
      if (key !== undefined && typeof key.value === "string") oldPathMembers(value, [...path, key.value], out);
    }
  }
  if (node.type === "array") (node.children ?? []).forEach((child, index) => oldPathMembers(child, [...path, index], out));
  return out;
}

/** `<file>.bak-<version>`, or with `-2`, `-3`, ... when that backup is already there. */
function backupPath(path: string, version: string): string {
  for (let n = 1; ; n += 1) {
    const candidate = `${path}.bak-${version}${n === 1 ? "" : `-${n}`}`;
    if (!existsSync(candidate)) return candidate;
  }
}

/** Write `text` at `path` (0600 or 0644) with `owner`'s uid and gid when this process may set them; a note otherwise. */
function writeLike(path: string, text: string, mode: number, owner: { uid: number; gid: number } | null, notes: string[]): void {
  writePrivateFile(path, text, { force: true });
  chmodSync(path, mode);
  if (owner === null) return;
  const now = statSync(path);
  if (now.uid === owner.uid && now.gid === owner.gid) return;
  try {
    chownSync(path, owner.uid, owner.gid);
  } catch {
    notes.push(`${path} is owned by ${now.uid}:${now.gid}, the file it replaces by ${owner.uid}:${owner.gid}: chown ${owner.uid}:${owner.gid} it`);
  }
}

function regularFile(path: string): { uid: number; gid: number } | null {
  if (!existsSync(path)) return null;
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new RelayKitError("io", `${path} is not a regular file`);
  return { uid: stat.uid, gid: stat.gid };
}

/**
 * The project name and state volume key of a compose file an `init --pair` of any kit wrote, or null for any other file.
 * `upgrade` and `init --pair --force` keep both, so a project started by an older kit keeps its volume (the agent's
 * state: designation.json, account aliases) and its network.
 */
export function pairedComposeKeep(composeText: string): { readonly name: string; readonly stateVolume: string } | null {
  if (!OWN_COMPOSE.test(composeText)) return null;
  const parsed = parseComposeText(composeText);
  if (!parsed.ok) return null;
  const name = parsed.value.get("name");
  const services = parsed.value.get("services");
  const agent = isYamlMap(services) ? services.get("agent") : undefined;
  const volumes = isYamlMap(agent) ? agent.get("volumes") : undefined;
  const stateVolume = (Array.isArray(volumes) ? volumes : [])
    .map((entry) => (typeof entry === "string" ? entry.split(":") : []))
    .find((parts) => parts.length >= 2 && (parts[1] === STATE_MOUNT || parts[1] === "/var/lib/gray-relay"))?.[0];
  return typeof name === "string" && stateVolume !== undefined && VOLUME_KEY.test(stateVolume) ? { name, stateVolume } : null;
}

export function upgradeWorkspace(options: UpgradeOptions): UpgradeResult {
  const directory = resolve(options.directory);
  const configPath = join(directory, INIT_FILES.config);
  const oldPath = join(directory, OLD_CONFIG_FILE);
  const current = regularFile(configPath);
  const old = current === null ? regularFile(oldPath) : null;
  if (current === null && old === null) {
    throw new RelayKitError("io", `no ${INIT_FILES.config} or ${OLD_CONFIG_FILE} in ${directory}: pass --dir <the kit directory, the one with relay-key.json and compose.yaml>`);
  }
  const notes: string[] = [];
  const written: string[] = [];
  const backups: string[] = [];
  const source = current === null ? oldPath : configPath;
  const text = readFileText(source, "relay config", MAX_CONFIG_BYTES);
  const members = oldPathMembers(parseTree(text));
  let next = text;
  for (const member of members) {
    next = applyEdits(next, modify(next, member.path, renamed(member.value), { formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" } }));
  }
  // The whole document as run and doctor read it; the refusal names the member, never its value.
  const loaded = parseRelayConfigText(next, configPath);
  if (current === null || next !== text) {
    const backup = backupPath(source, options.version);
    if (current !== null) writeLike(backup, text, 0o600, current, notes);
    writeLike(configPath, next, 0o600, current ?? old, notes);
    // The old file stays as the backup (renamed, so a running container keeps reading it until it is recreated).
    if (current === null) renameSync(oldPath, backup);
    backups.push(backup);
    written.push(configPath);
  }
  // A phase-1 pairing (no contract) cannot serve with this kit: it pairs again, and says so where the agent looks first.
  if (loaded.daemon.pairing !== null && (loaded.daemon.chain ?? null) === null) notes.push(PHASE1_TEXT);
  if (current !== null && existsSync(oldPath)) notes.push(`${oldPath} is left as it is: ${INIT_FILES.config} is the config this kit reads`);

  const composePath = join(directory, PAIRED_COMPOSE_FILE);
  const composeOwner = regularFile(composePath);
  let project: string | null = null;
  if (composeOwner === null) {
    notes.push(`no ${PAIRED_COMPOSE_FILE} in ${directory}: a host install starts the agent itself; point it at ${configPath}`);
  } else {
    const composeText = readFileText(composePath, "compose file", MAX_CONFIG_BYTES);
    const keep = pairedComposeKeep(composeText);
    if (keep === null) {
      notes.push(`${composePath} was not written by init --pair (or names no project or state volume): left as it is; mount ${INIT_FILES.config} at /etc/gray-assistant/gray-assistant.jsonc and the state volume at ${STATE_MOUNT}`);
    } else if (options.image === null) {
      throw new RelayKitError("usage", "upgrade needs the image compose.yaml should run: pass --image <image@sha256:...> (the published image sets $GRAY_ASSISTANT_IMAGE)");
    } else {
      project = keep.name;
      const composeNext = pairedComposeText(options.image, loaded.daemon.relayId, keep);
      if (composeNext !== composeText) {
        const backup = backupPath(composePath, options.version);
        writeLike(backup, composeText, 0o644, composeOwner, notes);
        backups.push(backup);
        writeLike(composePath, composeNext, 0o644, composeOwner, notes);
        written.push(composePath);
      }
      // Kits up to 1.4.5 ran the agent all the time (`docker compose up -d`, `restart: unless-stopped`, the image's `run`).
      // This kit has no `run`: a container that project left would restart for ever on "unknown command".
      if (ALWAYS_ON.test(composeText)) notes.push(ALWAYS_ON_NOTE);
    }
  }
  return { directory, relayId: loaded.daemon.relayId, found: current === null ? OLD_CONFIG_FILE : INIT_FILES.config, written, backups, members: members.map((m) => m.path.join(".")), project, notes };
}
