/**
 * `gray-assistant` — the relay operator's command line.
 *
 *     gray-assistant keygen --out <dir> [--key-id <id>]
 *     gray-assistant attest <lane origin> (--allow <release-list.json> --release-key <64 hex>
 *                   [--allow-freshness <file> --freshness-key <64 hex>] | --allow-unpinned)
 *                       --app-id <40 hex> --kms-ca-pubkey <182 hex> [--accept-os-image <hash> ...]
 *                       [--out <verified-report.json>]
 *     gray-assistant policy bundle --module <module.wasm> --templates <templates.json> --version <n>
 *                              --relay-id <id> --key <key> --out <bundle.json>
 *     gray-assistant credentials seal --report <verified-report.json> [--report <...>] [--reports <list>]
 *                                 --accounts <accounts.json> [--version <n>] --relay-id <id>
 *                                 --key <key> --out <envelope.json|dir>
 *     gray-assistant credentials push-token --report <verified-report.json> [--report <...>] [--reports <list>]
 *                                        --account <id> --token-file <file> --type <api_key|oauth_access_token>
 *                                        [--version <n>] --relay-id <id> --key <key> [--out <file|dir>]
 *     gray-assistant credentials revoke --report <verified-report.json> [--report <...>] [--reports <list>]
 *                                   (--account <id> | --relay) [--version <n>] --relay-id <id> --key <key>
 *                                   --out <envelope.json|dir>
 *     gray-assistant upload <lane origin> <file> [--report <verified-report.json>]
 *     gray-assistant scheduler --config <scheduler.json>
 *     gray-assistant init --dir <dir> [--relay-id <id>] [--scheduler-url <url>] [--lane-origin <url>]
 *                    [--release-list <url>] [--release-public-key <64 hex>] [--release-freshness-public-key <64 hex>]
 *                    [--app-id <40 hex>] [--kms-ca-pubkey <182 hex>] [--force]
 *     gray-assistant init --pair <code> --gray <api origin> --dir <dir> [--key <relay-key.json>] [--force]
 *                    [--registry-user <user> [--registry-expires-at <YYYY-MM-DDTHH:MM:SSZ>]]
 *     gray-assistant accounts [--config <gray-assistant.jsonc>]
 *     gray-assistant deliver [--config <gray-assistant.jsonc>] [--no-wait] [--timeout <s>]   (phase 2, P4b)
 *     gray-assistant accounts push [--config <gray-assistant.jsonc>]                       (phase 2)
 *     gray-assistant registry set [--config <gray-assistant.jsonc>]                        (phase 2)
 *     gray-assistant run [--config <gray-assistant.jsonc>] [--ca <pem>] [--verifier-module <mjs>]
 *     gray-assistant doctor [--config <gray-assistant.jsonc>] [--ca <pem>] [--verifier-module <mjs>] [--now <unix>]
 *     gray-assistant status [--config <gray-assistant.jsonc>]
 *     gray-assistant pause|resume [--config <gray-assistant.jsonc>]
 *     gray-assistant releases [--config <gray-assistant.jsonc>]
 *     gray-assistant releases accept <id> [--config <gray-assistant.jsonc>] [--no-wait] [--timeout <s>]
 *     gray-assistant releases reject|unreject <hash> [--config <gray-assistant.jsonc>]
 *     gray-assistant stack rollout <image> | rollback | restart [--config <gray-assistant.jsonc>] [--no-wait] [--timeout <s>]
 *     gray-assistant stack status [--config <gray-assistant.jsonc>]
 *     gray-assistant debug get <request id> [--out <file>] [--config <gray-assistant.jsonc>]
 *     gray-assistant login <account> [--config <gray-assistant.jsonc>]
 *     gray-assistant ui [--config <gray-assistant.jsonc>] [--port <n>] [--ca <pem>] [--verifier-module <mjs>]
 *     gray-assistant ui link [--config <gray-assistant.jsonc>] [--port <n>]
 *     gray-assistant ui enroll [--config <gray-assistant.jsonc>] [--origin <https origin>]
 *     gray-assistant ui passkeys list|revoke <id> [--config <gray-assistant.jsonc>]
 *     gray-assistant policy test --bundle <bundle.json> --fixtures <fixtures.jsonl>
 *                              (--key <relay-key.json> | --public-key <64 hex>)
 *     gray-assistant config set <member> <value> [--json] [--config <gray-assistant.jsonc>]
 *     gray-assistant config unset <member> [--config <gray-assistant.jsonc>]
 *     gray-assistant --version | -V
 *
 * `credentials seal|push-token|revoke` without `--version` take the clock in Unix milliseconds, the daemon ledger's
 * floor, and say so (`version <n> (chosen: now)`, `"version_chosen": true`).
 *
 * Without `--config` a command reads `$GRAY_ASSISTANT_CONFIG`, else /etc/gray-assistant/gray-assistant.jsonc when it exists, else
 * ./gray-assistant.jsonc (`defaultConfigPath`).
 *
 * Exit codes: 0 success, 1 a refusal (a failed verification, a policy the TEE would refuse, a lane
 * that answered an error), 2 usage or I/O. Secret values are never printed: the key's seed, account
 * credentials and tokens stay in the process (the only binary a command prints is a ciphertext
 * envelope, which is not a secret); tests scan every stdout/stderr line for them.
 */
import { existsSync } from "node:fs";
import { isIP } from "node:net";
import { join } from "node:path";
import { get, isObject, parsePlain, parseStrict, toJsonString, type JsonObject } from "@gray/json";
import { bytesToLowerHex, lowerHexBytes } from "@gray/attest";
import {
  RelayConnectorError,
  assertBundleSealable,
  assertCredentialFormat,
  parseCredentialPayload,
  payloadValue,
  randomBytes,
  VENDORS,
  type Credential,
  type CredentialRevoke,
  type Vendor,
} from "@gray/relay-connector";
import { bundleFromAccounts, parseAccountsValue, updateForToken } from "../accounts.ts";
import {
  DEFAULT_MAX_REPORT_AGE_SECONDS,
  DEFAULT_VERIFIED_REPORT_FILE,
  RELAY_KEY_FILE_NAME,
  RELAY_KIT_VERSION,
} from "../endpoints.ts";
import { exitCodeFor, isRelayKitError, RelayKitError } from "../errors.ts";
import { initPlaceholderNote } from "../init.ts";
import { generateRelayKey, relayKeyValue, type RelayKeyFile } from "../keys.ts";
import { APP_ID_PATTERN, KMS_CA_PUBKEY_PATTERN } from "../lane-binding.ts";
import { parseTemplatesValue, prepareAndSignPolicyBundle } from "../policy-bundle.ts";
import { sealCredentialBundleForReplicas, sealCredentialRevokeForReplicas, sealCredentialUpdateForReplicas, type SealedForReplica } from "../seal.ts";
import { classifyUpload } from "../upload.ts";
import {
  normalizeHttpsOrigin,
  verifiedReportValue,
  type CheckedVerifiedReport,
} from "../verified-report.ts";
import { attestLane, loadQuoteVerifier, loadReleaseList } from "./attest.ts";
import { ensureDirectory, readFileBytes, readFileText, readPrivateFile, warnLoosePermissions, writePrivateFile } from "./files.ts";
import { configArgumentFor, defaultConfigPath } from "./config-file.ts";
import { loadVerifiedReports } from "./reports.ts";
import { buildKeyFromText } from "./scheduler-load.ts";
import { startReferenceScheduler } from "./scheduler-server.ts";
import { uploadToLane } from "./upload.ts";

const U64_MAX = 0xffff_ffff_ffff_ffffn;
/**
 * Gray's release traffic window in hours (the console's RELAY_RELEASE_TRAFFIC_WINDOW_HOURS default, @gray/control
 * release-traffic.ts): a VM still on an older release gets no traffic from this long after a newer normal one is proposed.
 */
const RELEASE_TRAFFIC_WINDOW_HOURS = 72;
const MAX_KEY_BYTES = 64 * 1024;
const MAX_MODULE_BYTES = 8 * 1024 * 1024;
const MAX_TEMPLATES_BYTES = 4 * 1024 * 1024;
const MAX_ACCOUNTS_BYTES = 16 * 1024 * 1024;
const MAX_UPLOAD_BYTES = 16 * 1024 * 1024;

/** The injected streams and clock, so a test can run the CLI in-process when a subprocess is slow. */
export interface CliIo {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
  readonly now: () => number;
  readonly random: (length: number) => Uint8Array;
  /** A pause; `releases accept` waits with it for the agent's first sight. */
  readonly sleep: (ms: number) => Promise<void>;
  /** The process environment; `init --pair` reads `GRAY_ASSISTANT_IMAGE`, which the published image sets. */
  readonly env: Readonly<Record<string, string | undefined>>;
}

function defaultIo(): CliIo {
  return {
    stdout: (line) => process.stdout.write(line),
    stderr: (line) => process.stderr.write(line),
    now: () => Date.now(),
    random: (length) => randomBytes(length),
    sleep: (ms) => new Promise((done) => setTimeout(done, ms)),
    env: process.env,
  };
}

interface ParsedArgs {
  readonly positionals: readonly string[];
  /** The first value of every option; a repeatable option keeps all of them in `multiFlags`. */
  readonly flags: ReadonlyMap<string, string>;
  /** Every value of a repeatable option, in the order given (`--report`). */
  readonly multiFlags: ReadonlyMap<string, readonly string[]>;
  readonly help: boolean;
  readonly kitVersion: boolean;
}

/** Options that may be given more than once. */
const REPEATABLE_FLAGS: ReadonlySet<string> = new Set(["report", "accept-os-image"]);

/** Options that take no value. */
const BOOLEAN_FLAGS: ReadonlySet<string> = new Set([
  "json",
  "force",
  "no-wait",
  "relay",
  "allow-unpinned",
  "accept-unpinned",
  "accept-os-unpinned",
  "submit",
  "print",
]);

function parseArgs(argv: readonly string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags = new Map<string, string>();
  const multiFlags = new Map<string, string[]>();
  let help = false;
  let kitVersion = false;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] as string;
    if (arg === "--help" || arg === "-h") {
      help = true;
      continue;
    }
    // `--version` alone; with a command it is that command's option (`policy bundle --version <n>`).
    if (arg === "-V" || arg === "--kit-version" || (arg === "--version" && argv.length === 1)) {
      kitVersion = true;
      continue;
    }
    if (!arg.startsWith("--")) {
      positionals.push(arg);
      continue;
    }
    const equals = arg.indexOf("=");
    const name = equals < 0 ? arg.slice(2) : arg.slice(2, equals);
    if (name === "") throw new RelayKitError("usage", "an empty option name");
    if (BOOLEAN_FLAGS.has(name)) {
      if (equals >= 0) throw new RelayKitError("usage", `--${name} takes no value`);
      if (flags.has(name)) throw new RelayKitError("usage", `--${name} is given twice`);
      flags.set(name, "true");
      continue;
    }
    let value: string;
    if (equals >= 0) {
      value = arg.slice(equals + 1);
    } else {
      const next = argv[index + 1];
      if (next === undefined || next.startsWith("--")) throw new RelayKitError("usage", `--${name} needs a value`);
      value = next;
      index += 1;
    }
    if (flags.has(name) && !REPEATABLE_FLAGS.has(name)) throw new RelayKitError("usage", `--${name} is given twice`);
    if (!flags.has(name)) flags.set(name, value);
    if (REPEATABLE_FLAGS.has(name)) {
      const values = multiFlags.get(name) ?? [];
      values.push(value);
      multiFlags.set(name, values);
    }
  }
  return { positionals, flags, multiFlags, help, kitVersion };
}

function usage(): string {
  return [
    "usage: gray-assistant keygen --out <dir> [--key-id <id>] [--force]",
    "       gray-assistant attest <lane origin> (--allow <release-list.json> --release-key <64 hex> [--allow-freshness <file> --freshness-key <64 hex>] | --allow-unpinned [--accept-unpinned])",
    "                                     --app-id <40 hex> --kms-ca-pubkey <182 hex>",
    "                                     [--accept-os-unpinned] [--accept-os-image <hash> ...] [--out <verified-report.json>]",
    "                                     [--nonce <64 hex>] [--now <unix>] [--ca <pem>]",
    "                                     [--pccs <url>] [--verifier-module <module.mjs>]",
    "       gray-assistant policy bundle --module <module.wasm> --templates <templates.json>",
    "                              --version <n> --relay-id <id> --key <relay-key.json> --out <bundle.json>",
    "                              [--interpreter <wasm>] [--force]",
    "       gray-assistant credentials seal --report <verified-report.json> [--report <...>] [--reports <list.json>]",
    "                                 --accounts <accounts.json> [--version <n>] --relay-id <id> --key <relay-key.json>",
    "                                 --out <envelope.json|dir> [--issued-at <unix>] [--expires-at <unix>]",
    "                                 [--lifetime <seconds>] [--now <unix>] [--max-report-age <seconds>]",
    "                                 [--accept-unpinned] [--force]",
    "       gray-assistant credentials push-token --report <verified-report.json> [--report <...>] [--reports <list.json>]",
    "                                        --account <id> --token-file <file> --type <api_key|oauth_access_token>",
    "                                        [--version <n>] --relay-id <id> --key <relay-key.json>",
    "                                        [--vendor <vendor>] [--expires-at <unix>] [--out <envelope.json|dir>]",
    "                                        [--now <unix>] [--max-report-age <seconds>] [--accept-unpinned] [--force]",
    "       gray-assistant credentials revoke --report <verified-report.json> [--report <...>] [--reports <list.json>]",
    "                                   (--account <id> | --relay) [--version <n>] --relay-id <id> --key <relay-key.json>",
    "                                   --out <envelope.json|dir> [--now <unix>] [--max-report-age <seconds>]",
    "                                   [--accept-unpinned] [--force]",
    "       gray-assistant upload <lane origin> <file> [--report <verified-report.json>] [--reports <list.json>]",
    "                                  [--accept-unpinned] [--ca <pem>] [--max-report-age <seconds>]",
    "       gray-assistant scheduler --config <scheduler.json>",
    "       gray-assistant init --dir <dir> [--relay-id <id>] [--scheduler-url <url>] [--lane-origin <url>]",
    "                        [--release-list <url>] [--release-public-key <64 hex>] [--release-freshness-public-key <64 hex>]",
    "                        [--app-id <40 hex>] [--kms-ca-pubkey <182 hex>] [--force]",
    "       gray-assistant init --pair <code> --gray <api origin> --dir <dir> [--key <relay-key.json>] [--force]   (the code from the relay's Integration page)",
    "                        [--release-delay <hours>]   (phase 2: how long a Gray release waits for your veto, 0 to 168, default 24)",
    "                        [--registry-user <user> [--registry-expires-at <YYYY-MM-DDTHH:MM:SSZ>]] [--image <image@sha256:...>]   (the pull token's user, and its expiry when it has one; the image compose.yaml runs)",
    "       gray-assistant accounts [--config <config>]   (each account's panel id beside its source id)",
    "       gray-assistant deliver [--config <config>] [--no-wait] [--timeout <seconds>]   (phase 2: attest the VM, check the contract, seal the boot box and the accounts, restart when needed)",
    "       gray-assistant accounts push [--config <config>]   (phase 2: read the source once and seal the accounts to the VM)",
    "       gray-assistant registry set [--config <config>]   (phase 2: seal stack.registry's login anew, same designation)",
    "       gray-assistant source check [--config <config>]   (the http source's two routes against the standard; prints no key)",
    "       gray-assistant run [--config <config>] [--ca <pem>] [--verifier-module <module.mjs>]",
    "       gray-assistant doctor [--config <config>] [--ca <pem>] [--verifier-module <module.mjs>] [--now <unix>]",
    "       gray-assistant status [--config <config>]",
    "       gray-assistant pause|resume [--config <config>]",
    "       gray-assistant releases [--config <config>]   (Gray's releases and OS images, each accepted, rejected or pending)",
    "       gray-assistant releases accept <id> [--config <config>] [--no-wait] [--timeout <seconds>]   (waits for the agent's first sight)",
    "       gray-assistant releases reject|unreject <hash> [--config <config>]   (a compose hash or an OS image hash)",
    "       gray-assistant releases list [--from-block <n>] [--config <config>]   (phase 2: each release proposed on the relay's contract)",
    "       gray-assistant releases check <hash> [--kind compose|os_image] [--config <config>]   (its state on the contract, read from both RPCs, and its compose or OS image texts from Gray's signed list, checked here)",
    "       gray-assistant releases approve|reject <hash> [--kind compose|os_image] [--deadline <unix>] [--nonce <n>]",
    "                                          [--submit --rpc <url> | --print] [--config <config>]   (phase 2: the guardian's signed approval or veto;",
    "                                          Gray's relayer sends it by default, --submit from the guardian key, --print only signs)",
    "       gray-assistant releases delay <hours> [--force] [--deadline <unix>] [--nonce <n>] [--submit --rpc <url> | --print] [--config <config>]",
    "                                          (phase 2: your release delay, 0 to 168 h, signed by the guardian and sent as approve is; --force when",
    "                                          lengthening it would stop a release that is effective by time alone)",
    "       gray-assistant keys set-guardian|set-recovery <address> --key <recovery-key.json> [--deadline <unix>] [--nonce <n>]",
    "                                          [--submit --rpc <url> | --print] [--config <config>]   (phase 2: the recovery key replaces a key)",
    "       gray-assistant pause|unpause [--deadline <unix>] [--nonce <n>] [--submit --rpc <url> | --print] [--config <config>]",
    "                                    (phase 2, a config with `chain`: the contract's off switch, signed by the guardian)",
    "       gray-assistant stack rollout <image> [--config <config>] [--no-wait] [--timeout <seconds>]   (one of stack.relay_images)",
    "       gray-assistant stack rollback|restart [--config <config>] [--no-wait] [--timeout <seconds>]",
    "                                    (phase 2, a config with `chain`: rollout and rollback seal a new designation, then restart the VM;",
    "                                     restart waits for the new boot's own attestation)",
    "       gray-assistant stack status [--config <config>]",
    "       gray-assistant debug get <request id> [--out <file>] [--config <config>]   (a request's record the customer authorized; the VM holds it 24 h)",
    "       gray-assistant login <account> [--config <config>]   (signs a subscription account in inside the VM, by your software there)",
    "       gray-assistant ui [--config <config>] [--port <n>] [--host <address>] [--ca <pem>] [--verifier-module <module.mjs>]",
    "                                    (the local page, on 127.0.0.1; in the kit's container --host 0.0.0.0, published on the host's 127.0.0.1 only)",
    "       gray-assistant ui link [--config <config>] [--port <n>]   (a one-time sign-in link for the local page)",
    "       gray-assistant ui enroll [--config <config>] [--origin <https origin>]   (a one-time link that adds a passkey, ui.public)",
    "       gray-assistant ui passkeys list | revoke <id> [--config <config>]",
    "       gray-assistant tunnel status [--config <config>]   (the relay tunnel, its certificate and the CT monitor)",
    "       gray-assistant tunnel ack <cert or key sha256> [--config <config>]   (a CT finding the operator has explained)",
    "       gray-assistant config set <member> <value> [--json] [--config <config>]   (one member; restart the agent after)",
    "       gray-assistant config unset <member> [--config <config>]",
    "       gray-assistant upgrade --dir <kit dir> [--image <image@sha256:...>]   (a kit of any earlier version, of the old name too, to this one;",
    "                                    run from the newest image: docker run --rm -v \"$PWD:/work\" <image> upgrade --dir /work)",
    "       gray-assistant --version   (this build: the kit version and its commit)",
    "       gray-assistant policy test --bundle <bundle.json> --fixtures <fixtures.jsonl>",
    "                                 (--key <relay-key.json> | --public-key <64 hex>) [--interpreter <wasm>]",
    "",
    "credentials seal|push-token|revoke without --version use the clock in Unix ms as the version and print it",
    "--config defaults to $GRAY_ASSISTANT_CONFIG, else /etc/gray-assistant/gray-assistant.jsonc when it exists, else ./gray-assistant.jsonc",
    "exit codes: 0 ok, 1 refused or failed, 2 usage/IO",
    "",
  ].join("\n");
}

const USAGE_ENTRY = /^(?:usage: | {7})gray-assistant (\S+)(?: (\S+))?/;

/**
 * `gray-assistant <command> [<sub>] --help`: only that command's entries of `usage()` (each with its continuation lines),
 * narrowed to the subcommand when one matches, and the footer lines they need. Null for a command the list does not name.
 */
export function commandUsage(command: string, sub: string | undefined): string | null {
  const lines = usage().split("\n");
  const entries: { words: [string[], string[]]; lines: string[] }[] = [];
  for (const line of lines) {
    const start = USAGE_ENTRY.exec(line);
    if (start) entries.push({ words: [start[1]!.split("|"), /^[a-z]/.test(start[2] ?? "") ? start[2]!.split("|") : []], lines: [line] });
    else if (line.startsWith(" ") && entries.length > 0) entries[entries.length - 1]!.lines.push(line);
    else if (line === "") break;
  }
  const ofCommand = entries.filter((e) => e.words[0].includes(command));
  if (ofCommand.length === 0) return null;
  const ofSub = sub === undefined ? [] : ofCommand.filter((e) => e.words[1].includes(sub));
  const chosen = (ofSub.length > 0 ? ofSub : ofCommand).flatMap((e) => e.lines);
  chosen[0] = `usage: ${chosen[0]!.slice(7)}`;
  const footer = lines.filter((l) => l.startsWith("exit codes:") || (l.startsWith("--config defaults") && chosen.some((c) => c.includes("--config"))));
  return [...chosen, "", ...footer, ""].join("\n");
}

/** Run one command line; returns the process exit code. */
export async function runCli(argv: readonly string[], io: Partial<CliIo> = {}): Promise<number> {
  const out = { ...defaultIo(), ...io };
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (error) {
    if (isRelayKitError(error)) {
      out.stderr(`gray-assistant: ${error.message}\n${usage()}`);
      return exitCodeFor(error);
    }
    out.stderr("gray-assistant: internal error\n");
    return 1;
  }
  if (args.help) {
    const [command, sub] = args.positionals;
    out.stdout((command === undefined ? null : commandUsage(command, sub)) ?? usage());
    return 0;
  }
  if (args.kitVersion) {
    out.stdout(`${RELAY_KIT_VERSION}\n`);
    return 0;
  }
  if (args.positionals.length === 0) {
    out.stdout(usage());
    return 2;
  }
  try {
    return await dispatch(args, out);
  } catch (error) {
    if (isRelayKitError(error)) {
      out.stderr(`gray-assistant: ${error.message}\n`);
      return exitCodeFor(error);
    }
    if (error instanceof RelayConnectorError) {
      out.stderr(`gray-assistant: relay-connector/${error.code}${error.path === null ? "" : `: ${error.path}`}\n`);
      return 1;
    }
    out.stderr("gray-assistant: internal error\n");
    return 1;
  }
}

async function dispatch(args: ParsedArgs, io: CliIo): Promise<number> {
  const command = args.positionals[0];
  if (command === "keygen") return keygen(args, io);
  if (command === "attest") return attest(args, io);
  if (command === "policy") return policy(args, io);
  if (command === "credentials") return credentials(args, io);
  if (command === "upload") return upload(args, io);
  if (command === "scheduler") return scheduler(args, io);
  if (command === "init") return initCommand(args, io);
  if (command === "accounts") return args.positionals[1] === "push" ? deliverCli(args, io, "accounts", null) : accountsCommand(args, io);
  if (command === "deliver") return deliverCli(args, io, "deliver", null);
  if (command === "registry") {
    if (args.positionals[1] !== "set") throw new RelayKitError("usage", "registry needs the `set` subcommand: gray-assistant registry set [--config <config>]");
    return deliverCli(args, io, "registry", null);
  }
  if (command === "source") return sourceCommand(args, io);
  if (command === "run") return runCommand(args, io);
  if (command === "doctor") return doctorCommand(args, io);
  if (command === "upgrade") return upgradeCommand(args, io);
  if (command === "status") return statusCommand(args, io);
  if (command === "pause" || command === "resume") {
    // Phase 2: with a `chain` member, `pause` is the contract's off switch; `resume` stays the agent's.
    if (command === "pause") {
      const chain = await chainContextOf(args, true);
      if (chain !== null) return chainSwitchCommand(args, io, "pause", chain);
    }
    return pauseCommand(args, io, command === "pause");
  }
  if (command === "unpause") return chainSwitchCommand(args, io, "unpause", await requireChainContext(args, "unpause"));
  if (command === "releases") return releasesCommand(args, io);
  if (command === "keys") return keysCommand(args, io);
  if (command === "stack") return stackCommand(args, io);
  if (command === "debug") return debugCommand(args, io);
  if (command === "login") return loginCommand(args, io);
  if (command === "ui") return uiCommand(args, io);
  if (command === "tunnel") return tunnelCommand(args, io);
  if (command === "config") return configCommand(args, io);
  io.stderr(`gray-assistant: unknown command ${JSON.stringify(command)}\n${usage()}`);
  return 2;
}

// ---------------------------------------------------------------------------------------------
// upgrade
// ---------------------------------------------------------------------------------------------

/** `upgrade --dir <kit>` (./upgrade.ts): the kit directory of any earlier kit moved to this one's names and image. */
async function upgradeCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["dir", "image"]);
  assertPositionals(args, 1);
  const { upgradeWorkspace } = await import("./upgrade.ts");
  const image = (args.flags.get("image") ?? io.env["GRAY_ASSISTANT_IMAGE"] ?? "").trim();
  const result = upgradeWorkspace({ directory: requiredFlag(args, "dir"), image: image === "" ? null : image, version: RELAY_KIT_VERSION.split("+")[0] as string });
  io.stdout(`gray-assistant upgrade: relay ${result.relayId}, ${result.found} in ${result.directory}, to kit ${RELAY_KIT_VERSION}\n`);
  for (const file of result.written) io.stdout(`wrote ${file}\n`);
  for (const file of result.backups) io.stdout(`kept the previous file as ${file}\n`);
  for (const member of result.members) io.stdout(`renamed the old path in ${member}\n`);
  for (const note of result.notes) io.stdout(`note: ${note}\n`);
  if (result.written.length === 0) io.stdout("nothing to change: the kit is already this version's\n");
  // Phase 2: nothing runs on the host, so the next step is a check; the next `deliver` or `accounts push` reports the new
  // version to Gray. A relay paired before phase 2 (no `chain`) still restarts its always-on agent (the console guide §10).
  const next = result.project === null ? [] : ["docker compose run --rm --no-deps agent --version", "docker compose run --rm --no-deps agent doctor"];
  for (const line of next) io.stdout(`next, in the kit directory: ${line}\n`);
  if (result.project !== null) io.stdout("note: a relay paired before phase 2 (its config has no chain) restarts its agent instead: docker compose up -d\n");
  printJson(io, {
    command: "upgrade",
    relay_id: result.relayId,
    kit: RELAY_KIT_VERSION,
    found: result.found,
    changed: result.written.length > 0,
    written: [...result.written],
    backups: [...result.backups],
    members: [...result.members],
    project: result.project,
    notes: [...result.notes],
    next,
  });
  return 0;
}

// ---------------------------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------------------------

/** `config set <member> <value> [--json]` and `config unset <member>`: one member, written by `./config-edit.ts`. */
async function configCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  const sub = args.positionals[1];
  if (sub !== "set" && sub !== "unset") throw new RelayKitError("usage", "config takes set <member> <value> or unset <member>");
  assertFlags(args, sub === "set" ? ["config", "json"] : ["config"]);
  assertPositionals(args, sub === "set" ? 4 : 3);
  const member = args.positionals[2] as string;
  let value: unknown;
  if (sub === "set") {
    const text = args.positionals[3] as string;
    if (args.flags.has("json")) {
      try {
        value = parsePlain(text);
      } catch {
        throw new RelayKitError("usage", "with --json the value must be JSON (a string in double quotes, a number, true, false, an array or an object)");
      }
    } else {
      value = text;
    }
  }
  const { editRelayConfig } = await import("./config-edit.ts");
  const result = editRelayConfig(configPathOf(args), member, value);
  if (!result.changed) {
    io.stdout(`gray-assistant config: ${member} is not in ${result.path}; nothing changed\n`);
  } else {
    io.stdout(`gray-assistant config: ${sub === "set" ? "set" : "removed"} ${member} in ${result.path}\n`);
    // Phase 2: every command reads the config when it starts. The config is mounted read-only in the agent's compose, so
    // the write itself runs with the kit mounted writable (writeRefusal names the same form).
    io.stdout(
      "Each gray-assistant command reads the config when it starts: the next one uses the change. From the kit's directory, " +
        'config set runs as: docker compose run --rm --no-deps -v "$PWD:/work" agent config set --config /work/gray-assistant.jsonc <member> <value>. ' +
        "A relay paired before phase 2 (its config has no chain) restarts its agent: docker compose up -d --force-recreate agent.\n",
    );
  }
  printJson(io, { command: "config", action: sub, member, config: result.path, changed: result.changed, restart_needed: result.changed });
  return 0;
}

// ---------------------------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------------------------

async function keygen(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["out", "key-id", "force"]);
  assertPositionals(args, 1);
  const out = requiredFlag(args, "out");
  ensureDirectory(out);
  const path = join(out, RELAY_KEY_FILE_NAME);
  const key = await generateRelayKey(args.flags.get("key-id"));
  writePrivateFile(path, `${toJsonString(relayKeyValue(key))}\n`, { force: args.flags.has("force") });
  io.stdout(`gray-assistant keygen: wrote ${path} (mode 0600)\n`);
  io.stdout(`key_id ${key.keyId}\n`);
  io.stdout(`public_key ${toHex(key.publicKey)}\n`);
  printJson(io, { command: "keygen", key_id: key.keyId, public_key: toHex(key.publicKey), key_file: path });
  return 0;
}

// ---------------------------------------------------------------------------------------------
// attest
// ---------------------------------------------------------------------------------------------

async function attest(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, [
    "allow",
    "allow-unpinned",
    "accept-unpinned",
    "accept-os-unpinned",
    "accept-os-image",
    "release-key",
    "allow-freshness",
    "freshness-key",
    "app-id",
    "kms-ca-pubkey",
    "out",
    "nonce",
    "now",
    "ca",
    "pccs",
    "verifier-module",
  ]);
  assertPositionals(args, 2);
  const allowPath = args.flags.get("allow") ?? null;
  const allowUnpinned = args.flags.has("allow-unpinned");
  const acceptUnpinned = args.flags.has("accept-unpinned");
  const acceptOsUnpinned = args.flags.has("accept-os-unpinned");
  const releaseKeyText = args.flags.get("release-key");
  const releaseKey = releaseKeyText === undefined ? null : lowerHexBytes(releaseKeyText);
  if (releaseKeyText !== undefined && (releaseKey === null || releaseKey.length !== 32)) {
    throw new RelayKitError("usage", "--release-key must be 32 bytes as 64 lower-case hex digits");
  }
  if (allowPath !== null && allowUnpinned) throw new RelayKitError("usage", "pass --allow or --allow-unpinned, not both");
  if (acceptUnpinned && !allowUnpinned) throw new RelayKitError("usage", "--accept-unpinned is only meaningful with --allow-unpinned");
  if (acceptOsUnpinned && allowPath === null) throw new RelayKitError("usage", "--accept-os-unpinned is only meaningful with --allow");
  if (releaseKey !== null && allowPath === null) throw new RelayKitError("usage", "--release-key is only meaningful with --allow");
  // D138: the list's freshness document and Gray's freshness key, both or neither, as gray-lane-verify takes them.
  const freshnessPath = args.flags.get("allow-freshness") ?? null;
  const freshnessKeyText = args.flags.get("freshness-key");
  const freshnessKey = freshnessKeyText === undefined ? null : lowerHexBytes(freshnessKeyText);
  if (freshnessKeyText !== undefined && (freshnessKey === null || freshnessKey.length !== 32)) {
    throw new RelayKitError("usage", "--freshness-key must be 32 bytes as 64 lower-case hex digits");
  }
  if ((freshnessPath === null) !== (freshnessKey === null)) {
    throw new RelayKitError("usage", "--allow-freshness and --freshness-key go together: the document Gray publishes beside the list and its freshness public key");
  }
  if (freshnessPath !== null && allowPath === null) throw new RelayKitError("usage", "--allow-freshness is only meaningful with --allow");
  // S11b: an OS image whose entry does not prove it production is taken only when named here.
  const acceptedOsImages = [...(args.multiFlags.get("accept-os-image") ?? [])];
  if (acceptedOsImages.some((hash) => !/^[0-9a-f]{64}$/.test(hash))) throw new RelayKitError("usage", "--accept-os-image takes an OS image hash: 64 lower-case hex digits");
  if (acceptedOsImages.length > 0 && allowPath === null) throw new RelayKitError("usage", "--accept-os-image is only meaningful with --allow");
  const origin = normalizeHttpsOrigin(args.positionals[1] as string);
  const nonce = args.flags.get("nonce") ?? toHex(io.random(32));
  if (!/^[0-9a-f]{64}$/.test(nonce)) throw new RelayKitError("usage", "--nonce must be 32 bytes as 64 lower-case hex digits");
  const nowSecs = args.flags.has("now") ? parseU64(args.flags.get("now") as string, "--now") : BigInt(Math.floor(io.now() / 1000));
  if (allowPath !== null && releaseKey === null) {
    throw new RelayKitError("usage", "attest --allow needs --release-key <64 hex>: the release-signing key Gray publishes");
  }
  // S12: the instance is always pinned, also with --allow-unpinned; there is no flag to skip it.
  const expectedInstance = { appId: requiredFlag(args, "app-id"), kmsCaPubkey: requiredFlag(args, "kms-ca-pubkey") };
  if (!APP_ID_PATTERN.test(expectedInstance.appId)) {
    throw new RelayKitError("usage", "--app-id must be the lane's dstack app id: 20 bytes as 40 lower-case hex digits");
  }
  if (!KMS_CA_PUBKEY_PATTERN.test(expectedInstance.kmsCaPubkey)) {
    throw new RelayKitError("usage", "--kms-ca-pubkey must be the node KMS's ca_pubkey: a P-256 SPKI, 182 lower-case hex digits");
  }
  const release = allowPath === null
    ? null
    : await loadReleaseList(allowPath, releaseKey as Uint8Array, nowSecs, freshnessPath === null || freshnessKey === null ? null : { path: freshnessPath, publicKey: freshnessKey });
  const ca = args.flags.has("ca") ? readFileText(args.flags.get("ca") as string, "CA certificate", 1024 * 1024) : undefined;
  const quoteVerifier = await loadQuoteVerifier({
    ...(args.flags.has("verifier-module") ? { verifierModule: args.flags.get("verifier-module") as string } : {}),
    ...(args.flags.has("pccs") ? { pccs: args.flags.get("pccs") as string } : {}),
  });
  const result = await attestLane({
    origin,
    release,
    allowUnpinned,
    acceptUnpinned,
    acceptOsUnpinned,
    nonce,
    nowSecs,
    ...(ca === undefined ? {} : { ca }),
    quoteVerifier,
    expectedInstance,
    osImageAcceptance: { acceptedOsImages },
  });
  io.stdout(`gray-assistant attest ${origin}\n`);
  io.stdout(`nonce ${nonce}\n`);
  if (result.stage === "report") {
    io.stderr(`gray-assistant: attestation_failed: the lane did not serve an ACI report\n`);
    printJson(io, { command: "attest", ok: false, origin, nonce });
    return 1;
  }
  for (const check of result.verification.checks) io.stdout(`${check.status.toUpperCase().padEnd(4)} ${check.id}: ${check.detail}\n`);
  if (result.stage === "verification") {
    io.stdout(`VERDICT: FAIL\n`);
    printJson(io, { command: "attest", ok: false, origin, nonce });
    return 1;
  }
  if (result.stage === "pinning") {
    io.stdout(`VERDICT: ${result.verdict}\n`);
    printJson(io, { command: "attest", ok: false, origin, nonce, verdict: result.verdict });
    return 1;
  }
  const out = args.flags.get("out") ?? DEFAULT_VERIFIED_REPORT_FILE;
  writePrivateFile(out, `${toJsonString(verifiedReportValue(result.file))}\n`, { force: true });
  io.stdout(`VERDICT: ${result.verdict}\n`);
  io.stdout(`wrote ${out}\n`);
  printJson(io, {
    command: "attest",
    ok: true,
    origin,
    nonce,
    pinned: result.verification.pinned,
    keyset_digest: result.file.verification.keysetDigest,
    report_data: result.file.verification.reportData,
    compose_hash: result.file.verification.composeHash,
    os_image_hash: result.file.verification.osImageHash,
    tls_spki_sha256: result.file.verification.tlsSpkiSha256,
    file: out,
  });
  return 0;
}

// ---------------------------------------------------------------------------------------------
// policy bundle
// ---------------------------------------------------------------------------------------------

async function policy(args: ParsedArgs, io: CliIo): Promise<number> {
  if (args.positionals[1] === "test") return policyTestCommand(args, io);
  if (args.positionals[1] !== "bundle") throw new RelayKitError("usage", "policy needs the `bundle` or `test` subcommand");
  assertFlags(args, ["module", "templates", "version", "relay-id", "key", "out", "interpreter", "force"]);
  assertPositionals(args, 2);
  const relayId = requiredFlag(args, "relay-id");
  const version = parseU64(requiredFlag(args, "version"), "--version");
  const key = await loadKey(requiredFlag(args, "key"));
  const moduleBytes = readFileBytes(requiredFlag(args, "module"), "policy module", MAX_MODULE_BYTES);
  const templates = loadTemplates(requiredFlag(args, "templates"));
  const { initWorkspaceInterpreter } = await import("./interpreter.ts");
  initWorkspaceInterpreter(args.flags.get("interpreter"));
  // The library runs the TEE's own upload check, signs the claim and self-checks the signature, so
  // a bundle the TEE would refuse never gets a signature here either.
  const prepared = await prepareAndSignPolicyBundle({ relayId, version, moduleBytes, templates, signingKey: key.seed });
  if (!prepared.ok) {
    io.stderr(`gray-assistant: policy_refused ${prepared.code}: ${prepared.detail}\n`);
    return 1;
  }
  const out = requiredFlag(args, "out");
  writePrivateFile(out, `${toJsonString(prepared.document)}\n`, { force: args.flags.has("force") });
  io.stdout(`gray-assistant policy bundle: ${relayId} version ${version}\n`);
  io.stdout(`module_sha256 ${prepared.claim.module_sha256}\n`);
  io.stdout(`templates_sha256 ${prepared.claim.templates_sha256}\n`);
  io.stdout(`wrote ${out}\n`);
  printJson(io, {
    command: "policy.bundle",
    relay_id: relayId,
    version,
    module_sha256: prepared.claim.module_sha256,
    templates_sha256: prepared.claim.templates_sha256,
    signature: toHex(prepared.bundle.signature),
    file: out,
  });
  return 0;
}

// ---------------------------------------------------------------------------------------------
// credentials
// ---------------------------------------------------------------------------------------------

async function credentials(args: ParsedArgs, io: CliIo): Promise<number> {
  const sub = args.positionals[1];
  if (sub === "seal") return sealCredentials(args, io);
  if (sub === "push-token") return pushToken(args, io);
  if (sub === "revoke") return revokeCredentials(args, io);
  throw new RelayKitError("usage", "credentials needs the `seal`, `push-token` or `revoke` subcommand");
}

async function sealCredentials(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["report", "reports", "accounts", "version", "relay-id", "key", "out", "issued-at", "expires-at", "lifetime", "now", "max-report-age", "accept-unpinned", "force"]);
  assertPositionals(args, 2);
  const nowSecs = nowSecsFrom(args, io);
  const maxAge = maxReportAgeFrom(args);
  const key = await loadKey(requiredFlag(args, "key"));
  const reports = loadReportFiles(args, nowSecs, maxAge, { acceptUnpinned: args.flags.has("accept-unpinned") });
  const accountsPath = requiredFlag(args, "accounts");
  // The accounts file holds the pool's credentials, so it follows the private-file rule (K4-3), the
  // same one the daemon's `file` source applies: a symlink or a group/other-readable file is refused.
  const accountsText = readPrivateFile(accountsPath, "accounts file", MAX_ACCOUNTS_BYTES);
  const accounts = parseJsonOr(accountsText, "invalid_accounts", () => parseAccountsValue(parseStrict(accountsText)));
  const relayId = args.flags.get("relay-id") ?? accounts.relayId;
  if (relayId !== accounts.relayId) throw new RelayKitError("invalid_accounts", "the accounts file names another relay");
  const { version, chosen } = credentialVersionFrom(args, io, "a credential bundle's version starts at 1");
  const issuedAt = args.flags.has("issued-at") ? parseU64(args.flags.get("issued-at") as string, "--issued-at") : (accounts.issuedAt ?? nowSecs);
  const lifetime = args.flags.has("lifetime") ? parsePositiveInt(args.flags.get("lifetime") as string, "--lifetime") : 3600n;
  const expiresAt = args.flags.has("expires-at") ? parseU64(args.flags.get("expires-at") as string, "--expires-at") : (accounts.expiresAt ?? issuedAt + lifetime);
  if (expiresAt <= issuedAt) throw new RelayKitError("invalid_accounts", "expires_at must be after issued_at");
  const bundle = bundleFromAccounts(accounts, { version, issuedAt, expiresAt });
  assertBundleSealable(bundle, nowSecs);
  const sealed = await sealCredentialBundleForReplicas({ reports, signingKey: key.seed, bundle, nowSecs });
  io.stdout(`gray-assistant credentials seal: ${relayId} ${versionText(version, chosen)}, ${bundle.accounts.length} account(s), ${sealed.length} replica(s)\n`);
  io.stdout(`issued_at ${issuedAt} expires_at ${expiresAt}\n`);
  writeSealed(args, io, {
    command: "credentials.seal",
    relayId,
    version,
    versionChosen: chosen,
    accounts: BigInt(bundle.accounts.length),
    relayKeyId: key.keyId,
    sealed,
    requireOut: true,
    extra: { issued_at: issuedAt, expires_at: expiresAt },
  });
  return 0;
}

async function pushToken(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["report", "reports", "account", "token-file", "type", "vendor", "version", "relay-id", "key", "expires-at", "out", "now", "max-report-age", "accept-unpinned", "force"]);
  assertPositionals(args, 2);
  const nowSecs = nowSecsFrom(args, io);
  const maxAge = maxReportAgeFrom(args);
  const key = await loadKey(requiredFlag(args, "key"));
  const reports = loadReportFiles(args, nowSecs, maxAge, { acceptUnpinned: args.flags.has("accept-unpinned") });
  const relayId = requiredFlag(args, "relay-id");
  const accountId = requiredFlag(args, "account");
  const tokenPath = requiredFlag(args, "token-file");
  const type = requiredFlag(args, "type");
  if (type !== "api_key" && type !== "oauth_access_token") throw new RelayKitError("usage", "--type is api_key or oauth_access_token");
  warnLoosePermissions(tokenPath, "token file", io.stderr);
  const token = readToken(tokenPath);
  const expiresAt = args.flags.has("expires-at") ? parseU64(args.flags.get("expires-at") as string, "--expires-at") : undefined;
  const credential: Credential & { readonly type: "api_key" | "oauth_access_token" } = { type, value: token, ...(expiresAt === undefined ? {} : { expires_at: expiresAt }) };
  if (args.flags.has("vendor")) {
    const vendor = args.flags.get("vendor") as string;
    if (!(VENDORS as readonly string[]).includes(vendor)) throw new RelayKitError("usage", `--vendor is one of ${VENDORS.join(", ")}`);
    try {
      assertCredentialFormat(vendor as Vendor, credential);
    } catch {
      throw new RelayKitError("invalid_token", "the token does not match the vendor's format class");
    }
  }
  const { version, chosen } = credentialVersionFrom(args, io, "a credential update's version starts at 1");
  const update = updateForToken({ relayId, version, accountId, credential });
  const sealed = await sealCredentialUpdateForReplicas({ reports, signingKey: key.seed, update, nowSecs });
  const summary = `gray-assistant credentials push-token: ${accountId} ${versionText(version, chosen)}, ${sealed.length} replica(s)\n`;
  // Without --out stdout carries only the envelopes; a version the command chose is still said, on stderr.
  if (args.flags.has("out")) io.stdout(summary);
  else if (chosen) io.stderr(summary);
  writeSealed(args, io, {
    command: "credentials.push-token",
    relayId,
    version,
    versionChosen: chosen,
    relayKeyId: key.keyId,
    sealed,
    requireOut: false,
  });
  return 0;
}

async function revokeCredentials(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["report", "reports", "account", "relay", "version", "relay-id", "key", "out", "now", "max-report-age", "accept-unpinned", "force"]);
  assertPositionals(args, 2);
  if (args.flags.has("relay") === args.flags.has("account")) {
    throw new RelayKitError("usage", "credentials revoke needs exactly one of --account <id> or --relay");
  }
  const nowSecs = nowSecsFrom(args, io);
  const key = await loadKey(requiredFlag(args, "key"));
  const reports = loadReportFiles(args, nowSecs, maxReportAgeFrom(args), { acceptUnpinned: args.flags.has("accept-unpinned") });
  const relayId = requiredFlag(args, "relay-id");
  const { version, chosen } = credentialVersionFrom(args, io, "a revocation's version starts at 1");
  const revocation: CredentialRevoke = args.flags.has("relay")
    ? { relay_id: relayId, version, revoke: "relay" }
    : { relay_id: relayId, version, revoke: "account", account_id: requiredFlag(args, "account") };
  // The same wire rules the TEE applies, checked before the message is signed.
  parseCredentialPayload(payloadValue(revocation));
  const sealed = await sealCredentialRevokeForReplicas({ reports, signingKey: key.seed, revoke: revocation, nowSecs });
  io.stdout(`gray-assistant credentials revoke: ${relayId} ${versionText(version, chosen)}, ${revocation.revoke === "relay" ? "whole relay" : revocation.account_id}, ${sealed.length} replica(s)\n`);
  writeSealed(args, io, {
    command: "credentials.revoke",
    relayId,
    version,
    versionChosen: chosen,
    relayKeyId: key.keyId,
    sealed,
    requireOut: true,
  });
  return 0;
}

// ---------------------------------------------------------------------------------------------
// upload
// ---------------------------------------------------------------------------------------------

async function upload(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["report", "reports", "accept-unpinned", "ca", "max-report-age"]);
  assertPositionals(args, 3);
  const origin = normalizeHttpsOrigin(args.positionals[1] as string);
  const path = args.positionals[2] as string;
  const bytes = readFileBytes(path, "upload file", MAX_UPLOAD_BYTES);
  const document = parseJsonOr(toText(bytes), "unsupported_document", () => classifyUpload(parseStrict(toText(bytes))));
  const hasReport = args.flags.has("report") || args.flags.has("reports");
  if (document.kind === "policy_bundle" && !hasReport) {
    throw new RelayKitError("usage", "a policy bundle upload needs --report: it is the relay's closed module");
  }
  let reports: readonly CheckedVerifiedReport[] = [];
  if (hasReport) {
    const nowSecs = BigInt(Math.floor(io.now() / 1000));
    reports = loadReportFiles(args, nowSecs, maxReportAgeFrom(args), { origin, acceptUnpinned: args.flags.has("accept-unpinned") });
  } else {
    io.stderr("warning: uploading without --report; the lane origin was not checked against an attestation\n");
  }
  // Pin the TLS peer to the report's verified SPKI: the check runs inside TLS validation, before a
  // byte of the body is sent, so a substituted or transparent endpoint with a merely WebPKI-valid
  // certificate never receives the closed module. With multiple reports their origins must match,
  // but an SPKI change between attest and upload is a hard refusal, not a pick-any.
  const pinnedSpki = reports.length === 1 ? reports[0]?.file.verification.tlsSpkiSha256 ?? null : null;
  if (reports.length === 1 && pinnedSpki === null) {
    throw new RelayKitError("report_unverified", "the verified report recorded no TLS SPKI");
  }
  const ca = args.flags.has("ca") ? readFileText(args.flags.get("ca") as string, "CA certificate", 1024 * 1024) : undefined;
  const response = await uploadToLane({
    origin,
    path: document.path,
    body: bytes,
    ...(pinnedSpki === null ? {} : { pinnedSpkiSha256: pinnedSpki }),
    ...(ca === undefined ? {} : { ca }),
  });
  const ok = response.ok;
  io.stdout(`gray-assistant upload ${document.kind} -> ${origin}${document.path}\n`);
  io.stdout(`status ${response.status}\n`);
  if (response.body.length > 0 && response.body.length <= 2048) {
    try {
      io.stdout(`${new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(response.body)}\n`);
    } catch {
      // A non-text answer is not printed.
    }
  }
  printJson(io, { command: "upload", ok, status: BigInt(response.status), kind: document.kind, endpoint: document.path, relay_id: document.relayId });
  return ok ? 0 : 1;
}

// ---------------------------------------------------------------------------------------------
// scheduler
// ---------------------------------------------------------------------------------------------

async function scheduler(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["config"]);
  assertPositionals(args, 1);
  // The signal handlers exist before the address is printed: a supervisor that stops the process as
  // soon as it reads the line must find a handler, not the default terminate action.
  const stopped = new Promise<void>((resolve) => {
    const stop = (): void => resolve();
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  const started = await startReferenceScheduler({ configPath: requiredFlag(args, "config"), now: io.now, warn: io.stderr });
  io.stdout(`gray-assistant scheduler: listening on ${started.url}\n`);
  io.stdout(`relay_id ${started.config.relayId}\n`);
  io.stdout(`keyset_digest ${started.keysetDigest}\n`);
  io.stdout(`relay_public_key ${started.relayPublicKeyHex}\n`);
  io.stdout(`accounts ${started.config.accounts.length}\n`);
  await stopped;
  await started.close();
  return 0;
}


// ---------------------------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------------------------

async function initCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  if (args.flags.has("pair")) return initPairCommand(args, io);
  assertFlags(args, ["dir", "relay-id", "scheduler-url", "lane-origin", "release-list", "release-public-key", "release-freshness-public-key", "app-id", "kms-ca-pubkey", "force"]);
  assertPositionals(args, 1);
  const { initSummary, initWorkspace } = await import("./init.ts");
  const result = await initWorkspace({
    directory: requiredFlag(args, "dir"),
    ...(args.flags.has("relay-id") ? { relayId: args.flags.get("relay-id") as string } : {}),
    ...(args.flags.has("scheduler-url") ? { schedulerUrl: args.flags.get("scheduler-url") as string } : {}),
    ...(args.flags.has("lane-origin") ? { laneOrigin: args.flags.get("lane-origin") as string } : {}),
    ...(args.flags.has("release-list") ? { releaseListUrl: args.flags.get("release-list") as string } : {}),
    ...(args.flags.has("release-public-key") ? { releasePublicKey: args.flags.get("release-public-key") as string } : {}),
    ...(args.flags.has("release-freshness-public-key") ? { releaseFreshnessPublicKey: args.flags.get("release-freshness-public-key") as string } : {}),
    ...(args.flags.has("app-id") ? { appId: args.flags.get("app-id") as string } : {}),
    ...(args.flags.has("kms-ca-pubkey") ? { kmsCaPubkey: args.flags.get("kms-ca-pubkey") as string } : {}),
    ...(args.flags.has("force") ? { force: true } : {}),
  });
  io.stdout(`gray-assistant init: wrote the relay workspace in ${result.directory}\n`);
  io.stdout(`relay_id ${result.relayId}\n`);
  io.stdout(`public_key ${result.publicKeyHex}\n`);
  for (const file of result.files) io.stdout(`wrote ${file}\n`);
  const placeholderNote = initPlaceholderNote(result.placeholders);
  if (placeholderNote !== null) io.stdout(`${placeholderNote}\n`);
  io.stdout("next: fill relay_id, scheduler.public_url, lane.origins, lane.release_list and lane.release_public_key\n");
  io.stdout("      write accounts.json (0600), then run `gray-assistant doctor --config <dir>/gray-assistant.jsonc`\n");
  io.stdout("      replace lane.example and scheduler.example only after Gray sends the registration values\n");
  printJson(io, initSummary(result) as JsonObject);
  return 0;
}

/** `GRAY_ASSISTANT_HOST_DIR`: the kit directory's path on the host, when it is an absolute path of printable characters. */
function hostKitDir(value: string | undefined): string | null {
  if (value === undefined) return null;
  const path = value.replace(/\/+$/, "");
  return path.startsWith("/") && /^[\x20-\x7e]{2,4096}$/.test(path) ? path : null;
}

/** `init --pair` (S57): pair a key with the relay's code on Gray's page and write the kit from Gray's answer. */
async function initPairCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["pair", "gray", "dir", "key", "force", "registry-user", "registry-expires-at", "image", "release-delay"]);
  assertPositionals(args, 1);
  const { pairSummary, pairWorkspace } = await import("./init.ts");
  const result = await pairWorkspace({
    code: requiredFlag(args, "pair"),
    gray: requiredFlag(args, "gray"),
    directory: requiredFlag(args, "dir"),
    ...(args.flags.has("key") ? { keyPath: args.flags.get("key") as string } : {}),
    ...(args.flags.has("force") ? { force: true } : {}),
    ...(args.flags.has("registry-user") ? { registryUser: args.flags.get("registry-user") as string } : {}),
    ...(args.flags.has("registry-expires-at") ? { registryExpiresAt: args.flags.get("registry-expires-at") as string } : {}),
    ...(args.flags.has("release-delay") ? { releaseDelayHours: args.flags.get("release-delay") as string } : {}),
    // `--image` pins compose.yaml to a digest (the published image knows only its own tag), as `upgrade --image` does.
    ...(composeImageOf(args, io) === null ? {} : { composeImage: composeImageOf(args, io) as string }),
  });
  if (!result.ok) {
    io.stderr(`gray-assistant init: ${result.text}\n`);
    return 1;
  }
  // The pairing command runs init in a container that sees the kit at --dir (/work); GRAY_ASSISTANT_HOST_DIR, which the
  // command sets, is the same directory on the host, so every path printed here is one the operator can use.
  const hostDir = hostKitDir(io.env["GRAY_ASSISTANT_HOST_DIR"]);
  const shown = (path: string): string => (hostDir === null ? path : path === result.directory ? hostDir : path.startsWith(`${result.directory}/`) ? join(hostDir, path.slice(result.directory.length + 1)) : path);
  io.stdout(`gray-assistant init: paired relay ${result.relayId} with Gray; wrote the kit in ${shown(result.directory)}\n`);
  io.stdout(`relay_id ${result.relayId}\n`);
  io.stdout(`fingerprint ${result.fingerprint} (compare it with the one on the relay's Integration page)\n`);
  for (const file of result.files) io.stdout(`wrote ${shown(file)} (mode ${file === result.composePath ? "0644" : "0600"})\n`);
  io.stdout(
    `guardian ${result.guardian.address} (${result.guardian.generated ? "new key" : "the kit's key"} in ${shown(result.guardian.keyPath)}: back it up with relay-key.json; it approves, vetoes and pauses the relay's contract)\n`,
  );
  const phase2 = result.guardian.phase2;
  if (phase2 !== null) {
    io.stdout(`contract ${phase2.contract} on chain ${phase2.chainId} (your relay's app id; Gray deploys it at Deploy)\n`);
    io.stdout(`approved for it: compose hash ${phase2.composeHash}, OS image hash ${phase2.osImageHash} (signed by the guardian, submitted by Gray after Deploy)\n`);
    const delayHours = Number(phase2.releaseDelaySeconds) / 3600;
    io.stdout(
      `release delay ${delayHours} h: each later Gray release takes effect that long after it is proposed unless you veto it (approve one to let it in sooner); an upgrade of the contract always waits 7 days. Change it with gray-assistant releases delay <hours>\n`,
    );
    // Gray's release traffic window: a VM still on an older release gets no traffic from that long after a newer normal
    // release is proposed, so a longer delay leaves a time without traffic at each one.
    if (delayHours > RELEASE_TRAFFIC_WINDOW_HOURS) {
      io.stdout(
        `note: the delay is longer than Gray's ${RELEASE_TRAFFIC_WINDOW_HOURS} h traffic window: each normal release stops your relay's traffic ${RELEASE_TRAFFIC_WINDOW_HOURS} h after it is proposed until it takes effect, ${delayHours - RELEASE_TRAFFIC_WINDOW_HOURS} h later, unless you approve it sooner (gray-assistant releases approve)\n`,
      );
    }
  }
  const recovery = result.guardian.recovery;
  if (recovery !== null) {
    io.stdout(
      `recovery ${recovery.address} (${recovery.generated ? "new key" : "the kit's key"} in ${shown(recovery.keyPath)}): the only key that can replace your guardian if it is lost or stolen. ` +
        "Back this file up offline now (a USB stick or paper, not this machine) and remove it from here; Gray never receives it, and nobody can replace a lost one\n",
    );
  }
  // Only what is still left: a token file already in the kit (the pairing command puts it there first) is not asked for.
  const left: string[] = [];
  if (!existsSync(join(result.directory, "registry-password"))) {
    left.push(`put the registry's read-only pull token in ${shown(join(result.directory, "registry-password"))} (0600, owned by 10001)`);
  }
  if (result.placeholders.includes("stack.registry.username")) left.push("set stack.registry.username to its user and stack.registry.expires_at to its expiry (YYYY-MM-DDTHH:MM:SSZ), if it has one");
  if (!result.image) left.push("set stack.relay_images to your image, pinned by digest (<registry>/<repository>@sha256:<64 hex>)");
  left.forEach((line, index) => io.stdout(`${index === 0 ? "next: " : "      "}${line}\n`));
  // Joining trusts the releases Gray lists now: name each one the first boot may run without waiting.
  const pairing = result.releases;
  if (pairing !== null) {
    for (const entry of pairing.accepted) {
      io.stdout(`accepted at pairing: ${entry.kind === "release" ? "release" : "OS image"} ${entry.name}, ${entry.kind === "release" ? "compose hash" : "hash"} ${entry.hash}\n`);
    }
    if (pairing.accepted.length > 0) io.stdout("      gray-assistant takes these when it first reads Gray's list and tells Gray in its first report; every later release waits releases.delay_days (7)\n");
    for (const hash of pairing.unverifiedOsImages) {
      io.stdout(`not accepted: OS image ${hash}: its texts do not prove a production image; if you trust it, gray-assistant releases accept ${hash}\n`);
    }
    if (pairing.listError !== null) {
      io.stdout(`could not read Gray's release list (${pairing.listError}): nothing was accepted at pairing, so the current release waits 7 days from the agent's first sight, or accept it with gray-assistant releases accept once gray-assistant releases lists it\n`);
    }
  }
  const release = result.placeholders.filter((member) => member.startsWith("lane."));
  const placeholderNote = initPlaceholderNote(release);
  if (placeholderNote !== null) io.stdout(`${placeholderNote}\n`);
  // The config names the paths the host install mounts the kit at, so the install's own check reads it there.
  const then = left.length > 0 || placeholderNote !== null ? "then" : "next:";
  if (phase2 !== null) {
    // Phase 2 runs nothing on the host: an apply queues Deploy (relay-stack.md §6), then one delivery from the kit directory.
    io.stdout(`${then} apply the relay-stack document again: it adds the models and, once Gray approved the VM, queues Deploy (relay-stack.md §6)\n`);
    io.stdout(`      once the VM waits for its delivery (the setup checklist's deliver step), from ${shown(result.directory)}: docker compose run --rm --no-deps agent deliver\n`);
  } else if (result.composePath === null) io.stdout(`${then} install it: deploy/relay/host/install.sh --host <ssh alias> --kit ${shown(result.directory)}\n`);
  else io.stdout(`${then} start gray-assistant from ${shown(result.directory)}: docker compose up -d\n`);
  printJson(io, { ...pairSummary(result), ...(hostDir === null ? {} : { host_directory: hostDir }) } as JsonObject);
  return 0;
}

// ---------------------------------------------------------------------------------------------
// accounts
// ---------------------------------------------------------------------------------------------

/**
 * `gray-assistant accounts` (S59): the source's accounts with the id Gray's panel knows each by, on this machine only:
 * the source's own id, or the plain alias the agent gave an id that cannot be one (an e-mail address). The source is
 * read as `doctor` reads it; the aliases from the state directory.
 */
async function accountsCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["config"]);
  assertPositionals(args, 1);
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const { createSourceAdapter } = await import("./source/config.ts");
  const { accountAliasesPath, readAccountAliasesFile } = await import("./daemon/account-aliases-file.ts");
  const { panelIdLookup } = await import("../daemon/account-aliases.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  const aliasesPath = accountAliasesPath(config.daemon.stateFile);
  const aliases = readAccountAliasesFile(aliasesPath);
  if (aliases === null) io.stderr(`gray-assistant accounts: ${aliasesPath} does not read; aliased accounts show no panel id\n`);
  const panelId = panelIdLookup(aliases ?? []);
  const snapshot = await createSourceAdapter(config.source).list(AbortSignal.timeout(config.source.requestTimeoutMs));
  const rows = snapshot.accounts
    .map((account) => ({ panelId: panelId(account.vendor, account.sourceId), sourceId: account.sourceId, vendor: account.vendor }))
    .sort((left, right) => (left.sourceId < right.sourceId ? -1 : left.sourceId > right.sourceId ? 1 : 0));
  const width = Math.max("panel id".length, ...rows.map((row) => (row.panelId ?? "-").length));
  io.stdout(`gray-assistant accounts: ${rows.length} account(s) in the ${config.source.kind} source\n`);
  io.stdout(`${"panel id".padEnd(width)}  source id\n`);
  for (const row of rows) {
    io.stdout(`${(row.panelId ?? "-").padEnd(width)}  ${row.sourceId}${row.panelId === null ? "  (gets a panel id when the agent next reads the source)" : ""}\n`);
  }
  printJson(io, { command: "accounts", accounts: rows.map((row) => ({ panel_id: row.panelId, source_id: row.sourceId, vendor: row.vendor })) });
  return 0;
}

// ---------------------------------------------------------------------------------------------
// source check
// ---------------------------------------------------------------------------------------------

async function sourceCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  if (args.positionals[1] !== "check") throw new RelayKitError("usage", "gray-assistant source check [--config <config>]");
  assertFlags(args, ["config"]);
  assertPositionals(args, 2);
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const { checkSourceContract } = await import("./source/config.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  const report = await checkSourceContract(config.source);
  for (const line of report.lines) io.stdout(`${line.status.toUpperCase().padEnd(4)} ${line.id}: ${line.message}\n`);
  printJson(io, { command: "source check", ok: report.ok, lines: report.lines.map((line) => ({ id: line.id, status: line.status, message: line.message })) });
  return report.ok ? 0 : 1;
}

// ---------------------------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------------------------

async function runCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["config", "ca", "verifier-module"]);
  assertPositionals(args, 1);
  const { runSummary, startRelay } = await import("./run.ts");
  const runnerIo = { stdout: io.stdout, stderr: io.stderr, now: io.now };
  // Register the handlers before the listener exists: a supervisor that stops the process as soon
  // as it reads the listening line must find a handler, not the default terminate action.
  let resolveStop: () => void = () => undefined;
  const stopped = new Promise<void>((resolve) => {
    resolveStop = resolve;
  });
  const onSignal = (): void => resolveStop();
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  let running;
  try {
    running = await startRelay({
      configPath: configPathOf(args),
      ...(args.flags.has("ca") ? { ca: readFileText(args.flags.get("ca") as string, "CA certificate", 1024 * 1024) } : {}),
      ...(args.flags.has("verifier-module") ? { verifierModule: args.flags.get("verifier-module") as string } : {}),
      io: runnerIo,
    });
  } catch (error) {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    throw error;
  }
  io.stdout(`gray-assistant run: listening on ${running.url}\n`);
  if (running.ui !== null) io.stdout(`gray-assistant run: local page on ${running.ui.url}/ui/; sign in with gray-assistant ui link${configArgumentFor(running.config.path)}\n`);
  const publicPage = running.uiPublic?.origin() ?? null;
  if (publicPage !== null) io.stdout(`gray-assistant run: page on ${publicPage}/ui/ (passkeys only); add one with gray-assistant ui enroll${configArgumentFor(running.config.path)}\n`);
  printJson(io, runSummary(running));
  await stopped;
  await running.stop();
  io.stdout("gray-assistant run: stopped\n");
  return 0;
}

// ---------------------------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------------------------

async function doctorCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["config", "ca", "verifier-module", "now"]);
  assertPositionals(args, 1);
  const nowMs = args.flags.has("now") ? Number(parseU64(args.flags.get("now") as string, "--now") * 1000n) : io.now();
  const { doctorReportValue, runDoctor } = await import("./doctor.ts");
  const report = await runDoctor({
    configPath: configPathOf(args),
    nowMs,
    ...(args.flags.has("ca") ? { ca: readFileText(args.flags.get("ca") as string, "CA certificate", 1024 * 1024) } : {}),
    ...(args.flags.has("verifier-module") ? { verifierModule: args.flags.get("verifier-module") as string } : {}),
  });
  for (const line of report.lines) io.stdout(`${line.status.toUpperCase().padEnd(4)} ${line.id}: ${line.message}\n`);
  printJson(io, doctorReportValue(report) as JsonObject);
  return report.ok ? 0 : 1;
}

// ---------------------------------------------------------------------------------------------
// status / pause / resume
// ---------------------------------------------------------------------------------------------

function objectOf(value: unknown): JsonObject | null {
  return isObject(value as never) ? (value as JsonObject) : null;
}

function arrayOf(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function numeric(value: unknown): number | null {
  return typeof value === "number" ? value : typeof value === "bigint" ? Number(value) : null;
}

function text(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/**
 * `gray-assistant tunnel status`: the tunnel's part of the running agent's status (docs/relay-tunnel.md). `gray-assistant
 * tunnel ack <sha256>`: a CT finding the operator has explained (a certificate the relay obtained by hand, say) stops
 * counting; the agent reads the acknowledgements on its next poll. Both read the config for the tunnel's files.
 */
async function tunnelCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  const action = args.positionals[1];
  const { loadRelayConfigFile } = await import("./config-file.ts");
  if (action === "status") {
    assertFlags(args, ["config"]);
    assertPositionals(args, 2);
    const { readDaemonStatusFile } = await import("./daemon/status-file.ts");
    const config = loadRelayConfigFile(requiredFlag(args, "config"));
    if (config.daemon.tunnel === null) throw new RelayKitError("usage", "the config has no tunnel section");
    const snapshot = readDaemonStatusFile(config.daemon.statusFile);
    const tunnel = snapshot === null ? null : objectOf(get(snapshot, "tunnel"));
    if (tunnel === null) {
      io.stdout(`gray-assistant tunnel: not running (no tunnel status in ${config.daemon.statusFile})\n`);
      io.stdout(`name ${config.daemon.tunnel.name}\n`);
      printJson(io, { command: "tunnel status", running: false, name: config.daemon.tunnel.name, origin: config.daemon.tunnel.origin });
      return 0;
    }
    const certificate = objectOf(get(tunnel, "certificate"));
    const ct = objectOf(get(tunnel, "ct"));
    io.stdout(`tunnel ${text(get(tunnel, "state")) ?? "unknown"}\n`);
    io.stdout(`name ${config.daemon.tunnel.name}\n`);
    io.stdout(`origin ${config.daemon.tunnel.origin}\n`);
    io.stdout(`certificate ${certificate === null ? "unknown" : (text(get(certificate, "state")) ?? "unknown")}\n`);
    io.stdout(`ct ${ct === null ? "not run yet" : (text(get(ct, "state")) ?? "unknown")}\n`);
    printJson(io, { command: "tunnel status", running: true, ...(tunnel as Record<string, unknown>) });
    return 0;
  }
  if (action === "ack") {
    assertFlags(args, ["config"]);
    assertPositionals(args, 3);
    const sha256 = args.positionals[2] ?? "";
    if (!/^[0-9a-f]{64}$/.test(sha256)) throw new RelayKitError("usage", "tunnel ack takes a certificate's or a key's SHA-256, 64 lower-case hex");
    const { tunnelPaths } = await import("./tunnel/files.ts");
    const { writeCtAck } = await import("./tunnel/ct.ts");
    const config = loadRelayConfigFile(requiredFlag(args, "config"));
    if (config.daemon.tunnel === null) throw new RelayKitError("usage", "the config has no tunnel section");
    const path = tunnelPaths(config.daemon.tunnel).ctAcks;
    writeCtAck(path, sha256);
    io.stdout(`gray-assistant tunnel: ${sha256} acknowledged; the agent stops counting it at its next CT poll\n`);
    printJson(io, { command: "tunnel ack", sha256, acks_file: path });
    return 0;
  }
  throw new RelayKitError("usage", "tunnel takes status or ack");
}

async function statusCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["config"]);
  assertPositionals(args, 1);
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const { controlFileBeside } = await import("./daemon/control-file.ts");
  const { readControlView } = await import("./control.ts");
  const { readDaemonStatusFile } = await import("./daemon/status-file.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  const controlFile = controlFileBeside(config.daemon.stateFile);
  const snapshot = readDaemonStatusFile(config.daemon.statusFile);
  if (snapshot === null) {
    const view = await readControlView(config.daemon.stateFile, controlFile);
    io.stdout(`gray-assistant status: not running (no status file at ${config.daemon.statusFile})\n`);
    io.stdout(`relay_id ${config.daemon.relayId}\n`);
    io.stdout(`paused ${view.control.paused ? "yes" : "no"}\n`);
    io.stdout(`last_version ${view.lastVersion}\n`);
    io.stdout(`control_file ${controlFile} (${view.source})\n`);
    printJson(io, {
      command: "status",
      running: false,
      relay_id: config.daemon.relayId,
      paused: view.control.paused,
      last_version: view.lastVersion,
      control_file: controlFile,
      control_source: view.source,
      status_file: config.daemon.statusFile,
    });
    return 0;
  }
  const status = objectOf(get(snapshot, "status"));
  const health = objectOf(get(snapshot, "health"));
  const relayId = status === null ? null : text(get(status, "relay_id"));
  const paused = status !== null && get(status, "paused") === true;
  const writtenAt = numeric(get(snapshot, "written_at_ms"));
  const clockSkew = status === null ? null : numeric(get(status, "clock_skew_ms"));
  const reasons = health === null ? [] : arrayOf(get(health, "reasons")).map(String);
  const stopped = reasons.includes("stopped");
  // R23: a snapshot older than 3 ticks + one 60 s request timeout is not a running agent; the
  // status file is written after every tick, and one tick may wait out a slow lane POST.
  const staleAfterMs = 3 * config.daemon.tickMs + 60_000;
  const ageMs = writtenAt === null ? null : Math.max(0, io.now() - writtenAt);
  if (ageMs !== null && ageMs > staleAfterMs) {
    io.stdout(`gray-assistant status: not running (stale snapshot: written ${ageMs} ms ago, older than ${staleAfterMs} ms)\n`);
    io.stdout(`relay_id ${relayId ?? config.daemon.relayId}\n`);
    io.stdout(`paused ${paused ? "yes" : "no"}\n`);
    io.stdout(`snapshot_age_ms ${ageMs}\n`);
    printJson(io, { command: "status", running: false, stale: true, snapshot_age_ms: BigInt(ageMs), ...snapshot } as JsonObject);
    return 0;
  }
  const readiness = health !== null && get(health, "ready") === true && !stopped;
  io.stdout(`gray-assistant status: ${relayId ?? config.daemon.relayId}${stopped ? " (stopped)" : ""}\n`);
  io.stdout(`ready ${readiness ? "yes" : "no"}${reasons.length === 0 ? "" : ` (${reasons.join(", ")})`}\n`);
  io.stdout(`paused ${paused ? "yes" : "no"}\n`);
  io.stdout(`clock_skew_ms ${clockSkew === null ? "unknown" : String(clockSkew)}\n`);
  if (ageMs !== null) io.stdout(`snapshot_age_ms ${ageMs}\n`);
  const source = status === null ? null : objectOf(get(status, "source"));
  if (source !== null) io.stdout(`source healthy ${get(source, "healthy") === true ? "yes" : "no"}, accounts ${numeric(get(source, "accounts")) ?? 0}\n`);
  for (const replica of status === null ? [] : arrayOf(get(status, "replicas"))) {
    const record = objectOf(replica);
    if (record === null) continue;
    // R23: the remaining lease is the absolute deadline minus now, so it ages even when the writer
    // stopped. `lease_remaining_ms` in the file is the writer's snapshot and is deliberately unused.
    const expiresAt = numeric(get(record, "lease_expires_at_ms"));
    const remaining = expiresAt === null ? null : Math.max(0, expiresAt - io.now());
    // D116(b): the scheduler API version the replica's TEE uses, from its last verified call.
    const apiVersion = numeric(get(record, "scheduler_api_version"));
    io.stdout(
      `replica ${text(get(record, "origin")) ?? "?"}: phase ${text(get(record, "phase")) ?? "?"}, accounts ${numeric(get(record, "accounts")) ?? 0}, lease ${remaining === null ? "none" : `${Math.floor(remaining / 1000)}s`}, policy ${text(get(record, "policy_version")) ?? "-"}, credentials ${text(get(record, "credential_version")) ?? "-"}, scheduler api ${apiVersion === null ? "-" : String(apiVersion)}\n`,
    );
  }
  for (const account of status === null ? [] : arrayOf(get(status, "parked"))) {
    const record = objectOf(account);
    if (record === null) continue;
    io.stdout(`parked ${text(get(record, "account_id")) ?? "?"} (${text(get(record, "vendor")) ?? "?"}): ${text(get(record, "reason")) ?? "?"}\n`);
  }
  printReleaseLines(io, status);
  // S45: what the agent last reported to Gray's console (a relay stack's agent only).
  const agent = objectOf(get(snapshot, "agent_status"));
  if (agent !== null) {
    const { agentStatusVerdict } = await import("./daemon/agent-status-report.ts");
    const verdict = agentStatusVerdict(agent, io.now());
    io.stdout(`agent_status ${verdict.status}: ${verdict.message}\n`);
  }
  printJson(io, { command: "status", running: !stopped, ...(stopped ? { stopped: true } : {}), ...snapshot } as JsonObject);
  return 0;
}

/**
 * The release lines of `status` and `releases` (the daemon's status snapshot): each release of Gray's list and each OS
 * image with whether it is accepted (at pairing, or by you), rejected or pending and when it will be accepted, and what
 * keeps the list current.
 */
function printReleaseLines(io: CliIo, status: JsonObject | null): void {
  for (const release of status === null ? [] : arrayOf(get(status, "releases"))) {
    const record = objectOf(release);
    if (record === null) continue;
    const acceptable = get(record, "acceptable") === true;
    const at = numeric(get(record, "acceptable_at_ms"));
    const remaining = at === null ? null : Math.max(0, at - io.now());
    const rejected = get(record, "rejected") === true;
    const atPairing = acceptable && get(record, "accepted_at_pairing") === true ? " at pairing" : "";
    io.stdout(
      `release ${text(get(record, "compose_hash")) ?? "?"}: ${acceptable ? `accepted${atPairing}` : rejected ? "rejected" : "pending"}${acceptable || rejected || remaining === null ? "" : `, acceptable in ${Math.ceil(remaining / 3_600_000)}h`}\n`,
    );
  }
  // D137: what keeps the release list an authority, and until when; which part is stale when it is not.
  const releaseList = status === null ? null : objectOf(get(status, "release_list"));
  if (releaseList !== null) {
    const iso = (value: number | null): string => (value === null ? "none" : new Date(value).toISOString());
    const until = numeric(get(releaseList, "current_until_ms"));
    const freshness = text(get(releaseList, "freshness"));
    const error = text(get(releaseList, "last_error"));
    const staleness = text(get(releaseList, "staleness"));
    io.stdout(
      `release_list current until ${iso(until)}${until !== null && until <= io.now() ? " (lapsed)" : ""} by ${text(get(releaseList, "current_by")) ?? "-"}, expires ${iso(numeric(get(releaseList, "expires_at_ms")))}, freshness ${freshness ?? "-"}${error === null ? "" : `; last poll ${error}${staleness === null ? "" : ` (${staleness})`}`}\n`,
    );
  }
  // S11b: the list's OS images, with why one is not accepted and when it will be.
  for (const image of status === null ? [] : arrayOf(get(status, "os_images"))) {
    const record = objectOf(image);
    if (record === null) continue;
    const acceptable = get(record, "acceptable") === true;
    const refusal = text(get(record, "refusal"));
    const at = numeric(get(record, "acceptable_at_ms"));
    const remaining = at === null ? null : Math.max(0, at - io.now());
    const waiting = refusal === "os_image_not_accepted" && remaining !== null ? `, acceptable in ${Math.ceil(remaining / 3_600_000)}h` : "";
    const atPairing = acceptable && get(record, "accepted_at_pairing") === true ? " at pairing" : "";
    io.stdout(
      `os_image ${text(get(record, "os_image_hash")) ?? "?"}: ${acceptable ? `accepted${atPairing}` : (refusal ?? "pending")}${waiting}, provenance ${text(get(record, "provenance")) ?? "?"}${text(get(record, "version")) === null ? "" : `, version ${text(get(record, "version"))}`}\n`,
    );
  }
}

async function pauseCommand(args: ParsedArgs, io: CliIo, paused: boolean): Promise<number> {
  assertFlags(args, ["config"]);
  assertPositionals(args, 1);
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const { controlFileBeside } = await import("./daemon/control-file.ts");
  const { setPausedState } = await import("./control.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  const controlFile = controlFileBeside(config.daemon.stateFile);
  const view = await setPausedState(controlFile, config.daemon.stateFile, paused);
  io.stdout(`gray-assistant ${paused ? "pause" : "resume"}: relay ${config.daemon.relayId} is ${paused ? "paused" : "running"}\n`);
  io.stdout(`control_file ${controlFile}\n`);
  io.stdout(`state_file ${config.daemon.stateFile} (read only; the agent owns it)\n`);
  printJson(io, {
    command: paused ? "pause" : "resume",
    relay_id: config.daemon.relayId,
    paused: view.control.paused,
    accepted_releases: BigInt(view.control.acceptedReleases.length),
    last_version: view.lastVersion,
    control_file: controlFile,
    control_source: view.source,
  });
  return 0;
}

// ---------------------------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------------------------

/** `login <account>` (docs/design/relay-sign-in-in-vm.md): the sign-in inside the VM. */
async function loginCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  if (args.positionals[1] === undefined) throw new RelayKitError("usage", "login needs an account id (gray-assistant login <account>)");
  return loginVmCommand(args, io);
}

/** `login <account>`: the sign-in inside the relay's stack VM (`./login-vm.ts`). */
async function loginVmCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["config"]);
  assertPositionals(args, 2);
  const accountId = args.positionals[1] as string;
  const { checkLoginAccountId, loginVm } = await import("./login-vm.ts");
  checkLoginAccountId(accountId);
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  const key = await buildKeyFromText(readPrivateFile(config.daemon.keyPath, "relay key", MAX_KEY_BYTES));
  const { createInterface } = await import("node:readline");
  return loginVm({
    config,
    seed: key.seed,
    accountId,
    io: {
      stdout: io.stdout,
      stderr: io.stderr,
      now: io.now,
      sleep: io.sleep,
      random: io.random,
      readLines: (onLine) => {
        const lines = createInterface({ input: process.stdin, terminal: false });
        lines.on("line", onLine);
        return () => lines.close();
      },
      onCancel: (onCancel) => {
        process.on("SIGINT", onCancel);
        process.on("SIGHUP", onCancel);
        return () => {
          process.off("SIGINT", onCancel);
          process.off("SIGHUP", onCancel);
        };
      },
    },
  });
}

// ---------------------------------------------------------------------------------------------
// ui | ui link
// ---------------------------------------------------------------------------------------------

/** `--port`, when given; the page otherwise takes the config's `ui.listen.port`, else its default. */
function uiPortFlag(args: ParsedArgs): number | undefined {
  if (!args.flags.has("port")) return undefined;
  const text = args.flags.get("port") as string;
  if (!/^\d{1,5}$/.test(text) || Number(text) > 65_535) throw new RelayKitError("usage", "--port must be a TCP port (0-65535)");
  return Number(text);
}

/** How to open the page: the link, the code alone, the tunnel. The code is printed to this terminal only. */
function printUiLink(io: CliIo, link: { readonly url: string; readonly code: string }, port: number): void {
  io.stdout("Open this link in your browser to sign in (it works once, within 10 minutes):\n");
  io.stdout(`  ${link.url}\n`);
  io.stdout(`Or paste this code into the page's sign-in box: ${link.code}\n`);
  io.stdout(`From another machine, forward the port first: ssh -L ${port}:127.0.0.1:${port} <this host>\n`);
}

async function uiCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  if (args.positionals[1] === "enroll") return uiEnrollCommand(args, io);
  if (args.positionals[1] === "passkeys") return uiPasskeysCommand(args, io);
  if (args.positionals[1] === "link") {
    const { DEFAULT_UI_PORT } = await import("./ui/server.ts");
    assertFlags(args, ["config", "port"]);
    assertPositionals(args, 2);
    const { loadRelayConfigFile } = await import("./config-file.ts");
    const { mintUiLink, uiLinksDirectory } = await import("./ui/session.ts");
    const config = loadRelayConfigFile(configPathOf(args));
    const port = uiPortFlag(args) ?? config.daemon.ui?.port ?? DEFAULT_UI_PORT;
    const link = mintUiLink(uiLinksDirectory(config.daemon.stateFile), io.now(), io.random);
    io.stdout(`gray-assistant ui link: for ${config.daemon.relayId}'s page on http://127.0.0.1:${port}\n`);
    printUiLink(io, { url: `http://127.0.0.1:${port}/ui/session/${link.code}`, code: link.code }, port);
    printJson(io, { command: "ui link", relay_id: config.daemon.relayId, port: BigInt(port), expires_at_ms: BigInt(link.expiresAtMs) });
    return 0;
  }
  assertFlags(args, ["config", "port", "host", "ca", "verifier-module"]);
  assertPositionals(args, 1);
  const host = args.flags.get("host");
  // An address literal only (node:net isIP); a name would resolve to who knows what.
  if (host !== undefined && isIP(host) === 0) throw new RelayKitError("usage", "--host must be an IP address, such as 0.0.0.0 in the kit's container");
  const { startRelayUi } = await import("./ui/server.ts");
  const configPath = configPathOf(args);
  const port = uiPortFlag(args);
  let resolveStop: () => void = () => undefined;
  const stopped = new Promise<void>((resolve) => {
    resolveStop = resolve;
  });
  const onSignal = (): void => resolveStop();
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  let running;
  try {
    running = await startRelayUi({
      configPath,
      ...(port === undefined ? {} : { port }),
      ...(host === undefined ? {} : { host }),
      ...(args.flags.has("ca") ? { ca: readFileText(args.flags.get("ca") as string, "CA certificate", 1024 * 1024) } : {}),
      ...(args.flags.has("verifier-module") ? { verifierModule: args.flags.get("verifier-module") as string } : {}),
      io: { stdout: io.stdout, stderr: io.stderr, now: io.now },
      random: io.random,
    });
  } catch (error) {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    throw error;
  }
  io.stdout(`gray-assistant ui: ${running.config.daemon.relayId}'s page on ${running.url} (this machine only)\n`);
  printUiLink(io, running.mintLink(), running.port);
  io.stdout(`Another link later: gray-assistant ui link${configArgumentFor(running.config.path)}${port === undefined ? "" : ` --port ${running.port}`}\n`);
  printJson(io, { command: "ui", relay_id: running.config.daemon.relayId, url: running.url, port: BigInt(running.port) });
  await stopped;
  await running.stop();
  io.stdout("gray-assistant ui: stopped\n");
  return 0;
}

/**
 * `gray-assistant ui enroll`: a one-time link (15 minutes) that adds a passkey to the page on the relay's public origin
 * (`ui.public`). The origin is `--origin`, else where the running agent serves the page now (its status snapshot: the
 * tunnel's origin while it is up), else `ui.origin`, else `stack.token_url`'s. Printed to this terminal only.
 */
async function uiEnrollCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["config", "origin"]);
  assertPositionals(args, 2);
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const { readDaemonStatusFile } = await import("./daemon/status-file.ts");
  const { mintUiLink, uiEnrollDirectory, UI_ENROLL_LIFETIME_MS } = await import("./ui/session.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  if (config.daemon.ui?.public !== true) throw new RelayKitError("usage", "passkeys sign in to the page on the relay's public origin: set ui.public to true in the config first (and restart gray-assistant run)");
  let origin: string | null = null;
  if (args.flags.has("origin")) {
    const given = args.flags.get("origin") as string;
    let url: URL;
    try {
      url = new URL(given);
    } catch {
      throw new RelayKitError("usage", "--origin must be an https origin");
    }
    if (url.protocol !== "https:" || url.origin !== given) throw new RelayKitError("usage", "--origin must be an https origin (no path or trailing slash)");
    origin = given;
  }
  if (origin === null) {
    const snapshot = readDaemonStatusFile(config.daemon.statusFile);
    const page = snapshot === null ? null : get(snapshot, "ui_page");
    const written = snapshot === null ? null : get(snapshot, "written_at_ms");
    const fresh = typeof written === "number" && io.now() - written <= 3 * config.daemon.tickMs + 60_000;
    const served = fresh && isObject(page as never) ? get(page as JsonObject, "origin") : null;
    if (typeof served === "string") origin = served;
  }
  origin ??= config.daemon.ui.origin ?? (config.daemon.stack === null ? null : new URL(config.daemon.stack.tokenUrl).origin);
  if (origin === null) throw new RelayKitError("usage", "no public origin for the page yet: set ui.origin, or pass --origin");
  const link = mintUiLink(uiEnrollDirectory(config.daemon.stateFile), io.now(), io.random, UI_ENROLL_LIFETIME_MS);
  io.stdout(`gray-assistant ui enroll: add a passkey for ${config.daemon.relayId}'s page on ${origin}/ui/\n`);
  io.stdout("Open this link on the device that will hold the passkey (it works once, within 15 minutes):\n");
  io.stdout(`  ${origin}/ui/enroll/${link.code}\n`);
  io.stdout("Anyone with the link can add a passkey until it is used: open it yourself, now.\n");
  printJson(io, { command: "ui enroll", relay_id: config.daemon.relayId, origin, expires_at_ms: BigInt(link.expiresAtMs) });
  return 0;
}

/** `gray-assistant ui passkeys list|revoke <id>`: the passkeys that sign in to the public page, and taking one back. */
async function uiPasskeysCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  const verb = args.positionals[2];
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const { passkeyByPrefix, passkeysPath, readPasskeys, updatePasskeys } = await import("./ui/passkeys.ts");
  if (verb === "list") {
    assertFlags(args, ["config"]);
    assertPositionals(args, 3);
    const config = loadRelayConfigFile(configPathOf(args));
    const store = readPasskeys(passkeysPath(config.daemon.stateFile), io.random);
    const iso = (ms: number | null): string => (ms === null ? "never" : new Date(ms).toISOString());
    if (store.passkeys.length === 0) io.stdout("gray-assistant ui passkeys: none yet; add one with gray-assistant ui enroll\n");
    for (const passkey of store.passkeys) {
      io.stdout(`${passkey.id.slice(0, 12)}  ${passkey.label}  on ${passkey.rp_id}  added ${iso(passkey.created_at_ms)}  last used ${iso(passkey.last_used_at_ms)}\n`);
    }
    printJson(io, {
      command: "ui passkeys list",
      relay_id: config.daemon.relayId,
      passkeys: store.passkeys.map((passkey) => ({ id: passkey.id, label: passkey.label, rp_id: passkey.rp_id, created_at_ms: BigInt(passkey.created_at_ms), last_used_at_ms: passkey.last_used_at_ms === null ? null : BigInt(passkey.last_used_at_ms) })),
    });
    return 0;
  }
  if (verb === "revoke") {
    assertFlags(args, ["config"]);
    assertPositionals(args, 4);
    const config = loadRelayConfigFile(configPathOf(args));
    const prefix = args.positionals[3] as string;
    const removed = await updatePasskeys(passkeysPath(config.daemon.stateFile), io.random, (store) => {
      const passkey = passkeyByPrefix(store, prefix);
      return { store: { userId: store.userId, passkeys: store.passkeys.filter((item) => item.id !== passkey.id) }, result: passkey };
    });
    io.stdout(`gray-assistant ui passkeys revoke: ${removed.id.slice(0, 12)} (${removed.label}) can no longer sign in; its open sessions end at their next request\n`);
    printJson(io, { command: "ui passkeys revoke", relay_id: config.daemon.relayId, id: removed.id, label: removed.label });
    return 0;
  }
  throw new RelayKitError("usage", "ui passkeys needs `list` or `revoke <id>`");
}

// ---------------------------------------------------------------------------------------------
// releases accept | reject | unreject
// ---------------------------------------------------------------------------------------------

/** S53: the relay's own image rollout, rollback and restart, and where its stack app stands. */
async function stackCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  const verb = args.positionals[1];
  if (verb !== "rollout" && verb !== "rollback" && verb !== "restart" && verb !== "status") {
    throw new RelayKitError("usage", "stack needs the `rollout <image>`, `rollback`, `restart` or `status` subcommand");
  }
  assertFlags(args, verb === "status" ? ["config"] : ["config", "no-wait", "timeout"]);
  assertPositionals(args, verb === "rollout" ? 3 : 2);
  // Phase 2 (a config with `chain`): a rollout or rollback is a new designation in a boot box, then the restart (P4b);
  // a restart is accepted on the new boot's attestation (a phase-2 boot asks for no pull token).
  if (verb === "rollout" || verb === "rollback" || verb === "restart") {
    const chain = await chainContextOf(args, true);
    if (chain !== null) return deliverCli(args, io, verb, verb === "rollout" ? (args.positionals[2] as string) : null);
  }
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const { readPrivateFile } = await import("./files.ts");
  const { buildKeyFromText } = await import("./scheduler-load.ts");
  const { stackRoll, stackStatus } = await import("./stack.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  if (verb === "status") return stackStatus({ config, seed: new Uint8Array(32), io, wait: false });
  const timeout = args.flags.get("timeout");
  if (timeout !== undefined && !/^[1-9][0-9]{0,5}$/.test(timeout)) throw new RelayKitError("usage", "--timeout is whole seconds");
  const key = await buildKeyFromText(readPrivateFile(config.daemon.keyPath, "relay key", 64 * 1024));
  return stackRoll(
    { config, seed: key.seed, io, wait: !args.flags.has("no-wait"), ...(timeout === undefined ? {} : { timeoutMs: Number(timeout) * 1000 }) },
    verb,
    verb === "rollout" ? (args.positionals[2] as string) : null,
  );
}

/**
 * Phase 2's deliveries (P4b, `./deliver.ts`): `deliver`, `accounts push`, `registry set`, and `stack rollout|rollback`
 * for a config with a `chain` member. Each attests the VM, checks the relay's contract from two RPCs, seals what it
 * sends to the attested boot, and asks Gray for the restart when the VM's receipt says one is needed.
 */
async function deliverCli(args: ParsedArgs, io: CliIo, action: "deliver" | "accounts" | "registry" | "rollout" | "rollback" | "restart", image: string | null): Promise<number> {
  const waits = action === "deliver" || action === "rollout" || action === "rollback" || action === "restart";
  assertFlags(args, waits ? ["config", "no-wait", "timeout"] : ["config"]);
  assertPositionals(args, action === "deliver" ? 1 : action === "rollout" ? 3 : 2);
  const command = action === "deliver" ? "deliver" : action === "accounts" ? "accounts push" : action === "registry" ? "registry set" : `stack ${action}`;
  const chain = await requireChainContext(args, command);
  const timeout = args.flags.get("timeout");
  if (timeout !== undefined && !/^[1-9][0-9]{0,5}$/.test(timeout)) throw new RelayKitError("usage", "--timeout is whole seconds");
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  const key = await buildKeyFromText(readPrivateFile(config.daemon.keyPath, "relay key", MAX_KEY_BYTES));
  const { deliverCommand } = await import("./deliver.ts");
  return deliverCommand({
    config,
    chain,
    seed: key.seed,
    io,
    action,
    image,
    wait: !args.flags.has("no-wait"),
    ...(timeout === undefined ? {} : { timeoutMs: Number(timeout) * 1000 }),
  });
}

/**
 * `debug get <request id> [--out <file>]` (docs/design/relay-debug-sharing.md §6): the record of one request the
 * customer authorized for debugging, from the relay's stack VM, opened here (`./debug.ts`). The record goes to `--out`
 * or to stdout when that is not a terminal; stderr gets its metadata as one JSON line.
 */
async function debugCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  if (args.positionals[1] !== "get") throw new RelayKitError("usage", "debug needs the `get <request id>` subcommand");
  assertFlags(args, ["config", "out"]);
  if (args.positionals.length !== 3) throw new RelayKitError("usage", "debug get takes one request id: the customer's x-request-id or the container's X-Gray-Request");
  const requestId = args.positionals[2] as string;
  const out = args.flags.get("out") ?? null;
  const { checkDebugRequestId, debugGet } = await import("./debug.ts");
  checkDebugRequestId(requestId);
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  const key = await buildKeyFromText(readPrivateFile(config.daemon.keyPath, "relay key", MAX_KEY_BYTES));
  return debugGet({
    config,
    seed: key.seed,
    requestId,
    out,
    io: {
      stderr: io.stderr,
      now: io.now,
      stdoutIsTTY: process.stdout.isTTY === true,
      stdoutBytes: (bytes) =>
        new Promise<void>((done, fail) => {
          process.stdout.write(bytes, (error) => (error === null || error === undefined ? done() : fail(new RelayKitError("io", "cannot write the record to stdout"))));
        }),
    },
  });
}

/**
 * `releases` alone: Gray's releases and OS images as the running agent last saw them (its status snapshot, as `status`
 * prints them), each accepted (at pairing or by you), rejected or pending with when it will be; the hashes to give
 * `releases accept`. A stopped agent lists what control.json accepted and rejected.
 */
async function releasesListCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["config"]);
  assertPositionals(args, 1);
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const { readDaemonStatusFile } = await import("./daemon/status-file.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  const snapshot = readDaemonStatusFile(config.daemon.statusFile);
  const status = snapshot === null ? null : objectOf(get(snapshot, "status"));
  if (status === null) {
    const { controlFileBeside } = await import("./daemon/control-file.ts");
    const { readControlView } = await import("./control.ts");
    const view = await readControlView(config.daemon.stateFile, controlFileBeside(config.daemon.stateFile));
    io.stdout(`gray-assistant releases: ${config.daemon.relayId}: the agent is not running (no status file at ${config.daemon.statusFile}), so Gray's list is not read; control.json says:\n`);
    for (const hash of view.control.acceptedReleases) io.stdout(`accepted ${hash}\n`);
    for (const hash of view.control.rejectedReleases ?? []) io.stdout(`rejected ${hash}\n`);
    printJson(io, {
      command: "releases",
      running: false,
      relay_id: config.daemon.relayId,
      accepted: [...view.control.acceptedReleases],
      rejected: [...(view.control.rejectedReleases ?? [])],
    });
    return 0;
  }
  io.stdout(`gray-assistant releases: ${text(get(status, "relay_id")) ?? config.daemon.relayId}\n`);
  printReleaseLines(io, status);
  io.stdout("accept one now with gray-assistant releases accept <hash>; reject one with gray-assistant releases reject <hash>\n");
  printJson(io, {
    command: "releases",
    running: true,
    relay_id: text(get(status, "relay_id")) ?? config.daemon.relayId,
    releases: arrayOf(get(status, "releases")),
    os_images: arrayOf(get(status, "os_images")),
    release_list: objectOf(get(status, "release_list")),
  } as JsonObject);
  return 0;
}

async function releasesCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  const verb = args.positionals[1];
  if (verb === undefined) return releasesListCommand(args, io);
  // Phase 2: the releases on the relay's contract. `reject` is the contract's veto when the config has a `chain` member.
  if (verb === "list" || verb === "check" || verb === "approve") return chainReleasesCommand(args, io, verb, await requireChainContext(args, `releases ${verb}`));
  if (verb === "delay") return releasesDelayCommand(args, io, await requireChainContext(args, "releases delay"));
  if (verb === "reject") {
    const chain = await chainContextOf(args, true);
    if (chain !== null) return chainReleasesCommand(args, io, "reject", chain);
  }
  if (verb === "reject" || verb === "unreject") return releasesVetoCommand(args, io, verb);
  if (verb !== "accept") throw new RelayKitError("usage", "releases lists Gray's releases; it takes no subcommand, or `accept <id>`, `reject <hash>` or `unreject <hash>`; on a relay's contract `list`, `check <hash>`, `approve <hash>` or `reject <hash>`");
  assertFlags(args, ["config", "no-wait", "timeout"]);
  assertPositionals(args, 3);
  const id = args.positionals[2] as string;
  const timeout = args.flags.get("timeout");
  if (timeout !== undefined && !/^[1-9][0-9]{0,5}$/.test(timeout)) throw new RelayKitError("usage", "--timeout is whole seconds");
  const waitMs = args.flags.has("no-wait") ? 0 : timeout === undefined ? RELEASE_ACCEPT_WAIT_DEFAULT_MS : Number(timeout) * 1000;
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const { controlFileBeside } = await import("./daemon/control-file.ts");
  const { agentRunning, readDaemonStatusFile } = await import("./daemon/status-file.ts");
  const { acceptReleaseId } = await import("./release-control.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  const controlFile = controlFileBeside(config.daemon.stateFile);
  const outcome = await acceptReleaseId(config, controlFile, id, io.now, {
    waitMs,
    agentRunning: agentRunning(readDaemonStatusFile(config.daemon.statusFile), config.daemon.tickMs, io.now()),
    sleep: io.sleep,
    onWait: (hash) =>
      io.stderr(`gray-assistant releases accept: the agent has not seen ${hash} in Gray's list yet; it reads the list now, waiting up to ${Math.round(waitMs / 1000)} s for its first sight\n`),
  });
  if (!outcome.ok && outcome.code === "os_image_dev") {
    io.stderr(`gray-assistant: releases accept: ${id} is a dstack dev image by its own metadata.json; it is never accepted\n`);
    printJson(io, { command: "releases.accept", ok: false, relay_id: config.daemon.relayId, id, code: "os_image_dev" });
    return 1;
  }
  if (!outcome.ok && outcome.code === "not_seen") {
    // R27: an acceptance counts only from the agent's first sight, so one made now would not count. Say so, and what to do.
    const what = outcome.kind === "os_image" ? `OS image ${outcome.hash}` : outcome.hash;
    const why = !outcome.agentRunning
      ? `the agent is not running (no fresh status in ${config.daemon.statusFile}), so it cannot record its first sight of ${what}`
      : outcome.waitedMs === 0
        ? `the agent has not seen ${what} in Gray's list yet`
        : `the agent did not see ${what} in Gray's list within ${Math.round(outcome.waitedMs / 1000)} s`;
    const next = !outcome.agentRunning
      ? "start the agent, wait until `gray-assistant releases` lists it, then run this command again"
      : outcome.waitedMs === 0
        ? "run this command again without --no-wait, or once `gray-assistant releases` lists it"
        : "`gray-assistant releases` shows whether the agent's last read of the list failed; run this command again once it lists the release";
    io.stderr(`gray-assistant: releases accept: ${why}. An acceptance counts only from that first sight, so this one does not count; ${next}\n`);
    printJson(io, {
      command: "releases.accept",
      ok: false,
      relay_id: config.daemon.relayId,
      id,
      code: "not_seen",
      [outcome.kind === "os_image" ? "os_image_hash" : "compose_hash"]: outcome.hash,
      agent_running: outcome.agentRunning,
      waited_ms: BigInt(outcome.waitedMs),
    });
    return 1;
  }
  if (!outcome.ok) {
    io.stderr(`gray-assistant: releases accept: ${id} names no release or OS image in the signed list\n`);
    printJson(io, { command: "releases.accept", ok: false, relay_id: config.daemon.relayId, id });
    return 1;
  }
  const counted = {
    first_seen_ms: BigInt(outcome.firstSeenMs),
    accepted_at_ms: BigInt(outcome.acceptedAtMs),
    accepted_releases: BigInt(outcome.view.control.acceptedReleases.length),
    control_file: controlFile,
    control_source: outcome.view.source,
  };
  const printCounted = (): void => {
    io.stdout(`first_seen ${new Date(outcome.firstSeenMs).toISOString()}\n`);
    io.stdout(`accepted_at ${new Date(outcome.acceptedAtMs).toISOString()}\n`);
    io.stdout(`control_file ${controlFile}\n`);
    io.stdout(`accepted_releases ${outcome.view.control.acceptedReleases.length}\n`);
  };
  if (outcome.kind === "os_image") {
    if (outcome.provenance !== "ok") {
      io.stderr(`gray-assistant releases accept: warning: ${id}'s entry does not prove it a production image (${outcome.provenance}); you are accepting it on your own judgment\n`);
    }
    io.stdout(`gray-assistant releases accept: OS image ${id} accepted for ${config.daemon.relayId}; the agent counts it from its next tick\n`);
    printCounted();
    printJson(io, { command: "releases.accept", ok: true, relay_id: config.daemon.relayId, os_image_hash: id, provenance: outcome.provenance, ...counted });
    return 0;
  }
  io.stdout(`gray-assistant releases accept: ${outcome.composeHash} accepted for ${config.daemon.relayId}; the agent counts it from its next tick\n`);
  printCounted();
  printJson(io, { command: "releases.accept", ok: true, relay_id: config.daemon.relayId, compose_hash: outcome.composeHash, git_commit: outcome.gitCommit, ...counted });
  return 0;
}

/** How long `releases accept` waits for the agent's first sight by default: its forced read of the list takes a tick and two 20 s GETs at most. */
const RELEASE_ACCEPT_WAIT_DEFAULT_MS = 120_000;

/**
 * S11b's veto (`./release-control.ts`): `reject <hash>` records a compose hash or an OS image hash of the current
 * signed list in `control.json`'s `rejected_releases`, and the agent stops accepting it at its next tick; `unreject
 * <hash>` removes the veto, also for a hash that has since left the list.
 */
async function releasesVetoCommand(args: ParsedArgs, io: CliIo, verb: "reject" | "unreject"): Promise<number> {
  assertFlags(args, ["config"]);
  assertPositionals(args, 3);
  const hash = args.positionals[2] as string;
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new RelayKitError("usage", `releases ${verb} takes a compose hash or an OS image hash (64 lower-case hex)`);
  const { loadRelayConfigFile } = await import("./config-file.ts");
  const { controlFileBeside } = await import("./daemon/control-file.ts");
  const { vetoRelease } = await import("./release-control.ts");
  const config = loadRelayConfigFile(configPathOf(args));
  const controlFile = controlFileBeside(config.daemon.stateFile);
  const outcome = await vetoRelease(config, controlFile, verb, hash, io.now());
  if (!outcome.ok) {
    io.stderr(`gray-assistant: releases reject: ${hash} names no release or OS image in the signed list\n`);
    printJson(io, { command: "releases.reject", ok: false, relay_id: config.daemon.relayId, hash });
    return 1;
  }
  const view = outcome.view;
  const rejected = view.control.rejectedReleases ?? [];
  io.stdout(`gray-assistant releases ${verb}: ${hash} ${verb === "reject" ? "rejected" : "no longer rejected"} for ${config.daemon.relayId}\n`);
  io.stdout(`control_file ${controlFile}\n`);
  io.stdout(`rejected_releases ${rejected.length}\n`);
  printJson(io, {
    command: `releases.${verb}`,
    ok: true,
    relay_id: config.daemon.relayId,
    hash,
    rejected_releases: BigInt(rejected.length),
    accepted_releases: BigInt(view.control.acceptedReleases.length),
    control_file: controlFile,
    control_source: view.source,
  });
  return 0;
}

// ---------------------------------------------------------------------------------------------
// policy test
// ---------------------------------------------------------------------------------------------

async function policyTestCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  assertFlags(args, ["bundle", "fixtures", "key", "public-key", "interpreter"]);
  assertPositionals(args, 2);
  let publicKey: Uint8Array | null = null;
  if (args.flags.has("key") && args.flags.has("public-key")) throw new RelayKitError("usage", "pass --key or --public-key, not both");
  if (args.flags.has("key")) publicKey = (await loadKey(args.flags.get("key") as string)).publicKey;
  if (args.flags.has("public-key")) {
    const bytes = lowerHexBytes(args.flags.get("public-key") as string);
    if (bytes === null || bytes.length !== 32) throw new RelayKitError("usage", "--public-key must be 32 bytes as 64 lower-case hex");
    publicKey = bytes;
  }
  const { loadPolicyBundle, parsePolicyFixtures, testPolicy, verifyPolicyBundleFile } = await import("./policy-test.ts");
  const { initWorkspaceInterpreter } = await import("./interpreter.ts");
  initWorkspaceInterpreter(args.flags.get("interpreter"));
  const bundle = loadPolicyBundle(requiredFlag(args, "bundle"));
  if (publicKey !== null) await verifyPolicyBundleFile(bundle, publicKey);
  else io.stderr("warning: no --key/--public-key; the bundle signature was not checked (the TEE always checks it)\n");
  const fixtures = parsePolicyFixtures(readFileText(requiredFlag(args, "fixtures"), "fixtures file", 64 * 1024 * 1024));
  const result = testPolicy(bundle, fixtures);
  io.stdout(`gray-assistant policy test: ${result.relayId} version ${result.version}, module_sha256 ${result.moduleSha256}\n`);
  let failures = 0;
  for (const fixture of result.fixtures) {
    if (fixture.cause !== null) failures += 1;
    const reason = fixture.reasonCode === null ? "" : ` ${fixture.reasonCode}`;
    const cause = fixture.cause === null ? "" : ` cause=${fixture.cause}`;
    io.stdout(
      `fixture ${fixture.fixture.name} ${fixture.fixture.protocol}: ${fixture.outcome}${reason}, fuel ${fixture.fuelUsed}/${fixture.fuelCap}, appends ${fixture.appends}${cause}\n`,
    );
    io.stdout(`${toJsonString(fixture.event)}\n`);
  }
  io.stdout(`fixtures ${result.fixtures.length}, failures ${failures}\n`);
  printJson(io, {
    command: "policy.test",
    ok: failures === 0,
    relay_id: result.relayId,
    version: result.version,
    module_sha256: result.moduleSha256,
    fixtures: BigInt(result.fixtures.length),
    failures: BigInt(failures),
  });
  return failures === 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

async function loadKey(path: string): Promise<RelayKeyFile> {
  const text = readPrivateFile(path, "relay key", MAX_KEY_BYTES);
  return buildKeyFromText(text);
}

function loadTemplates(path: string): ReturnType<typeof parseTemplatesValue> {
  const text = readFileText(path, "templates file", MAX_TEMPLATES_BYTES);
  return parseJsonOr(text, "invalid_templates", () => parseTemplatesValue(parseStrict(text)));
}

/** The CLI's `--report`/`--reports` form of the shared report loader. */
function loadReportFiles(
  args: ParsedArgs,
  nowSecs: bigint,
  maxAgeSeconds: bigint,
  options: { readonly origin?: string; readonly acceptUnpinned?: boolean } = {},
): readonly CheckedVerifiedReport[] {
  return loadVerifiedReports(
    { paths: [...(args.multiFlags.get("report") ?? [])], listPath: args.flags.get("reports") ?? null },
    {
      nowSecs,
      maxAgeSeconds,
      ...(options.origin === undefined ? {} : { origin: options.origin }),
      ...(options.acceptUnpinned === undefined ? {} : { acceptUnpinned: options.acceptUnpinned }),
      // S11b: every command that seals or uploads to a lane re-judges the OS image from the record.
      requireProductionOsImage: true,
    },
  );
}

interface WriteSealedOptions {
  readonly command: string;
  readonly relayId: string;
  readonly version: bigint;
  /** The command chose the version (no `--version`); the record says so as `version_chosen`. */
  readonly versionChosen: boolean;
  readonly accounts?: bigint;
  readonly relayKeyId: string;
  readonly sealed: readonly SealedForReplica[];
  /** `seal` and `revoke` require an output path; `push-token` may print the ciphertext. */
  readonly requireOut: boolean;
  /** Extra machine-readable members for this command's document. */
  readonly extra?: JsonObject;
}

/** Write one envelope per replica; for more than one, `--out` is a directory. */
function writeSealed(args: ParsedArgs, io: CliIo, options: WriteSealedOptions): void {
  const out = args.flags.get("out");
  const force = args.flags.has("force");
  const files: (string | null)[] = [];
  if (out === undefined) {
    if (options.requireOut) throw new RelayKitError("usage", "missing --out");
    for (const sealed of options.sealed) io.stdout(`${toJsonString(sealed.envelope)}\n`);
    return;
  }
  if (options.sealed.length === 1) {
    const sealed = options.sealed[0] as SealedForReplica;
    writePrivateFile(out, `${toJsonString(sealed.envelope)}\n`, { force });
    io.stdout(`wrote ${out}\n`);
    files.push(out);
  } else {
    ensureDirectory(out);
    for (let index = 0; index < options.sealed.length; index += 1) {
      const sealed = options.sealed[index] as SealedForReplica;
      const path = join(out, `${String(index + 1).padStart(2, "0")}-${safeFilePart(sealed.intakeKeyId)}.json`);
      writePrivateFile(path, `${toJsonString(sealed.envelope)}\n`, { force });
      io.stdout(`wrote ${path} (${sealed.report.file.origin}, ${sealed.intakeKeyId})\n`);
      files.push(path);
    }
  }
  const common = {
    command: options.command,
    relay_id: options.relayId,
    version: options.version,
    version_chosen: options.versionChosen,
    ...(options.accounts === undefined ? {} : { accounts: options.accounts }),
    ...options.extra,
    relay_key_id: options.relayKeyId,
  };
  if (options.sealed.length === 1) {
    const sealed = options.sealed[0] as SealedForReplica;
    printJson(io, {
      ...common,
      intake_key_id: sealed.intakeKeyId,
      keyset_digest: sealed.keysetDigest,
      origin: sealed.report.file.origin,
      file: files[0] ?? null,
    });
  } else {
    printJson(io, {
      ...common,
      replicas: options.sealed.map((sealed, index) => ({
        intake_key_id: sealed.intakeKeyId,
        keyset_digest: sealed.keysetDigest,
        origin: sealed.report.file.origin,
        file: files[index] ?? null,
      })),
    });
  }
}

/** A filename component for an intake key id (its alphabet includes `:`). */
function safeFilePart(text: string): string {
  return text.replace(/[^A-Za-z0-9_.-]/g, "_");
}

function readToken(path: string): string {
  const text = readFileText(path, "token file", MAX_KEY_BYTES);
  const token = text.replace(/\r?\n$/, "");
  if (token.length === 0) throw new RelayKitError("invalid_token", "the token file is empty");
  if (/[\r\n]/.test(token)) throw new RelayKitError("invalid_token", "the token file holds more than one line");
  return token;
}

/**
 * A credential message's version (`seal`, `push-token`, `revoke`): `--version <n>` as given, else the wall clock in
 * Unix milliseconds, the daemon ledger's floor (`../daemon/versions.ts`): a manual message after the daemon's is not
 * a rollback, and a later run picks a higher one. `--now` does not move it (it is the report-age clock), so a
 * backdated `--now` cannot pick a version below the ones already sent. `refusal` is the message for a given 0.
 */
function credentialVersionFrom(args: ParsedArgs, io: CliIo, refusal: string): { readonly version: bigint; readonly chosen: boolean } {
  if (args.flags.has("version")) {
    const version = parseU64(args.flags.get("version") as string, "--version");
    if (version < 1n) throw new RelayKitError("invalid_version", refusal);
    return { version, chosen: false };
  }
  const version = BigInt(Math.floor(io.now()));
  if (version < 1n) throw new RelayKitError("invalid_version", "the clock is before 1970; pass --version");
  return { version, chosen: true };
}

/** `version <n>`, and `(chosen: now)` when the command chose it. */
function versionText(version: bigint, chosen: boolean): string {
  return `version ${version}${chosen ? " (chosen: now)" : ""}`;
}

function nowSecsFrom(args: ParsedArgs, io: CliIo): bigint {
  return args.flags.has("now") ? parseU64(args.flags.get("now") as string, "--now") : BigInt(Math.floor(io.now() / 1000));
}

function maxReportAgeFrom(args: ParsedArgs): bigint {
  if (!args.flags.has("max-report-age")) return BigInt(DEFAULT_MAX_REPORT_AGE_SECONDS);
  const value = parsePositiveInt(args.flags.get("max-report-age") as string, "--max-report-age");
  if (value > 31_536_000n) throw new RelayKitError("usage", "--max-report-age is at most one year");
  return value;
}

function parseU64(text: string, what: string): bigint {
  if (!/^[0-9]{1,20}$/.test(text)) throw new RelayKitError("usage", `${what} must be a non-negative integer`);
  const value = BigInt(text);
  if (value > U64_MAX) throw new RelayKitError("usage", `${what} is out of the u64 range`);
  return value;
}

function parsePositiveInt(text: string, what: string): bigint {
  const value = parseU64(text, what);
  if (value === 0n) throw new RelayKitError("usage", `${what} must be positive`);
  return value;
}

function assertFlags(args: ParsedArgs, allowed: readonly string[]): void {
  for (const name of args.flags.keys()) {
    if (!allowed.includes(name)) throw new RelayKitError("usage", `unknown option --${name}`);
  }
}

function assertPositionals(args: ParsedArgs, count: number): void {
  if (args.positionals.length !== count) {
    throw new RelayKitError("usage", `${args.positionals[0] ?? "the command"} takes ${count === 1 ? "no arguments" : "a fixed number of arguments"}`);
  }
}

/** The relay config a command reads: `--config`, else the default location (`defaultConfigPath`). */
function configPathOf(args: ParsedArgs): string {
  return args.flags.get("config") ?? defaultConfigPath();
}

function requiredFlag(args: ParsedArgs, name: string): string {
  const value = args.flags.get(name);
  if (value === undefined) throw new RelayKitError("usage", `missing --${name}`);
  return value;
}

function parseJsonOr<T>(text: string, code: "invalid_accounts" | "invalid_templates" | "unsupported_document" | "invalid_verified_report", parse: () => T): T {
  try {
    return parse();
  } catch (error) {
    if (isRelayKitError(error)) throw error;
    // The platform's parse error can echo the input; say only that it is not JSON.
    throw new RelayKitError(code, "the file is not valid JSON");
  }
}

function toText(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new RelayKitError("io", "the file is not UTF-8");
  }
}

// ---------------------------------------------------------------------------------------------
// the relay's contract (phase 2): releases list|check|approve|reject, pause, unpause

/**
 * The config's `chain` member, or null for a config without one. With `routing` (choosing between a phase-1 command
 * and the contract's), a missing config is null too, so the phase-1 command says what is missing in its own words.
 */
/** The image `init --pair` writes into compose.yaml: `--image`, else the published image's own `$GRAY_ASSISTANT_IMAGE`. */
function composeImageOf(args: ParsedArgs, io: CliIo): string | null {
  const image = (args.flags.get("image") ?? io.env["GRAY_ASSISTANT_IMAGE"] ?? "").trim();
  return image === "" ? null : image;
}

async function chainContextOf(args: ParsedArgs, routing = false) {
  const { readChainContext } = await import("./chain.ts");
  const path = configPathOf(args);
  if (!existsSync(path)) {
    if (routing) return null;
    throw new RelayKitError("io", `no relay config at ${path}: pass --config <file> or set GRAY_ASSISTANT_CONFIG`);
  }
  return readChainContext(path);
}

async function requireChainContext(args: ParsedArgs, command: string) {
  const context = await chainContextOf(args);
  if (context === null) {
    throw new RelayKitError("usage", `${command} acts on the relay's contract, and this config has no chain member (a phase-2 relay's: chain_id, rpc, proposer, guardian, contract)`);
  }
  return context;
}

type ChainContextValue = NonNullable<Awaited<ReturnType<typeof chainContextOf>>>;

function submitOf(args: ParsedArgs): { readonly rpc: string } | null {
  if (!args.flags.has("submit")) {
    if (args.flags.has("rpc")) throw new RelayKitError("usage", "--rpc goes with --submit (the endpoint the transaction is sent through)");
    return null;
  }
  const rpc = args.flags.get("rpc");
  if (rpc === undefined) throw new RelayKitError("usage", "--submit needs --rpc <url>: the endpoint the guardian's transaction is sent through");
  return { rpc };
}

/** `--print`: sign only, send nothing (neither Gray's relayer nor `--submit`). */
function printOf(args: ParsedArgs): boolean {
  if (args.flags.has("print") && args.flags.has("submit")) throw new RelayKitError("usage", "--print signs only; --submit sends it: give one");
  return args.flags.has("print");
}

async function chainReleasesCommand(args: ParsedArgs, io: CliIo, verb: "list" | "check" | "approve" | "reject", context: ChainContextValue): Promise<number> {
  const chain = await import("./chain.ts");
  if (verb === "list") {
    assertFlags(args, ["config", "from-block"]);
    assertPositionals(args, 2);
    const fromText = args.flags.get("from-block");
    if (fromText !== undefined && !/^(0|[1-9][0-9]{0,15})$/.test(fromText)) throw new RelayKitError("usage", "--from-block is a block number");
    const listed = await chain.chainReleasesList(context, { nowMs: io.now(), ...(fromText === undefined ? {} : { fromBlock: BigInt(fromText) }) });
    io.stdout(`gray-assistant releases list: ${listed.releases.length} release(s) on ${context.chain.contract} at block ${listed.block} (both RPCs agree)\n`);
    const now = BigInt(Math.floor(io.now() / 1000));
    for (const state of listed.releases) {
      io.stdout(`${chain.releaseVerdict(state, now)}\n`);
      if (state.kind === "implementation") io.stdout(`  ${chain.upgradeVerdict(state.hash).detail}\n`);
    }
    printPlainJson(io, { command: "releases list", contract: context.chain.contract, chain_id: context.chain.chainId, block: listed.block.toString(), releases: listed.releases.map((state) => chain.releaseStateJson(state)) });
    return 0;
  }
  if (verb === "check") {
    assertFlags(args, ["config", "kind"]);
    assertPositionals(args, 3);
    const checked = await chain.chainReleaseCheck(context, args.positionals[2] as string, args.flags.get("kind"), { nowMs: io.now() });
    io.stdout(`gray-assistant releases check: ${checked.verdict} (block ${checked.block}, both RPCs agree)\n`);
    if (checked.state.kind === "implementation") {
      // An upgrade of the contract: Gray's only when this kit's published list names it.
      const upgrade = chain.upgradeVerdict(checked.state.hash);
      if (upgrade.ok) io.stdout(`gray-assistant releases check: ${upgrade.detail}\n`);
      else io.stderr(`gray-assistant releases check: ${upgrade.detail}\n`);
      printPlainJson(io, { command: "releases check", contract: context.chain.contract, block: checked.block.toString(), release: chain.releaseStateJson(checked.state), verdict: checked.verdict, upgrade });
      return upgrade.ok ? 0 : 1;
    }
    // P6: the release's own content, from Gray's signed list, checked here (the compose's text and policy, or the OS image's texts).
    const { releaseContentForCheck, releaseContentJson } = await import("./release-content.ts");
    const content = await releaseContentForCheck(context, checked.state.kind, checked.state.hash, io.now());
    if (content === null) {
      io.stdout("the release's content is not checked: the config has no lane section (lane.release_list and lane.release_public_key, the signed list to read it from)\n");
    } else {
      for (const line of content.checks) io.stdout(`  ${line.ok ? "ok  " : "FAIL"} ${line.name}: ${line.detail}\n`);
      if (content.ok) io.stdout(`gray-assistant releases check: the ${checked.state.kind === "compose" ? "compose" : "OS image"} passes the relay's checks (Gray's signed list, hashed and checked on this machine)\n`);
      else io.stderr(`gray-assistant releases check: the ${checked.state.kind === "compose" ? "compose" : "OS image"} does not pass (${content.code}); veto it with \`gray-assistant releases reject ${checked.state.hash}\` before it becomes effective\n`);
    }
    printPlainJson(io, {
      command: "releases check",
      contract: context.chain.contract,
      block: checked.block.toString(),
      release: chain.releaseStateJson(checked.state),
      verdict: checked.verdict,
      content: content === null ? null : releaseContentJson(content),
    });
    return content === null || content.ok ? 0 : 1;
  }
  assertFlags(args, ["config", "kind", "deadline", "nonce", "submit", "rpc", "print"]);
  assertPositionals(args, 3);
  return guardianActionOutput(io, verb === "approve" ? "approve" : "veto", context, await chain.chainGuardianAction(context, {
    action: verb === "approve" ? "approve" : "veto",
    hash: args.positionals[2] as string,
    ...(args.flags.has("kind") ? { kind: args.flags.get("kind") as string } : {}),
    ...(args.flags.has("deadline") ? { deadline: args.flags.get("deadline") as string } : {}),
    ...(args.flags.has("nonce") ? { nonce: args.flags.get("nonce") as string } : {}),
    submit: submitOf(args),
    print: printOf(args),
  }, { nowMs: io.now() }));
}

/** `releases delay <hours>` (phase 2, 13.13): the relay's release delay on its contract, signed by the guardian. */
async function releasesDelayCommand(args: ParsedArgs, io: CliIo, context: ChainContextValue): Promise<number> {
  assertFlags(args, ["config", "deadline", "nonce", "submit", "rpc", "print", "force"]);
  assertPositionals(args, 3);
  const { releaseDelayFlag } = await import("./init.ts");
  const seconds = releaseDelayFlag(args.positionals[2] as string, "releases delay");
  const chain = await import("./chain.ts");
  const result = await chain.chainSetDelay(context, {
    seconds,
    ...(args.flags.has("deadline") ? { deadline: args.flags.get("deadline") as string } : {}),
    ...(args.flags.has("nonce") ? { nonce: args.flags.get("nonce") as string } : {}),
    submit: submitOf(args),
    print: printOf(args),
    confirmed: args.flags.has("force"),
  }, { nowMs: io.now() });
  const hours = (s: bigint): string => `${Number(s) / 3600} h`;
  if (result.stopped === null) io.stdout(`note: the releases effective by time alone could not be listed (no chain.from_block: set it to the contract's deployment block with gray-assistant config set chain.from_block <n> --json); lengthening the delay makes any of them wait again\n`);
  for (const state of result.stopped ?? []) {
    io.stdout(`stops: ${state.kind === "compose" ? "compose" : "OS image"} ${state.hash} is effective by time alone; at ${hours(seconds)} it waits until ${new Date(Number(state.proposedAt + seconds) * 1000).toISOString()}, and a VM running it loses its accounts at its next KMS re-check (within 10 minutes). Approve it first to keep it: gray-assistant releases approve ${state.hash}\n`);
  }
  if (result.outcome === null) {
    io.stderr("gray-assistant releases delay: nothing signed; run it again with --force to lengthen the delay anyway\n");
    return 1;
  }
  io.stdout(`gray-assistant releases delay: from ${hours(result.previous)} to ${hours(seconds)} for compose and OS image releases (an upgrade of the contract always waits 7 days)\n`);
  return guardianActionOutput(io, "set_delay", context, result.outcome);
}

/** `keys set-guardian|set-recovery <address> --key <recovery-key.json>` (phase 2): the recovery key replaces a key. */
async function keysCommand(args: ParsedArgs, io: CliIo): Promise<number> {
  const verb = args.positionals[1];
  if (verb !== "set-guardian" && verb !== "set-recovery") throw new RelayKitError("usage", "keys takes set-guardian <address> or set-recovery <address>, with --key <recovery-key.json>");
  assertFlags(args, ["config", "key", "deadline", "nonce", "submit", "rpc", "print"]);
  assertPositionals(args, 3);
  const context = await requireChainContext(args, `keys ${verb}`);
  const chain = await import("./chain.ts");
  const which = verb === "set-guardian" ? "guardian" : "recovery";
  const outcome = await chain.chainSetKey(context, {
    which,
    address: args.positionals[2] as string,
    keyPath: requiredFlag(args, "key"),
    ...(args.flags.has("deadline") ? { deadline: args.flags.get("deadline") as string } : {}),
    ...(args.flags.has("nonce") ? { nonce: args.flags.get("nonce") as string } : {}),
    submit: submitOf(args),
    print: printOf(args),
  }, { nowMs: io.now() });
  const code = guardianActionOutput(io, which === "guardian" ? "set_guardian" : "set_recovery", context, outcome);
  if (outcome.transaction?.block != null) {
    io.stdout(
      which === "guardian"
        ? `chain.guardian is now ${outcome.json["new_address"]}: put its key file at chain.guardian_key (${context.chain.guardianKey}) before the next approve, veto or deliver\n`
        : "keep the new recovery key's file offline, as the old one; the old key changes nothing any more\n",
    );
  }
  return code;
}

async function chainSwitchCommand(args: ParsedArgs, io: CliIo, action: "pause" | "unpause", context: ChainContextValue): Promise<number> {
  assertFlags(args, ["config", "deadline", "nonce", "submit", "rpc", "print"]);
  assertPositionals(args, 1);
  const chain = await import("./chain.ts");
  return guardianActionOutput(io, action, context, await chain.chainGuardianAction(context, {
    action,
    ...(args.flags.has("deadline") ? { deadline: args.flags.get("deadline") as string } : {}),
    ...(args.flags.has("nonce") ? { nonce: args.flags.get("nonce") as string } : {}),
    submit: submitOf(args),
    print: printOf(args),
  }, { nowMs: io.now() }));
}

const ACTION_COMMAND = { approve: "releases approve", veto: "releases reject", pause: "pause", unpause: "unpause", set_delay: "releases delay", set_guardian: "keys set-guardian", set_recovery: "keys set-recovery" } as const;
const ACTION_WORDS = { approve: "the guardian's approval", veto: "the guardian's veto", pause: "the guardian's pause", unpause: "the guardian's unpause", set_delay: "the guardian's new release delay", set_guardian: "the recovery key's new guardian", set_recovery: "the recovery key's new recovery address" } as const;
const ACTION_STATE = { approve: "the release", veto: "the release", pause: "the off switch", unpause: "the off switch", set_delay: "the delay", set_guardian: "the keys", set_recovery: "the keys" } as const;

function guardianActionOutput(io: CliIo, action: keyof typeof ACTION_COMMAND, context: ChainContextValue, outcome: Awaited<ReturnType<(typeof import("./chain.ts"))["chainGuardianAction"]>>): number {
  const name = `gray-assistant ${ACTION_COMMAND[action]}`;
  io.stdout(
    `${name}: signed ${ACTION_WORDS[action]} for ${context.chain.contract} (version ${outcome.json["version"]}, nonce ${outcome.json["nonce"]}, valid until ${new Date(Number(outcome.json["deadline"]) * 1000).toISOString()})\n`,
  );
  if (outcome.note !== null) io.stdout(`note: ${outcome.note}\n`);
  const by = outcome.via === "relayer" ? " through Gray's relayer" : "";
  if (outcome.transaction === null) {
    io.stdout("not sent (--print): send it without --print (Gray's relayer), or yourself with --submit --rpc <url> from the signing key (it pays the gas)\n");
    io.stdout(`      it decides version ${outcome.json["version"]} of ${ACTION_STATE[action]}: any later decision on it, by you or your recovery key, makes this signature void (the contract answers SupersededSignature)\n`);
  }
  else if (outcome.transaction.block === null) io.stdout(`sent${by}: transaction ${outcome.transaction.hash}, not mined within the wait; look it up on the chain's explorer\n`);
  else io.stdout(`sent${by}: transaction ${outcome.transaction.hash}, mined in block ${outcome.transaction.block}\n`);
  printPlainJson(io, {
    command: name.slice("gray-assistant ".length),
    signed: true,
    via: outcome.via,
    message: outcome.json,
    transaction: outcome.transaction === null ? null : outcome.transaction.hash,
    block: outcome.transaction?.block === null || outcome.transaction === null ? null : outcome.transaction.block.toString(),
  });
  return 0;
}

/** A chain command's JSON line: plain JSON numbers (a chain id is 8453, not 8453.0), integers above 2^53 as strings. */
function printPlainJson(io: CliIo, value: Record<string, unknown>): void {
  io.stdout(`${JSON.stringify(value)}\n`);
}

function printJson(io: CliIo, value: JsonObject): void {
  io.stdout(`${toJsonString(value)}\n`);
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}
