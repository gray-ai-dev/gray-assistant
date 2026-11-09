/**
 * Phase 2's one-shot deliveries (docs/design/relay-no-always-on-host.md §3.3, §3.5, 13.3; P4b): what the relay runs on
 * a laptop, once, for a VM that keeps no host of the relay's.
 *
 *     gray-assistant deliver                 the first delivery (the VM waits in the empty slot), or after any change
 *     gray-assistant accounts push           the accounts only (a serving VM)
 *     gray-assistant registry set            a new registry login under the designation the VM runs
 *     gray-assistant stack rollout <image>   a new designation, then the restart
 *     gray-assistant stack rollback          the designation's previous image again, then the restart
 *     gray-assistant stack restart           the restart alone, accepted on the new boot's own attestation
 *
 * The first delivery of a paired kit (`stack.instance: "gray"`, no VM adopted) asks Gray which VM it deployed (the
 * answer to a signed agent status, P12), requires its app to be `chain.contract`'s and its lane origin the entry's
 * tunnel to this relay, and adopts it into control.json once the VM's quote proves it (step 1) and the checks below pass.
 *
 * Each, for a config with a `chain` member and a `stack` section:
 *
 * 1. **Attest** the relay's stack VM through Gray's entry with the agent's own attestation (`createDaemonAttest`: the
 *    quote, the replay, the signed release list, the instance, whose app id must be `chain.contract`), accepting a
 *    phase-2 boot in the empty slot (`allowEmptySlot`, this command's alone), and hold the boot to this relay: its
 *    identity names this relay and this relay key, and a sealed boot runs a designation (phase 2), not a token
 *    service's image (phase 1).
 * 2. **Check the contract** from the config's two RPC endpoints, which must agree (`checkRelayContract`, P4a): the code,
 *    the guardian, the delay, the KMS registration, not paused, and the compose hash and OS image hash this VM measured
 *    `effective`. Before it (P6), the compose the VM measured is checked by its text, which Gray's signed release list
 *    publishes (`app_compose`): it hashes to the measured hash, passes `@gray/lane-compose`'s closed policy with the
 *    list's expectation, names the KMS of the relay's app as its key provider, keeps the KMS lease (`LANE_KMS_URL`) and
 *    binds the vault (`../chain/release-compose.ts`). A list that does not publish the text refuses the delivery.
 * 3. **Build** what to send: the designation (`seq` one above the highest this relay issued, kept in `designation.json`
 *    beside the state file and written before anything is sent, under its lock so two commands never sign one seq, and
 *    above the one the VM runs; `previous` the image the VM attests it runs, never one only signed here), signed with
 *    the relay key, with the registry login of `stack.registry` (its password file), as the boot
 *    box (`@gray/relay-connector/boot-box`); the accounts read once from the source (`./deliver-accounts.ts`). Accounts
 *    for the image the VM runs now go only while it is one of `stack.relay_images`.
 * 4. **Send** them sealed to the attested boot's intake key, signed by the relay key: the boot box to
 *    `/v1/aci/relay-boot-box`, then the accounts to `/v1/aci/relay-credentials`, each pinned to the TLS key the VM
 *    attested (Gray's entry carries ciphertext only), and print the VM's receipts.
 * 5. **Restart** when the receipt says so (the empty slot, or another image): the relay-signed restart request (S53) to
 *    Gray, which the provisioner runs; the relay signs it, Gray only carries it out. Meanwhile the VM restarts (about
 *    95 s, S53): the entry routes nothing to it, and the panel shows it restarting. Unless `--no-wait`, the command then
 *    attests the VM again until it runs the designated image.
 *
 * Exit codes: 0 done, 1 refused (an unattested VM, the contract, the VM's refusal, a restart Gray refused, a timeout),
 * 2 usage or I/O. stdout gets sentences and one JSON line; nothing secret is printed (the registry password, the
 * accounts' credentials and the seeds stay in this process).
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { bytesToLowerHex, ed25519PublicKey, ed25519Sign } from "@gray/attest";
import { stackInstanceAnswerSchema } from "@gray/control/stack-provision";
import { get, isObject, parseStrict, parseStrictBytes, toJsonString, type Json, type JsonObject } from "@gray/json";
import { isRelayDesignationClaim, type StackBootFacts } from "@gray/lane-verify";
import { sealBootBoxDelivery, sealCredentialBundle, type CredentialBundle } from "@gray/relay-connector";
import { BOOT_BOX_DELIVERY_PATH, imageRegistry, type BootBox } from "@gray/relay-connector/boot-box";
import { designationMessage, type Designation } from "@gray/relay-connector/vault";
import type { Hex } from "viem";
import type { ChainCheckResult } from "../chain/checks.ts";
import type { ReleaseContentResult } from "../chain/release-compose.ts";
import { AGENT_STATUS_PATH, agentStatusDocument, signAgentStatus } from "../daemon/agent-status.ts";
import { attestationMismatch } from "../daemon/stack-boot.ts";
import { DaemonTransportError, type DaemonAttestResult, type DaemonFetch, type DaemonStackInstance } from "../daemon/types.ts";
import { LANE_ENDPOINTS, RELAY_KIT_VERSION } from "../endpoints.ts";
import { RelayKitError } from "../errors.ts";
import { isLaneBinding, type LaneBinding } from "../lane-binding.ts";
import { tunnelOriginOf } from "../lane-origin.ts";
import { normalizeHttpsOrigin } from "../verified-report.ts";
import type { ChainContext } from "./chain.ts";
import type { LoadedRelayConfig } from "./config-file.ts";
import { acquireControlLock } from "./control-lock.ts";
import { controlFileBeside, inspectControlFile } from "./daemon/control-file.ts";
import { writeAtomicPrivateFile } from "./daemon/atomic-file.ts";
import { debugStackVm } from "./debug.ts";
import type { ReadAccounts } from "./deliver-accounts.ts";
import { readControlView, setStackImageState, setStackInstanceState } from "./control.ts";
import { signedStackRestartRequest, stackRestartRequest, STACK_RESTART_REQUEST_PATH, type StackPost } from "./stack.ts";

export type DeliverAction = "deliver" | "accounts" | "registry" | "rollout" | "rollback" | "restart";

/** The relay's own record of the designations it issued, beside the state file (0600, not secret). */
export const DESIGNATION_STATE_FILE = "designation.json";
/** How long a restart is waited for by default: one restart (~95 s, S53) and an image pull, with room. */
export const DELIVER_WAIT_DEFAULT_MS = 15 * 60_000;
const DELIVER_WAIT_POLL_MS = 10_000;
/** The largest answer the VM gives (a receipt, a refusal). */
const ANSWER_MAX_BYTES = 64 * 1024;

export interface DeliverIo {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
  readonly now: () => number;
  readonly random: (length: number) => Uint8Array;
  readonly sleep: (ms: number) => Promise<void>;
}

/** One attestation of the stack VM (the CLI's fetches the signed release list and loads the quote verifier first). */
export type DeliverAttest = (input: { readonly origin: string; readonly instance?: LaneBinding; readonly nowSecs: bigint; readonly allowEmptySlot: boolean }) => Promise<DaemonAttestResult>;

export interface DeliverOptions {
  readonly config: LoadedRelayConfig;
  readonly chain: ChainContext;
  /** The relay key's seed. */
  readonly seed: Uint8Array;
  readonly io: DeliverIo;
  readonly action: DeliverAction;
  /** `stack rollout <image>`'s image. */
  readonly image?: string | null;
  readonly wait: boolean;
  readonly timeoutMs?: number;
  /** Tests replace the attestation, the pinned fetch, Gray's POST, the chain read, the source and the password file. */
  readonly attest?: DeliverAttest;
  readonly fetch?: DaemonFetch;
  readonly post?: StackPost;
  readonly chainCheck?: (composeHash: Hex | null, osImageHash: Hex | null) => Promise<ChainCheckResult>;
  /** P6: the check of the measured compose's published text (bare hex hash); by default from Gray's signed list. */
  readonly releaseContent?: (composeHash: string) => Promise<ReleaseContentResult>;
  readonly readAccounts?: () => Promise<ReadAccounts>;
  readonly registryPassword?: () => string;
  /**
   * The first delivery with `stack.instance: "gray"` and no adopted VM: Gray's answer naming the relay's lane instance
   * (`instance` of its answer to a signed agent status), by default posted to `stack.report_origin`.
   */
  readonly stackInstance?: () => Promise<unknown>;
}

/** What `designation.json` holds: the highest seq issued and the last designation, with its signature. */
export interface DesignationState {
  readonly seq: number;
  readonly designation: Designation | null;
  readonly signature: string | null;
}

const COMMAND_NAMES: Readonly<Record<DeliverAction, string>> = {
  deliver: "deliver",
  accounts: "accounts push",
  registry: "registry set",
  rollout: "stack rollout",
  rollback: "stack rollback",
  restart: "stack restart",
};
const RELAY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
/** How long a command waits for another one's designation (its read, sign and write take milliseconds). */
const DESIGNATION_LOCK_TIMEOUT_MS = 30_000;
/** Gray's deployments whose named instance the first delivery adopts once the VM's quote proves it (as the agent, P12 rule 3). */
const LIVE_DEPLOYMENTS: ReadonlySet<string> = new Set(["deploying", "running", "restarting"]);

export function designationStatePath(config: LoadedRelayConfig): string {
  return join(dirname(config.daemon.stateFile), DESIGNATION_STATE_FILE);
}

/**
 * `designation.json`, or the empty state when there is none (ENOENT only). A file that does not read, for any other
 * reason (its permissions, an I/O error) or as a document, is an I/O error: never a seq below the one issued.
 */
export function readDesignationState(path: string): DesignationState {
  const fail = (): never => {
    throw new RelayKitError("io", `${path} does not read: it holds the designation seq this relay issued (fix it or restore it, never delete it)`);
  };
  let text: string;
  try {
    text = readFileSync(resolve(path), "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { seq: 0, designation: null, signature: null };
    return fail();
  }
  let value: Json;
  try {
    value = parseStrict(text);
  } catch {
    return fail();
  }
  if (!isObject(value)) return fail();
  const seq = get(value, "seq");
  const d = get(value, "designation");
  const signature = get(value, "designation_sig");
  if (typeof seq !== "bigint" || seq < 0n || seq > BigInt(Number.MAX_SAFE_INTEGER)) return fail();
  if (d === null) return { seq: Number(seq), designation: null, signature: null };
  if (!isObject(d) || typeof signature !== "string" || !/^[0-9a-f]{128}$/.test(signature)) return fail();
  const image = get(d, "image");
  const previous = get(d, "previous");
  const relayId = get(d, "relay_id");
  const dSeq = get(d, "seq");
  const issued = get(d, "issued_ms");
  if (typeof image !== "string" || !(previous === null || typeof previous === "string") || typeof relayId !== "string" || typeof dSeq !== "bigint" || typeof issued !== "bigint") return fail();
  return { seq: Number(seq), designation: { image, previous, relayId, seq: Number(dSeq), issuedMs: Number(issued) }, signature };
}

function writeDesignationState(path: string, state: DesignationState): void {
  const d = state.designation;
  writeAtomicPrivateFile(
    path,
    `${toJsonString({
      api_version: 1n,
      seq: BigInt(state.seq),
      designation: d === null ? null : { image: d.image, issued_ms: BigInt(d.issuedMs), previous: d.previous, relay_id: d.relayId, seq: BigInt(d.seq) },
      designation_sig: state.signature,
    })}\n`,
  );
}

/** The stack VM and the instance its quote must prove: the relay's own contract's app (`chain.contract`). */
export function phase2Vm(config: LoadedRelayConfig, chain: ChainContext): { readonly origin: string; readonly instance: LaneBinding } {
  const vm = debugStackVm(config);
  const instance = vm.instance ?? config.daemon.lane.instances.get(vm.origin) ?? null;
  if (instance === null) throw new RelayKitError("usage", `lane.instances names no app for ${vm.origin}`);
  const contract = chain.chain.contract.slice(2).toLowerCase();
  if (instance.appId !== contract) {
    throw new RelayKitError("usage", `the stack VM's app is ${instance.appId}, but chain.contract is ${chain.chain.contract}: a delivery goes only to the app of the relay's own contract`);
  }
  return { origin: vm.origin, instance };
}

/** The stack VM as `phase2Vm` names it, or null while `stack.instance` is "gray" and control.json has adopted none yet. */
function adoptedPhase2Vm(config: LoadedRelayConfig, chain: ChainContext): { readonly origin: string; readonly instance: LaneBinding } | null {
  const stack = config.daemon.stack;
  if (stack !== null && stack.instanceSource === "gray" && stack.laneOrigin === null) {
    const inspected = inspectControlFile(controlFileBeside(config.daemon.stateFile));
    if (inspected.kind === "missing" || (inspected.kind === "ok" && (inspected.control.stackInstance ?? null) === null)) return null;
  }
  return phase2Vm(config, chain);
}

/**
 * The first delivery's VM (`stack.instance: "gray"`, none adopted): Gray's answer, read as the agent reads it (P12
 * rule 3: three values in their forms, a live deployment, the entry's tunnel to this relay's VM), and its app must be
 * `chain.contract`'s. It is adopted only once the VM's quote proves it (`deliverCommand`). Throws a usage error otherwise.
 */
export function phase2Candidate(answer: unknown, relayId: string, chain: ChainContext): DaemonStackInstance & { readonly adoptedMs: 0 } {
  const parsed = stackInstanceAnswerSchema.safeParse(answer);
  if (!parsed.success) throw new RelayKitError("usage", "Gray's answer names no lane instance this gray-assistant reads; upgrade gray-assistant, or tell Gray");
  const named = parsed.data;
  if (named.app_id === null || named.lane_origin === null || named.kms_ca_pubkey === null || !LIVE_DEPLOYMENTS.has(named.deployment)) {
    throw new RelayKitError("usage", `Gray names no running VM for this relay yet (deployment ${named.deployment}): Deploy it in the panel, then run \`gray-assistant deliver\` again`);
  }
  if (!isLaneBinding({ appId: named.app_id, kmsCaPubkey: named.kms_ca_pubkey })) throw new RelayKitError("usage", "Gray's answer names a lane instance that is not an app id and a KMS key");
  let laneOrigin: string;
  try {
    laneOrigin = normalizeHttpsOrigin(named.lane_origin);
  } catch {
    throw new RelayKitError("usage", "Gray's answer names a lane origin that is not an https origin");
  }
  const tunnel = tunnelOriginOf(laneOrigin);
  if (tunnel === null || tunnel.relayId !== relayId) {
    throw new RelayKitError("usage", `Gray names ${laneOrigin}, which is not the entry's tunnel to this relay's VM (${relayId}); ask Gray to correct the relay's lane instance`);
  }
  const contract = chain.chain.contract.slice(2).toLowerCase();
  if (named.app_id !== contract) {
    throw new RelayKitError("usage", `Gray names app ${named.app_id}, but chain.contract is ${chain.chain.contract}: a delivery goes only to the app of the relay's own contract`);
  }
  return { appId: named.app_id, kmsCaPubkey: named.kms_ca_pubkey, laneOrigin, adoptedMs: 0 };
}

/**
 * Gray's answer naming the relay's lane instance: the console answers it to a signed agent status only (S45, P12), so
 * this posts one with nothing in it but the relay and this kit's version (a host-less relay runs no agent, so no
 * other status is overwritten; `accepted_compose` null: no release registry here).
 */
async function cliStackInstance(config: LoadedRelayConfig, seed: Uint8Array, nowMs: number): Promise<unknown> {
  const stack = config.daemon.stack;
  if (stack === null) throw new RelayKitError("usage", "the config has no `stack` section");
  const { status } = agentStatusDocument({
    relayId: config.daemon.relayId,
    issuedMs: nowMs,
    agentVersion: RELAY_KIT_VERSION,
    stackOrigin: "",
    logins: [],
    replicas: [],
    parked: [],
    sources: null,
    acceptedCompose: null,
  });
  const url = `${stack.reportOrigin}${AGENT_STATUS_PATH}`;
  let answer: { readonly status: number; readonly text: string };
  try {
    answer = await defaultPost(url, toJsonString(await signAgentStatus(status, seed)));
  } catch {
    throw new RelayKitError("io", `Gray did not answer at ${url}, so the relay's VM is not known yet; run the command again`);
  }
  if (answer.status < 200 || answer.status > 299) throw new RelayKitError("io", `Gray refused the status that asks for the relay's VM (HTTP ${answer.status})`);
  try {
    return get(parseStrict(answer.text), "instance");
  } catch {
    throw new RelayKitError("io", "Gray's answer naming the relay's VM is not JSON");
  }
}

/** A phase-2 boot of this relay: the empty slot, or a sealed boot running a designation. */
export type Phase2Boot = { readonly ok: true; readonly running: null; readonly seq: 0; readonly previous: null } | { readonly ok: true; readonly running: string; readonly seq: number; readonly previous: string | null } | { readonly ok: false; readonly code: string; readonly message: string };

export function phase2Boot(facts: StackBootFacts | null | undefined, relayId: string, relayKeyHex: string): Phase2Boot {
  if (facts === null || facts === undefined) return { ok: false, code: "stack_boot_missing", message: "the VM measured no relay-stack boot" };
  if (facts.identity.relayId !== relayId || facts.identity.publicKey !== relayKeyHex) {
    return { ok: false, code: "stack_identity_mismatch", message: "the VM's measured identity is not this relay and this relay key (relay-key.json)" };
  }
  if (facts.phase === "empty_slot") return { ok: true, running: null, seq: 0, previous: null };
  if (facts.phase !== "sealed") return { ok: false, code: "stack_boot_not_sealed", message: "the VM's quote was taken before pre-launch sealed the boot" };
  if (!isRelayDesignationClaim(facts.image)) {
    return { ok: false, code: "stack_boot_phase1", message: "the VM is a phase-1 boot (its image comes from your token service): run the agent (`gray-assistant run`) for it, not a delivery" };
  }
  return { ok: true, running: facts.image.image, seq: facts.image.seq, previous: facts.image.previous };
}

function bareKeyset(digest: string): string {
  return digest.startsWith("sha256:") ? digest.slice("sha256:".length) : digest;
}

/** The VM's error code (`{"error": {"code": …}}`), or null. Only a lower-case word is printed. */
function errorCodeOf(body: Uint8Array): string | null {
  try {
    const error = get(parseStrictBytes(body), "error");
    const code = isObject(error) ? get(error, "code") : null;
    return typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? code : null;
  } catch {
    return null;
  }
}

/** The default attestation: the signed release list, the quote verifier and the agent's own attestation seam. */
function cliAttest(config: LoadedRelayConfig): DeliverAttest {
  return async (input) => {
    const { releaseListForCommand } = await import("./release-control.ts");
    const { loadQuoteVerifier } = await import("./attest.ts");
    const { createDaemonAttest } = await import("./run.ts");
    const verified = await releaseListForCommand(config, Number(input.nowSecs) * 1000);
    const quoteVerifier = await loadQuoteVerifier(config.daemon.pccsUrl === null ? {} : { pccs: config.daemon.pccsUrl });
    return createDaemonAttest({ config, quoteVerifier })({
      origin: input.origin,
      release: verified.list,
      nowSecs: input.nowSecs,
      ...(input.instance === undefined ? {} : { instance: input.instance }),
      allowEmptySlot: input.allowEmptySlot,
    });
  };
}

/** P6's default: the signed release list, and the measured compose's published text checked against the config. */
async function cliReleaseContent(config: LoadedRelayConfig, instance: LaneBinding, composeHash: string, nowMs: number): Promise<ReleaseContentResult> {
  const { releaseListForCommand } = await import("./release-control.ts");
  const { checkReleaseCompose } = await import("../chain/release-compose.ts");
  const { releaseExpectationOf } = await import("./release-content.ts");
  const verified = await releaseListForCommand(config, nowMs);
  return checkReleaseCompose(verified.list, composeHash, releaseExpectationOf(config, instance));
}

/** The delivery's refusal code for a compose that does not pass. */
const CONTENT_CODES: Readonly<Record<string, string>> = {
  release_not_listed: "compose_not_listed",
  compose_not_published: "compose_not_published",
  release_not_stack: "compose_not_stack",
  compose_refused: "compose_refused",
};

async function cliAccounts(config: LoadedRelayConfig, nowMs: number): Promise<ReadAccounts> {
  const { createSourceAdapter } = await import("./source/config.ts");
  const { accountAliasesPath, createFileAccountAliasStore } = await import("./daemon/account-aliases-file.ts");
  const { readAccountsOnce } = await import("./deliver-accounts.ts");
  return readAccountsOnce(config, {
    adapter: createSourceAdapter(config.source),
    aliases: createFileAccountAliasStore(accountAliasesPath(config.daemon.stateFile)),
    nowMs,
    signal: AbortSignal.timeout(config.source.requestTimeoutMs),
  });
}

const defaultPost: StackPost = async (url, body) => {
  const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json", "user-agent": "gray-assistant" }, body, redirect: "error", signal: AbortSignal.timeout(20_000) });
  return { status: response.status, text: await response.text() };
};

/** The sentence for each code the VM's intake answers a delivery with. */
function vmRefusal(status: number, code: string | null, what: "boot box" | "accounts"): string {
  switch (code) {
    case "designation_seq_below":
      return `the VM has seen a newer designation than this one (designation_seq_below): ${DESIGNATION_STATE_FILE} is behind; run the command again`;
    case "designation_signature_invalid":
    case "bad_relay_signature":
      return `the VM did not accept the signature (${code}): relay-key.json is not the key the VM measured`;
    case "unknown_relay":
    case "boot_box_relay_mismatch":
      return `the VM serves another relay (${code}): the config's relay_id is not the one the VM booted with`;
    case "boot_box_replay":
      return "the VM took a later delivery in this boot (boot_box_replay): this machine's clock is behind; set it right and run the command again";
    case "relay_empty_slot":
      return "the VM waits for its boot box first (relay_empty_slot): run `gray-assistant deliver`";
    case "boot_box_unavailable":
    case "boot_box_write_failed":
    case "vault_unavailable":
    case "vault_write_failed":
      return `the VM could not keep the ${what} now (${code}); run the command again in a minute`;
    case "boot_box_unsupported":
      return "the VM keeps no boot box (boot_box_unsupported): it is not a phase-2 VM";
    default:
      break;
  }
  if (status === 404) return "the VM does not take boot boxes (404): its Gray release is older than phase 2's delivery";
  return `the VM refused the ${what} (${status}${code === null ? "" : ` ${code}`})`;
}

/** Run one delivery command (see the module comment). Returns the exit code. */
export async function deliverCommand(options: DeliverOptions): Promise<number> {
  const { config, io, action, seed } = options;
  const name = COMMAND_NAMES[action];
  const relayId = config.daemon.relayId;
  const stack = config.daemon.stack;
  if (stack === null) throw new RelayKitError("usage", `the config has no \`stack\` section: \`gray-assistant ${name}\` is for a relay-stack VM`);
  if (!RELAY_ID.test(relayId)) throw new RelayKitError("usage", "relay_id is not an id a designation names");
  const refuse = (code: string, message: string, extra: JsonObject = {}): number => {
    io.stderr(`gray-assistant ${name}: ${message}\n`);
    io.stdout(`${toJsonString({ command: name.replace(" ", "."), ok: false, relay_id: relayId, code, ...extra })}\n`);
    return 1;
  };
  // 0. The VM: the adopted one, or for the first delivery (`stack.instance: "gray"`) the one Gray names, of the relay's
  // own contract's app, adopted below once its quote proves it (the agent adopted it at its first token request in
  // phase 1; a phase-2 boot asks for no token).
  let vm = adoptedPhase2Vm(config, options.chain);
  let candidate: DaemonStackInstance | null = null;
  if (vm === null) {
    if (action !== "deliver") throw new RelayKitError("usage", "no stack VM adopted yet: `gray-assistant deliver` adopts the VM Gray deployed once its quote proves it");
    candidate = phase2Candidate(await (options.stackInstance ?? (() => cliStackInstance(config, seed, io.now())))(), relayId, options.chain);
    vm = { origin: candidate.laneOrigin, instance: { appId: candidate.appId, kmsCaPubkey: candidate.kmsCaPubkey } };
    io.stdout(`gray-assistant ${name}: Gray names app ${candidate.appId} at ${candidate.laneOrigin}; it is adopted once its quote proves it\n`);
  }
  const relayKeyHex = bytesToLowerHex(await ed25519PublicKey(seed));
  const attest = options.attest ?? cliAttest(config);
  if (action === "restart") return phase2Restart(options, vm, relayKeyHex, attest, refuse);

  // 1. The VM.
  const nowSecs = BigInt(Math.floor(io.now() / 1000));
  let attested: DaemonAttestResult;
  try {
    attested = await attest({ origin: vm.origin, instance: vm.instance, nowSecs, allowEmptySlot: true });
  } catch (error) {
    if (error instanceof RelayKitError && (error.code === "usage" || error.code === "io")) throw error;
    return refuse("attest_transport_io", "the stack VM could not be attested; `gray-assistant doctor` checks the path to it");
  }
  if (!attested.ok) return refuse(`attest_${attested.stage}_${attested.code}`, `the stack VM did not attest (attest_${attested.stage}_${attested.code}); nothing was sent`);
  const mismatch = attestationMismatch(attested, vm.origin, relayId);
  if (mismatch !== null) return refuse(mismatch, `the attestation is not this relay's VM at ${vm.origin} (${mismatch}); nothing was sent`);
  const boot = phase2Boot(attested.stackBoot, relayId, relayKeyHex);
  if (!boot.ok) return refuse(`attest_${boot.code}`, `${boot.message} (attest_${boot.code}); nothing was sent`);
  io.stdout(`gray-assistant ${name}: the VM attests ${boot.running === null ? "the empty slot: it waits for its first delivery" : `${boot.running} (designation seq ${boot.seq})`}\n`);

  // 1b. The compose the VM measured, by its published text (P6).
  if (attested.composeHash === null) return refuse("compose_unmeasured", "the VM's quote measured no compose hash; nothing was sent");
  let content: ReleaseContentResult;
  try {
    content = options.releaseContent !== undefined ? await options.releaseContent(attested.composeHash) : await cliReleaseContent(config, vm.instance, attested.composeHash, io.now());
  } catch (error) {
    if (error instanceof RelayKitError && error.code === "usage") throw error;
    return refuse("release_list_unavailable", "Gray's signed release list could not be read, so the VM's compose was not checked; nothing was sent");
  }
  if (!content.ok) {
    for (const check of content.checks.filter((c) => !c.ok)) io.stderr(`gray-assistant ${name}: compose ${check.name}: ${check.detail}\n`);
    const code = CONTENT_CODES[content.code] ?? "compose_refused";
    return refuse(code, `the VM's compose does not pass this relay's checks (${code}); nothing was sent`);
  }
  io.stdout(`gray-assistant ${name}: the VM's compose passes (Gray's published text, hashed and checked here: the closed policy, the KMS, the lease, the vault)\n`);

  // 2. The relay's contract.
  const compose = `0x${attested.composeHash}` as Hex;
  const osImage = attested.osImageHash === null ? null : (`0x${attested.osImageHash}` as Hex);
  let chain: ChainCheckResult;
  try {
    chain = options.chainCheck !== undefined ? await options.chainCheck(compose, osImage) : (await (await import("./chain.ts")).chainChecksFor(options.chain, compose, osImage, { nowMs: io.now() })).result;
  } catch (error) {
    if (error instanceof RelayKitError && error.code === "usage") throw error;
    return refuse("chain_unreachable", "the relay's contract could not be read; nothing was sent");
  }
  if (!chain.ok) {
    for (const check of chain.checks.filter((c) => !c.ok)) io.stderr(`gray-assistant ${name}: chain ${check.name}: ${check.detail}\n`);
    return refuse(`chain_${chain.reason}`, `the relay's contract does not allow this VM (chain ${chain.reason}: ${chain.detail}); nothing was sent`);
  }
  io.stdout(`gray-assistant ${name}: the contract ${options.chain.chain.contract} allows this VM's compose and OS image (block ${chain.block}, both endpoints agree)\n`);

  // 2b. The first delivery's VM proved itself (the relay's identity, the contract's app, its KMS): adopt it before
  // anything is sent, so every later command reaches the same VM.
  const controlFile = controlFileBeside(config.daemon.stateFile);
  if (candidate !== null) {
    await setStackInstanceState(controlFile, config.daemon.stateFile, { ...candidate, adoptedMs: io.now() });
    io.stdout(`gray-assistant ${name}: adopted the stack VM ${candidate.appId} at ${candidate.laneOrigin} (its quote proves it)\n`);
  }

  // 3. What to send.
  const statePath = designationStatePath(config);
  const view = await readControlView(config.daemon.stateFile, controlFile);
  const configured = view.control.stackCurrentImage ?? stack.currentImage;
  let target: string | null = null;
  let sendAccounts = false;
  switch (action) {
    case "deliver":
      target = boot.running === configured ? null : configured;
      sendAccounts = true;
      break;
    case "accounts":
      if (boot.running === null) return refuse("relay_empty_slot", "the VM waits for its first delivery: run `gray-assistant deliver`");
      target = null;
      sendAccounts = true;
      break;
    case "registry":
      if (boot.running === null) return refuse("relay_empty_slot", "the VM waits for its first delivery: run `gray-assistant deliver`, which seals the login too");
      target = boot.running;
      sendAccounts = false;
      break;
    case "rollout":
      if (options.image === null || options.image === undefined) throw new RelayKitError("usage", "stack rollout needs the image: one of stack.relay_images");
      target = options.image;
      sendAccounts = false;
      break;
    case "rollback": {
      // The designation the VM attests, never this machine's record: a designation signed here may never have run.
      if (boot.previous === null) throw new RelayKitError("usage", "stack rollback: the designation the VM runs names no previous image");
      target = boot.previous;
      sendAccounts = false;
      break;
    }
  }
  if (target !== null && !stack.relayImages.includes(target)) {
    throw new RelayKitError("usage", `${target} is not one of stack.relay_images; add it to the config first`);
  }
  // Accounts that go to the image the VM runs now (no new designation): only while that image is still one of the
  // relay's (the phase-1 token service's rule, `stackBootDecision`). An image taken out of stack.relay_images gets none.
  if (sendAccounts && target === null && boot.running !== null && !stack.relayImages.includes(boot.running)) {
    return refuse(
      "running_image_not_allowed",
      `the VM runs ${boot.running}, which is not one of stack.relay_images: no accounts go to it; move it to an allowed image first (\`gray-assistant stack rollout <image>\`); nothing was sent`,
    );
  }

  let box: BootBox | null = null;
  if (target !== null) {
    const host = imageRegistry(target);
    if (host === null || host !== stack.registry.host) {
      throw new RelayKitError("usage", `stack.registry.host is ${stack.registry.host}, but ${target} is in ${host ?? "no registry"}: the login is for the designated image's registry`);
    }
    const password = options.registryPassword !== undefined ? options.registryPassword() : (await import("./files.ts")).readPrivateFile(stack.registry.passwordFile, "registry password", 8192).trim();
    // `registry set` keeps the designation the VM runs; everything else designates anew, above every seq seen. The
    // read, the seq, the signature and the write are one step under designation.json's lock, so two commands at once
    // never sign one seq for two images; the write comes before anything is sent.
    let designation: Designation;
    let signature: string;
    const lock = await acquireControlLock(`${statePath}.lock`, { timeoutMs: DESIGNATION_LOCK_TIMEOUT_MS });
    try {
      const state = readDesignationState(statePath);
      const last = state.designation;
      if (action === "registry" && last !== null && state.signature !== null && last.image === target && last.seq === boot.seq && last.relayId === relayId) {
        designation = last;
        signature = state.signature;
      } else {
        // `previous` is the image the VM attests it runs, or, re-designating that image, the one its attested
        // designation names: never an image this machine only signed (a rollout that never reached the VM).
        const previous = boot.running === null ? null : boot.running !== target ? boot.running : boot.previous;
        designation = { relayId, image: target, previous: previous === target ? null : previous, seq: Math.max(state.seq, boot.seq) + 1, issuedMs: io.now() };
        signature = bytesToLowerHex(await ed25519Sign(seed, designationMessage(designation)));
        // Kept before anything is sent: a seq is never issued twice, even when the delivery fails.
        writeDesignationState(statePath, { seq: designation.seq, designation, signature });
      }
    } finally {
      lock.release();
    }
    box = { registry: { host, username: stack.registry.username, password, expiresAt: stack.registry.expiresAt }, designation, designationSig: signature };
  }

  let accounts: ReadAccounts | null = null;
  if (sendAccounts) {
    accounts = await (options.readAccounts ?? (() => cliAccounts(config, io.now())))();
    for (const skipped of accounts.skipped) {
      io.stderr(`gray-assistant ${name}: left out a ${skipped.vendor} account${skipped.panelId === null ? "" : ` (${skipped.panelId})`}: ${skipped.reason}\n`);
    }
    if (accounts.accounts.length === 0 && accounts.listed > 0) io.stderr(`gray-assistant ${name}: no account of the source can be sealed; the VM keeps none\n`);
  }

  // 4. Send, sealed to the attested boot, pinned to the TLS key it attested.
  const fetch = options.fetch ?? (await import("./daemon/fetch.ts")).createPinnedDaemonFetch({ maxResponseBytes: ANSWER_MAX_BYTES });
  const tunnel = tunnelOriginOf(vm.origin) !== null;
  const post = async (path: string, body: JsonObject): Promise<{ readonly status: number; readonly body: Uint8Array } | { readonly transport: string }> => {
    try {
      const response = await fetch(`${vm.origin}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "user-agent": "gray-assistant" },
        body: new TextEncoder().encode(toJsonString(body)),
        expectedSpkiSha256: attested.tlsSpkiSha256,
        timeoutMs: 60_000,
        ...(tunnel ? { tunnelKeyset: bareKeyset(attested.keysetDigest) } : {}),
      });
      return { status: response.status, body: response.body };
    } catch (error) {
      return { transport: error instanceof DaemonTransportError || error instanceof RelayKitError ? error.code : "io" };
    }
  };
  const report = attested.checked.report;
  const nonce = attested.checked.file.nonce;
  const sealNowSecs = BigInt(Math.floor(io.now() / 1000));
  // The delivery versions: the clock in ms, as the credential commands choose one, above what this relay last sent.
  const versionBase = BigInt(io.now());

  let receipt: JsonObject | null = null;
  if (box !== null) {
    const sealed = await sealBootBoxDelivery(report, seed, { relayId, version: versionBase, box }, { nonce, quoteVerified: true, nowSecs: sealNowSecs });
    const answer = await post(BOOT_BOX_DELIVERY_PATH, sealed);
    if ("transport" in answer) return refuse(`transport_${answer.transport}`, `the boot box did not reach the VM through Gray's entry (${answer.transport}); run the command again`);
    if (answer.status !== 200) return refuse(errorCodeOf(answer.body) ?? `http_${answer.status}`, vmRefusal(answer.status, errorCodeOf(answer.body), "boot box"));
    try {
      const value = parseStrictBytes(answer.body);
      if (!isObject(value)) throw new Error("not an object");
      receipt = value;
    } catch {
      return refuse("answer_invalid", "the VM's receipt for the boot box did not read");
    }
    io.stdout(
      `gray-assistant ${name}: the VM keeps boot box version ${String(get(receipt, "boot_version"))} designating ${box.designation.image} (seq ${box.designation.seq}); Gray's copy ${String(get(receipt, "copy"))}\n`,
    );
  }

  let accountsReceipt: JsonObject | null = null;
  if (accounts !== null) {
    const issuedAt = sealNowSecs;
    const bundle: CredentialBundle = {
      relay_id: relayId,
      version: versionBase + 1n,
      issued_at: issuedAt,
      expires_at: issuedAt + BigInt(Math.min(config.daemon.leaseLifetimeSeconds, 86_400)),
      accounts: accounts.accounts,
    };
    const sealed = await sealCredentialBundle(report, seed, bundle, { nonce, quoteVerified: true, nowSecs: sealNowSecs });
    const answer = await post(LANE_ENDPOINTS.credentials, sealed);
    if ("transport" in answer) return refuse(`transport_${answer.transport}`, `the accounts did not reach the VM through Gray's entry (${answer.transport}); run the command again`);
    if (answer.status !== 200) return refuse(errorCodeOf(answer.body) ?? `http_${answer.status}`, vmRefusal(answer.status, errorCodeOf(answer.body), "accounts"));
    try {
      const value = parseStrictBytes(answer.body);
      accountsReceipt = isObject(value) ? value : null;
    } catch {
      accountsReceipt = null;
    }
    io.stdout(`gray-assistant ${name}: the VM keeps ${accounts.accounts.length} account(s), version ${bundle.version}${get(accountsReceipt ?? {}, "staged") === true ? ", for the designated image" : ""}\n`);
  }

  // 5. The restart.
  const restart = receipt !== null && get(receipt, "restart") === true;
  if (receipt !== null && restart) {
    const vault = get(receipt, "vault");
    if (vault === "closed" || vault === "failed") {
      return refuse(`vault_${vault}`, `the VM keeps the boot box, but its vault could not follow the new image (${vault}); no restart was requested: run the command again`);
    }
  }
  if (target !== null && (action === "rollout" || action === "rollback" || (action === "deliver" && boot.running !== null))) {
    await setStackImageState(controlFile, config.daemon.stateFile, target, stack.currentImage);
  }
  const done = (extra: JsonObject): number => {
    io.stdout(
      `${toJsonString({
        command: name.replace(" ", "."),
        ok: true,
        relay_id: relayId,
        image: target ?? boot.running,
        seq: box === null ? null : BigInt(box.designation.seq),
        boot_version: receipt === null ? null : (get(receipt, "boot_version") ?? null),
        accounts: accounts === null ? null : BigInt(accounts.accounts.length),
        ...extra,
      })}\n`,
    );
    return 0;
  };
  if (!restart || box === null) {
    io.stdout(`gray-assistant ${name}: no restart needed; the VM serves ${boot.running ?? target}\n`);
    return done({ restart: "not_needed" });
  }
  const request = stackRestartRequest({ relayId, appId: vm.instance.appId, reason: action === "rollback" ? "rollback" : "rollout", image: box.designation.image, issuedMs: io.now(), random: io.random });
  const url = `${stack.reportOrigin}${STACK_RESTART_REQUEST_PATH}`;
  let answer: { readonly status: number; readonly text: string };
  try {
    answer = await (options.post ?? defaultPost)(url, toJsonString(await signedStackRestartRequest(request, seed)));
  } catch {
    return refuse("restart_request_unsent", `the VM keeps the boot box, but the restart request did not reach ${url}; run the command again (a restart of the VM by any other means takes the box too)`, { request_id: request.request_id });
  }
  if (answer.status !== 200 && answer.status !== 202) {
    let code: string | null = null;
    try {
      code = errorCodeOf(new TextEncoder().encode(answer.text));
    } catch {
      code = null;
    }
    return refuse(code ?? `http_${answer.status}`, `the VM keeps the boot box, but Gray refused the restart request (${answer.status}${code === null ? "" : ` ${code}`})`, { request_id: request.request_id });
  }
  io.stdout(`gray-assistant ${name}: restart request ${request.request_id} recorded by Gray; the VM restarts onto ${box.designation.image} (about 95 s; the entry routes nothing to it meanwhile)\n`);
  if (!options.wait) return done({ restart: "requested", request_id: request.request_id, waited: false });

  // 6. Wait for the VM to attest the designated image.
  const timeoutMs = options.timeoutMs ?? DELIVER_WAIT_DEFAULT_MS;
  const deadline = io.now() + timeoutMs;
  for (;;) {
    await io.sleep(Math.min(DELIVER_WAIT_POLL_MS, Math.max(1, deadline - io.now())));
    let again: DaemonAttestResult | null = null;
    try {
      again = await attest({ origin: vm.origin, instance: vm.instance, nowSecs: BigInt(Math.floor(io.now() / 1000)), allowEmptySlot: true });
    } catch (error) {
      if (error instanceof RelayKitError && (error.code === "usage" || error.code === "io")) throw error;
      again = null;
    }
    if (again !== null && again.ok && attestationMismatch(again, vm.origin, relayId) === null) {
      const now = phase2Boot(again.stackBoot, relayId, relayKeyHex);
      if (now.ok && now.running === box.designation.image && now.seq >= box.designation.seq) {
        io.stdout(`gray-assistant ${name}: the VM attests ${now.running} (designation seq ${now.seq}) and serves\n`);
        return done({ restart: "requested", request_id: request.request_id, waited: true });
      }
    }
    if (io.now() >= deadline) {
      return refuse("not_attested", `timed out after ${Math.round(timeoutMs / 1000)} s: the VM does not attest ${box.designation.image} yet; \`gray-assistant doctor\` and the panel show where it stands (the boot box is on the VM: nothing needs sending again)`, {
        request_id: request.request_id,
      });
    }
  }
}

/** What tells one boot of the VM from the next: the keys it attested (a new boot makes new ones). */
function bootKeys(attested: DaemonAttestResult & { readonly ok: true }): string {
  return `${attested.keysetDigest} ${attested.tlsSpkiSha256}`;
}

/**
 * `stack restart` in phase 2: the relay-signed restart request (S53, reason `restart`, no image), then, unless
 * `--no-wait`, the new boot's own attestation: a phase-2 boot of this relay with other keys than the boot the command
 * attested first, running a designation (a VM that restarts into the empty slot lost its boot box: `deliver`; one that
 * waited in the empty slot before waits there again). A phase-2
 * boot asks for no pull token, so the token log the phase-1 restart waits on never moves. Nothing is sent to the VM. A
 * VM that does not attest first is restarted all the same, but the new boot cannot be told from it: no wait then.
 */
async function phase2Restart(
  options: DeliverOptions,
  vm: { readonly origin: string; readonly instance: LaneBinding },
  relayKeyHex: string,
  attest: DeliverAttest,
  refuse: (code: string, message: string, extra?: JsonObject) => number,
): Promise<number> {
  const { config, io, seed } = options;
  const relayId = config.daemon.relayId;
  const stack = config.daemon.stack;
  if (stack === null) throw new RelayKitError("usage", "the config has no `stack` section");
  const name = COMMAND_NAMES.restart;
  const attestNow = async (): Promise<DaemonAttestResult | null> => {
    try {
      return await attest({ origin: vm.origin, instance: vm.instance, nowSecs: BigInt(Math.floor(io.now() / 1000)), allowEmptySlot: true });
    } catch (error) {
      if (error instanceof RelayKitError && (error.code === "usage" || error.code === "io")) throw error;
      return null;
    }
  };
  let before: { readonly keys: string; readonly running: string | null; readonly seq: number } | null = null;
  const first = await attestNow();
  if (first !== null && first.ok && attestationMismatch(first, vm.origin, relayId) === null) {
    const boot = phase2Boot(first.stackBoot, relayId, relayKeyHex);
    if (!boot.ok) return refuse(`attest_${boot.code}`, `${boot.message} (attest_${boot.code}); no restart was requested`);
    before = { keys: bootKeys(first), running: boot.running, seq: boot.seq };
    io.stdout(`gray-assistant ${name}: the VM attests ${boot.running === null ? "the empty slot" : `${boot.running} (designation seq ${boot.seq})`}\n`);
  } else {
    io.stderr(`gray-assistant ${name}: the VM does not attest now; the restart is requested all the same\n`);
  }
  const done = (extra: JsonObject): number => {
    io.stdout(`${toJsonString({ command: "stack.restart", ok: true, relay_id: relayId, ...extra })}\n`);
    return 0;
  };
  const request = stackRestartRequest({ relayId, appId: vm.instance.appId, reason: "restart", image: null, issuedMs: io.now(), random: io.random });
  const url = `${stack.reportOrigin}${STACK_RESTART_REQUEST_PATH}`;
  let answer: { readonly status: number; readonly text: string };
  try {
    answer = await (options.post ?? defaultPost)(url, toJsonString(await signedStackRestartRequest(request, seed)));
  } catch {
    return refuse("restart_request_unsent", `the restart request did not reach ${url}; run the command again`, { request_id: request.request_id });
  }
  if (answer.status !== 200 && answer.status !== 202) {
    const code = errorCodeOf(new TextEncoder().encode(answer.text));
    return refuse(code ?? `http_${answer.status}`, `Gray refused the restart request (${answer.status}${code === null ? "" : ` ${code}`})`, { request_id: request.request_id });
  }
  io.stdout(`gray-assistant ${name}: restart request ${request.request_id} recorded by Gray; the VM restarts (about 95 s; the entry routes nothing to it meanwhile)\n`);
  if (!options.wait) return done({ restart: "requested", request_id: request.request_id, waited: false });
  if (before === null) {
    io.stdout(`gray-assistant ${name}: the boot before the restart did not attest, so the new one cannot be told from it; \`gray-assistant doctor\` and the panel show where it stands\n`);
    return done({ restart: "requested", request_id: request.request_id, waited: false });
  }

  const timeoutMs = options.timeoutMs ?? DELIVER_WAIT_DEFAULT_MS;
  const deadline = io.now() + timeoutMs;
  for (;;) {
    await io.sleep(Math.min(DELIVER_WAIT_POLL_MS, Math.max(1, deadline - io.now())));
    const again = await attestNow();
    if (again !== null && again.ok && attestationMismatch(again, vm.origin, relayId) === null && bootKeys(again) !== before.keys) {
      const now = phase2Boot(again.stackBoot, relayId, relayKeyHex);
      if (now.ok && now.running === null && before.running !== null) {
        return refuse("relay_empty_slot", "the VM restarted into the empty slot (it kept no boot box): run `gray-assistant deliver`", { request_id: request.request_id });
      }
      if (now.ok && now.running === null) {
        io.stdout(`gray-assistant ${name}: the new boot attests the empty slot, as the one before; it waits for its first delivery (\`gray-assistant deliver\`)\n`);
        return done({ restart: "requested", request_id: request.request_id, waited: true, image: null, seq: null });
      }
      if (now.ok && now.seq >= before.seq) {
        io.stdout(`gray-assistant ${name}: the new boot attests ${now.running} (designation seq ${now.seq}) and serves\n`);
        return done({ restart: "requested", request_id: request.request_id, waited: true, image: now.running, seq: BigInt(now.seq) });
      }
    }
    if (io.now() >= deadline) {
      return refuse("not_attested", `timed out after ${Math.round(timeoutMs / 1000)} s: no new boot of the VM attests yet; \`gray-assistant doctor\` and the panel show where it stands`, { request_id: request.request_id });
    }
  }
}
