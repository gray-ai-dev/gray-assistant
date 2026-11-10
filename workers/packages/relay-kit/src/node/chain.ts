/**
 * The guardian's commands on the relay's contract (docs/design/relay-no-always-on-host.md 3.2, 13.3): `releases
 * list|check|approve|reject` and `pause` / `unpause`, for a kit whose config has a `chain` member (`../chain/config.ts`).
 *
 * Each reads the contract from the config's two RPC endpoints, which must agree; signs the EIP-712 message with
 * `guardian-key.json`; prints the signed message as JSON for
 * Gray's relayer (P5 adds the route that takes it); and with `--submit --rpc <url>` sends the `...BySig` transaction from
 * the guardian key itself (it pays; the chain id must be the config's). Nothing here prints the key.
 */
import { closeSync, fsyncSync, openSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { get, isObject, parsePlain, type Json, type JsonObject } from "@gray/json";
import { bytesToLowerHex, ed25519Sign } from "@gray/attest";
import { relayerActionSchema, relayerRequestMessage } from "@gray/control/stack-provision";
import { BaseError, createWalletClient, custom, decodeErrorResult, defineChain, getAddress, isAddress, type Address, type Hex, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { APP_AUTH_ABI, APP_AUTH_DELAY_SECONDS, publishedUpgrade, releaseHash, type ReleaseKind } from "../chain/app-auth.ts";
import { checkRelayContract, chainCheckJson, kitErrorIn } from "../chain/checks.ts";
import { parseChainConfig, type ChainConfig } from "../chain/config.ts";
import { bySigCalldata, signedActionJson, signedActionSigner, signGuardianAction, type GuardianAction, type GuardianMessageContext } from "../chain/guardian.ts";
import { GUARDIAN_KEY_FILE, guardianKeyValue, parseGuardianKeyValue, type GuardianKeyFile } from "../chain/guardian-key.ts";
import { agreedChain, hasCode, listReleases, releaseState, releaseStateJson, settingsState, signerNonce, switchState, type AgreedChain, type ReleaseState } from "../chain/releases.ts";
import { checkedRpcUrl, httpRequestFn, rpcClient, rpcLabel, type RpcOptions } from "../chain/rpc.ts";
import { RelayKitError } from "../errors.ts";
import { loadRelayConfigFile, parseJsoncText } from "./config-file.ts";
import { editRelayConfig } from "./config-edit.ts";
import { buildKeyFromText } from "./scheduler-load.ts";
import { defaultPost, type StackPost } from "./stack.ts";
import { readFileText, readPrivateFile, writePrivateFile } from "./files.ts";

/** The largest config and key file read. */
const MAX_FILE_BYTES = 1024 * 1024;
/** How long a signed action holds by default: a day, time enough for Gray's relayer or a later `--submit`. */
export const DEFAULT_ACTION_LIFETIME_SECONDS = 24n * 60n * 60n;
/** The longest `--deadline` accepted: 30 days from now (the pairing's approvals' lifetime). */
const MAX_ACTION_LIFETIME_SECONDS = 30n * 24n * 60n * 60n;

/** A kit's chain context: the parsed `chain` member and the guardian key file's absolute path. */
export interface ChainContext {
  readonly configPath: string;
  readonly chain: ChainConfig;
  readonly guardianKeyPath: string;
}

/** The config's `chain` member, or null when the config has none (a phase-1 kit). The rest of the config is not judged here. */
export function readChainContext(configPath: string): ChainContext | null {
  const raw = parseJsoncText(readFileText(configPath, "relay config", MAX_FILE_BYTES), "relay config");
  if (!isObject(raw as Json)) throw new RelayKitError("usage", "invalid relay config: not an object");
  const member = get(raw as Json, "chain");
  if (member === undefined) return null;
  const chain = parseChainConfig(member);
  const base = dirname(resolve(configPath));
  const guardianKeyPath = isAbsolute(chain.guardianKey) ? chain.guardianKey : resolve(base, chain.guardianKey);
  return { configPath, chain, guardianKeyPath };
}

/** Read `guardian-key.json` (0600, a regular file) and check it is the configured guardian. */
export function readGuardianKeyFile(path: string, guardian: Address | null = null): GuardianKeyFile {
  let value: unknown;
  try {
    value = parsePlain(readPrivateFile(path, "guardian key", 64 * 1024));
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    throw new RelayKitError("invalid_key_file", `guardian key ${path} is not JSON`);
  }
  const key = parseGuardianKeyValue(value);
  if (guardian !== null && key.address !== guardian) throw new RelayKitError("invalid_key_file", `guardian key ${path} is ${key.address}, not chain.guardian ${guardian}`);
  return key;
}

/** Write a guardian key file (0600, never over an existing file unless `force`). */
export function writeGuardianKeyFile(path: string, key: GuardianKeyFile, force = false): void {
  writePrivateFile(path, `${JSON.stringify(guardianKeyValue(key), null, 2)}\n`, { force });
  // On disk before anything signed with it leaves this machine (`init --pair`): the file, then its directory entry.
  try {
    const fd = openSync(path, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    const directory = openSync(dirname(resolve(path)), "r");
    try {
      fsyncSync(directory);
    } finally {
      closeSync(directory);
    }
  } catch {
    throw new RelayKitError("io", `cannot sync ${path} to disk`);
  }
}

export { GUARDIAN_KEY_FILE };

/** Unix seconds now, from the CLI's clock. */
function nowSeconds(nowMs: number): bigint {
  return BigInt(Math.floor(nowMs / 1000));
}

/** `--deadline <unix seconds>` (in the future, at most 30 days ahead), else now + a day. */
export function actionDeadline(value: string | undefined, nowMs: number): bigint {
  const now = nowSeconds(nowMs);
  if (value === undefined) return now + DEFAULT_ACTION_LIFETIME_SECONDS;
  if (!/^[1-9][0-9]{0,11}$/.test(value)) throw new RelayKitError("usage", "--deadline is a Unix time in seconds");
  const deadline = BigInt(value);
  if (deadline <= now) throw new RelayKitError("usage", "--deadline is in the past");
  if (deadline > now + MAX_ACTION_LIFETIME_SECONDS) throw new RelayKitError("usage", "--deadline is more than 30 days ahead");
  return deadline;
}

/** `--nonce <n>`: a nonce of the guardian's own choosing (another signature of it is still unsubmitted). */
function nonceFlag(value: string | undefined): bigint | null {
  if (value === undefined) return null;
  if (!/^(0|[1-9][0-9]{0,18})$/.test(value)) throw new RelayKitError("usage", "--nonce is a whole number");
  return BigInt(value);
}

/** `--kind compose|os_image`. */
function kindFlag(value: string | undefined): ReleaseKind | null {
  if (value === undefined) return null;
  if (value === "compose" || value === "os_image" || value === "implementation") return value;
  throw new RelayKitError("usage", "--kind is compose, os_image or implementation");
}

export interface ChainCommandOptions extends RpcOptions {
  readonly nowMs: number;
}

async function openChain(context: ChainContext, options: ChainCommandOptions): Promise<AgreedChain> {
  try {
    return await agreedChain(context.chain.rpc, context.chain.chainId, options);
  } catch (error) {
    throw kitErrorIn(error) ?? new RelayKitError("chain_unreachable", "an RPC endpoint could not be read");
  }
}

/** The kind of a hash on the contract: the given one, else the one kind it was proposed as. */
async function kindOnChain(chain: AgreedChain, contract: Address, hash: Hex, given: ReleaseKind | null): Promise<ReleaseState> {
  if (given !== null) return releaseState(chain, contract, given, hash);
  const states = await Promise.all((["compose", "os_image", "implementation"] as const).map((kind) => releaseState(chain, contract, kind, hash)));
  const proposed = states.filter((state) => state.proposedAt !== 0n);
  if (proposed.length > 1) throw new RelayKitError("usage", `${hash} is proposed as more than one kind; say which with --kind compose|os_image|implementation`);
  if (proposed[0] !== undefined) return proposed[0];
  throw new RelayKitError("chain_refused", `${hash} has not been proposed on ${contract}`);
}

/**
 * An upgrade of the contract (kind `implementation`): Gray's when this kit's published list names it, from an
 * implementation to a published one, with its call; anything else is not Gray's and the relay vetoes it.
 */
export function upgradeVerdict(hash: Hex): { readonly ok: boolean; readonly detail: string } {
  const upgrade = publishedUpgrade(hash);
  if (upgrade === null || upgrade.version === null) {
    return { ok: false, detail: `${hash} is not an upgrade Gray publishes (this kit's abi/implementations.json): veto it with \`gray-assistant releases reject ${hash} --kind implementation\`` };
  }
  return { ok: true, detail: `an upgrade Gray publishes: from ${upgrade.from} to implementation ${upgrade.version} at ${upgrade.to} (code ${upgrade.codeHash}), ${upgrade.data === "0x" ? "no call" : `call ${upgrade.data}`}` };
}

/** `releases list`: every proposal since `chain.from_block` (or `--from-block`), with its state. */
export async function chainReleasesList(context: ChainContext, options: ChainCommandOptions & { readonly fromBlock?: bigint }): Promise<{ readonly block: bigint; readonly releases: readonly ReleaseState[] }> {
  const chain = await openChain(context, options);
  if (!(await hasCode(chain, context.chain.contract))) throw new RelayKitError("chain_refused", `no contract at ${context.chain.contract} yet (Gray deploys it at Deploy)`);
  const fromBlock = options.fromBlock ?? context.chain.fromBlock;
  if (fromBlock === null) throw new RelayKitError("usage", "releases list reads the contract's events from its deployment block: set chain.from_block, or give --from-block");
  return { block: chain.block, releases: await listReleases(chain, context.chain.contract, fromBlock) };
}

/** `releases check <hash>`: the hash's state on the contract, agreed by both endpoints, and what it means for the relay. */
export async function chainReleaseCheck(context: ChainContext, hashText: string, kind: string | undefined, options: ChainCommandOptions): Promise<{ readonly block: bigint; readonly state: ReleaseState; readonly verdict: string }> {
  const hash = releaseHash(hashText);
  const chain = await openChain(context, options);
  if (!(await hasCode(chain, context.chain.contract))) throw new RelayKitError("chain_refused", `no contract at ${context.chain.contract} yet (Gray deploys it at Deploy)`);
  const state = await kindOnChain(chain, context.chain.contract, hash, kindFlag(kind));
  return { block: chain.block, state, verdict: releaseVerdict(state, nowSeconds(options.nowMs)) };
}

/** One sentence on a release's state, for the person deciding. */
export function releaseVerdict(state: ReleaseState, now: bigint): string {
  const what = state.kind === "compose" ? "compose" : state.kind === "os_image" ? "OS image" : "upgrade";
  if (state.proposedAt === 0n) return `${what} ${state.hash} was never proposed`;
  if (state.removed) return `${what} ${state.hash} was removed; it is never effective again`;
  if (state.vetoed) return `${what} ${state.hash} is vetoed by the relay; it is not effective until the guardian approves it`;
  if (state.approved) return `${what} ${state.hash} is approved by the relay and effective`;
  if (state.effective) return `${what} ${state.hash} became effective after its delay; a veto still stops it`;
  const left = state.effectiveAt - now;
  const days = Number(left) / 86_400;
  return `${what} ${state.hash} becomes effective at ${new Date(Number(state.effectiveAt) * 1000).toISOString()} (in ${days.toFixed(1)} days) unless the guardian vetoes it`;
}

/** What a guardian action command produced. */
export interface GuardianActionOutcome {
  readonly json: Record<string, string | number | null>;
  /** The transaction sent, and the block it was mined in (null: not mined within the wait); null with `--print`. */
  readonly transaction: { readonly hash: Hex; readonly block: bigint | null } | null;
  /** Who sent it: Gray's relayer (the default) or the guardian key (`--submit`). */
  readonly via: "relayer" | "guardian" | null;
  readonly note: string | null;
}

/** Approve, veto, pause or unpause: read what the contract needs, sign with the guardian key, maybe submit. */
export async function chainGuardianAction(
  context: ChainContext,
  request: { readonly action: "approve" | "veto" | "pause" | "unpause"; readonly hash?: string; readonly kind?: string; readonly deadline?: string; readonly nonce?: string; readonly submit?: { readonly rpc: string } | null; readonly print?: boolean },
  options: ChainCommandOptions & { readonly post?: StackPost },
): Promise<GuardianActionOutcome> {
  const contract = context.chain.contract;
  const guardian = context.chain.guardian;
  const deadline = actionDeadline(request.deadline, options.nowMs);
  const givenNonce = nonceFlag(request.nonce);
  const key = readGuardianKeyFile(context.guardianKeyPath, guardian);
  const submitUrl = request.submit ? checkedRpcUrl(request.submit.rpc, "--rpc") : null;

  const chain = await openChain(context, options);
  if (!(await hasCode(chain, contract))) throw new RelayKitError("chain_refused", `no contract at ${contract} yet (Gray deploys it at Deploy; the pairing's approvals cover the first release)`);
  const switches = await switchState(chain, contract);
  if (switches.guardian !== guardian) throw new RelayKitError("chain_refused", `the contract's guardian is ${switches.guardian}, not chain.guardian ${guardian}`);
  let action: GuardianAction;
  let note: string | null = null;
  // The version of the state the signature decides, as both endpoints read it at the agreed block.
  let version: bigint;
  if (request.action === "pause" || request.action === "unpause") {
    if (request.action === "pause" && switches.paused) throw new RelayKitError("chain_refused", "the contract is paused already");
    if (request.action === "unpause" && !switches.paused) throw new RelayKitError("chain_refused", "the contract is not paused");
    action = { action: request.action };
    version = switches.pauseVersion;
  } else {
    const state = await kindOnChain(chain, contract, releaseHash(request.hash ?? ""), kindFlag(request.kind));
    if (state.removed) throw new RelayKitError("chain_refused", `${state.hash} was removed; there is nothing to ${request.action === "approve" ? "approve" : "reject"}`);
    if (request.action === "approve" && state.approved) throw new RelayKitError("chain_refused", `${state.hash} is approved already`);
    if (request.action === "veto" && state.vetoed) throw new RelayKitError("chain_refused", `${state.hash} is vetoed already`);
    if (request.action === "veto" && state.effective) note = "it is effective now: the veto stops it, and every VM on it loses its accounts at its next KMS re-check (within 10 minutes)";
    action = { action: request.action, kind: state.kind, hash: state.hash };
    version = state.version;
  }
  const nonce = givenNonce ?? (await signerNonce(chain, contract, guardian));
  return signAndSend(context, key, action, { version, nonce, deadline }, { submitUrl, print: request.print === true, note }, options);
}

/**
 * Sign `action` with `key` (the guardian's or the recovery key's) at the version, nonce and deadline read for it, check
 * the signature recovers to the key, then send it: `--submit` from the key itself, `--print` not at all, else through
 * Gray's relayer (the default: Gray pays, the relay holds no Base ETH).
 */
async function signAndSend(
  context: ChainContext,
  key: GuardianKeyFile,
  action: GuardianAction,
  at: { readonly version: bigint; readonly nonce: bigint; readonly deadline: bigint },
  how: { readonly submitUrl: string | null; readonly print: boolean; readonly note: string | null },
  options: ChainCommandOptions & { readonly post?: StackPost },
): Promise<GuardianActionOutcome> {
  const contract = context.chain.contract;
  const note = how.note;
  const messageContext: GuardianMessageContext = { chainId: context.chain.chainId, contract, version: at.version, signer: key.address, nonce: at.nonce, deadline: at.deadline };
  const signed = await signGuardianAction(key.privateKey, action, messageContext);
  if ((await signedActionSigner(signed)) !== key.address) throw new RelayKitError("invalid_key_file", "the signature does not recover to the key");
  const json = signedActionJson(signed);
  if (how.submitUrl !== null) return { json, transaction: await submitBySig(how.submitUrl, context.chain.chainId, key, contract, bySigCalldata(signed), options), via: "guardian", note };
  if (how.print) return { json, transaction: null, via: null, note };
  // The default: Gray's relayer pays, the request signed with the relay key as a restart request is.
  const config = loadRelayConfigFile(context.configPath);
  if (config.daemon.stack === null) throw new RelayKitError("usage", "the config has no stack section (stack.report_origin, where Gray's relayer is): send it yourself with --submit --rpc <url>, or --print it");
  const relayKey = await buildKeyFromText(readPrivateFile(config.daemon.keyPath, "relay key", 64 * 1024));
  const hash = await postToRelayer({ origin: config.daemon.stack.reportOrigin, relayId: config.daemon.relayId, seed: relayKey.seed, decision: json, ...(options.post === undefined ? {} : { post: options.post }) });
  return { json, transaction: { hash, block: await minedBlock(rpcClient(context.chain.rpc[0] as string, options), hash, RECEIPT_TIMEOUT_MS) }, via: "relayer", note };
}

/**
 * `releases delay <hours>` (13.13): the relay's release delay, signed by the guardian at the contract's `delayVersion`
 * and sent as approve is. Lengthening it makes a compose or OS image that is effective by time alone (not approved)
 * wait again: a VM running it loses its accounts at its next KMS re-check. The outcome names each such release (read
 * from the contract's events since `chain.from_block`), or says they could not be listed, before anything is sent;
 * `confirmed` false stops there. The config keeps the new delay once the change is sent.
 */
export async function chainSetDelay(
  context: ChainContext,
  request: { readonly seconds: bigint; readonly deadline?: string; readonly nonce?: string; readonly submit?: { readonly rpc: string } | null; readonly print?: boolean; readonly confirmed: boolean },
  options: ChainCommandOptions & { readonly post?: StackPost },
): Promise<{ readonly previous: bigint; readonly stopped: readonly ReleaseState[] | null; readonly outcome: GuardianActionOutcome | null }> {
  const contract = context.chain.contract;
  const guardian = context.chain.guardian;
  const deadline = actionDeadline(request.deadline, options.nowMs);
  const givenNonce = nonceFlag(request.nonce);
  const key = readGuardianKeyFile(context.guardianKeyPath, guardian);
  const submitUrl = request.submit ? checkedRpcUrl(request.submit.rpc, "--rpc") : null;
  const chain = await openChain(context, options);
  if (!(await hasCode(chain, contract))) throw new RelayKitError("chain_refused", `no contract at ${contract} yet (Gray deploys it at Deploy)`);
  const switches = await switchState(chain, contract);
  if (switches.guardian !== guardian) throw new RelayKitError("chain_refused", `the contract's guardian is ${switches.guardian}, not chain.guardian ${guardian}`);
  const settings = await settingsState(chain, contract);
  if (settings.delay === request.seconds) throw new RelayKitError("chain_refused", `the contract's delay is ${request.seconds} s already`);
  let stopped: ReleaseState[] | null = [];
  if (request.seconds > settings.delay) {
    const now = nowSeconds(options.nowMs);
    const fromBlock = context.chain.fromBlock;
    stopped =
      fromBlock === null
        ? null
        : (await listReleases(chain, contract, fromBlock)).filter((s) => s.kind !== "implementation" && s.effective && !s.approved && s.proposedAt + request.seconds > now);
  }
  if (!request.confirmed && (stopped === null || stopped.length > 0)) return { previous: settings.delay, stopped, outcome: null };
  const nonce = givenNonce ?? (await signerNonce(chain, contract, guardian));
  const outcome = await signAndSend(context, key, { action: "set_delay", delay: request.seconds }, { version: settings.delayVersion, nonce, deadline }, { submitUrl, print: request.print === true, note: null }, options);
  // Kept once mined: deliver's chain check compares the contract's delay() with it.
  const kept = outcome.transaction?.block == null ? null : keepInConfig(context, "chain.release_delay_seconds", Number(request.seconds));
  return { previous: settings.delay, stopped, outcome: kept === null ? outcome : { ...outcome, note: kept } };
}

/**
 * `keys set-guardian|set-recovery <address>` (13.13): a new guardian or recovery address, signed by the recovery key
 * (`--key`, the file the relay keeps offline) at the contract's `keysVersion`, and sent as approve is. A new guardian
 * is written to the config's `chain.guardian` once the change is sent; its key file is the relay's to put in place.
 */
export async function chainSetKey(
  context: ChainContext,
  request: { readonly which: "guardian" | "recovery"; readonly address: string; readonly keyPath: string; readonly deadline?: string; readonly nonce?: string; readonly submit?: { readonly rpc: string } | null; readonly print?: boolean },
  options: ChainCommandOptions & { readonly post?: StackPost },
): Promise<GuardianActionOutcome> {
  const contract = context.chain.contract;
  if (!isAddress(request.address, { strict: false }) || /^0x0{40}$/i.test(request.address)) throw new RelayKitError("usage", "the new key is an Ethereum address (0x and 40 hex digits), not zero");
  const address = getAddress(request.address);
  const deadline = actionDeadline(request.deadline, options.nowMs);
  const givenNonce = nonceFlag(request.nonce);
  const key = readGuardianKeyFile(request.keyPath);
  const submitUrl = request.submit ? checkedRpcUrl(request.submit.rpc, "--rpc") : null;
  const chain = await openChain(context, options);
  if (!(await hasCode(chain, contract))) throw new RelayKitError("chain_refused", `no contract at ${contract} yet (Gray deploys it at Deploy)`);
  const settings = await settingsState(chain, contract);
  if (key.address !== settings.recovery) throw new RelayKitError("invalid_key_file", `${request.keyPath} is ${key.address}, not the contract's recovery address ${settings.recovery}: only the recovery key changes keys`);
  const switches = await switchState(chain, contract);
  const current = request.which === "guardian" ? switches.guardian : settings.recovery;
  if (address === current) throw new RelayKitError("chain_refused", `${address} is the contract's ${request.which} already`);
  const nonce = givenNonce ?? (await signerNonce(chain, contract, key.address));
  const action: GuardianAction = { action: request.which === "guardian" ? "set_guardian" : "set_recovery", address };
  const outcome = await signAndSend(context, key, action, { version: settings.keysVersion, nonce, deadline }, { submitUrl, print: request.print === true, note: null }, options);
  const kept = outcome.transaction?.block == null || request.which !== "guardian" ? null : keepInConfig(context, "chain.guardian", address);
  return kept === null ? outcome : { ...outcome, note: kept };
}

/** Write a changed setting to the config; null when written, else what to run (the change is on chain already). */
function keepInConfig(context: ChainContext, member: string, value: string | number): string | null {
  try {
    editRelayConfig(context.configPath, member, value);
    return null;
  } catch {
    return `the contract took it, but ${context.configPath} could not be written: run gray-assistant config set ${member} ${typeof value === "number" ? `${value} --json` : value} where the config is writable (the kit directory)`;
  }
}

/** Gray's relayer for a decision the guardian signed, as gray-assistant sends it (the console's report.ts). */
export const RELAYER_REQUEST_PATH = "/v1/lane-stack/relayer";
/** Gray's relayer refusals that mean Gray does not pay for this one: the relay sends it with `--submit`. */
const NOT_PAID = new Set(["relay_relayer_over_limit", "relay_relayer_not_sponsored"]);

/** Sign the guardian's decision again with the relay key and have Gray's relayer submit it; the transaction's hash. */
export async function postToRelayer(input: { readonly origin: string; readonly relayId: string; readonly seed: Uint8Array; readonly decision: Record<string, unknown>; readonly post?: StackPost }): Promise<Hex> {
  const { function: _call, calldata: _data, ...signed } = input.decision;
  const decision = relayerActionSchema.parse(signed);
  const signature = bytesToLowerHex(await ed25519Sign(input.seed, relayerRequestMessage(input.relayId, decision)));
  let answer: { readonly status: number; readonly text: string };
  try {
    answer = await (input.post ?? defaultPost)(`${input.origin}${RELAYER_REQUEST_PATH}`, JSON.stringify({ relay_id: input.relayId, decision, signature }));
  } catch {
    throw new RelayKitError("chain_unreachable", `Gray's relayer at ${input.origin} did not answer: run the command again, or send it yourself with --submit --rpc <url>`);
  }
  let body: Json = null;
  try {
    body = parsePlain(answer.text) as Json;
  } catch {
    // Not JSON: refused below with the status alone.
  }
  const hash = isObject(body) ? get(body, "transaction_hash") : undefined;
  if (answer.status === 200 && typeof hash === "string" && /^0x[0-9a-f]{64}$/.test(hash)) return hash as Hex;
  const error = isObject(body) ? get(body, "error") : undefined;
  const code = isObject(error) && typeof get(error, "code") === "string" ? (get(error, "code") as string) : `HTTP ${answer.status}`;
  const message = isObject(error) && typeof get(error, "message") === "string" ? (get(error, "message") as string).slice(0, 300) : "";
  if (NOT_PAID.has(code)) throw new RelayKitError("chain_refused", `Gray's relayer does not pay for this one (${code}): send it yourself with --submit --rpc <url> (the guardian key pays a few cents of Base ETH)`);
  throw new RelayKitError("chain_refused", `Gray's relayer refused it (${code}${message === "" ? "" : `: ${message}`}); nothing was sent`);
}

/** The block a sent transaction was mined in, or null when it was not within the wait; a reverted one is refused. */
async function minedBlock(reader: PublicClient, hash: Hex, timeoutMs: number): Promise<bigint | null> {
  try {
    const receipt = await reader.waitForTransactionReceipt({ hash, timeout: timeoutMs, pollingInterval: 1000 });
    if (receipt.status !== "success") throw new RelayKitError("chain_refused", `transaction ${hash} was mined in block ${receipt.blockNumber} and reverted`);
    return receipt.blockNumber;
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    return null;
  }
}

/**
 * Send the `...BySig` transaction from the guardian key through `--rpc`. The endpoint must be on the config's chain;
 * viem estimates the gas (a call the contract would refuse fails here, before anything is sent) and signs locally.
 */
export async function submitBySig(
  url: string,
  chainId: number,
  key: GuardianKeyFile,
  contract: Address,
  data: Hex,
  options: RpcOptions & { readonly receiptTimeoutMs?: number } = {},
): Promise<{ readonly hash: Hex; readonly block: bigint | null }> {
  const reader = rpcClient(url, options);
  let endpointChain: number;
  try {
    endpointChain = await reader.getChainId();
  } catch (error) {
    throw kitErrorIn(error) ?? new RelayKitError("chain_unreachable", `${rpcLabel(url)} did not answer eth_chainId`);
  }
  if (endpointChain !== chainId) throw new RelayKitError("chain_refused", `--rpc ${rpcLabel(url)} is chain ${endpointChain}, not chain.chain_id ${chainId}; nothing was sent`);
  const chain = defineChain({ id: chainId, name: `chain ${chainId}`, nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [url] } } });
  const wallet = createWalletClient({ account: privateKeyToAccount(key.privateKey), chain, transport: custom({ request: httpRequestFn(url, options) }, { retryCount: 0 }) });
  let hash: Hex;
  try {
    hash = await wallet.sendTransaction({ to: contract, data, chain });
  } catch (error) {
    const kit = kitErrorIn(error);
    if (kit !== null) throw kit;
    const named = contractErrorName(error);
    if (named?.startsWith("SupersededSignature(")) {
      const [signed, current] = named.slice("SupersededSignature(".length, -1).split(", ");
      throw new RelayKitError(
        "chain_refused",
        `the signature is superseded: it decides version ${signed}, and the contract is at version ${current} because a later decision was made since it was signed; nothing was sent: read the state again (releases check) and sign again`,
      );
    }
    if (named !== null) throw new RelayKitError("chain_refused", `the contract refuses the call: ${named}; nothing was sent`);
    const short = error instanceof BaseError ? error.shortMessage.slice(0, 300) : "the transaction was not accepted";
    throw new RelayKitError("chain_refused", `${rpcLabel(url)}: ${short}`);
  }
  // Sent: wait for it to be mined (Base makes a block every 2 s), so the command says whether the contract took it.
  return { hash, block: await minedBlock(reader, hash, options.receiptTimeoutMs ?? RECEIPT_TIMEOUT_MS) };
}

/** How long `--submit` waits for its transaction to be mined before it prints the hash alone. */
export const RECEIPT_TIMEOUT_MS = 120_000;

/** The contract's custom error a refused call carries (`SignatureExpired(…)`, `NotProposed(…)`, …), by the ABI. */
function contractErrorName(error: unknown): string | null {
  if (!(error instanceof BaseError)) return null;
  let data: Hex | null = null;
  error.walk((cause) => {
    const value = (cause as { data?: unknown }).data;
    if (data === null && typeof value === "string" && /^0x[0-9a-f]{8}/i.test(value)) data = value as Hex;
    return false;
  });
  if (data === null) return null;
  try {
    const decoded = decodeErrorResult({ abi: APP_AUTH_ABI, data });
    return `${decoded.errorName}(${(decoded.args ?? []).map(String).join(", ")})`;
  } catch {
    return null;
  }
}

/** For `deliver` (P4b): the chain checks of the config's contract for a compose and OS image hash. */
export async function chainChecksFor(context: ChainContext, composeHash: Hex | null, osImageHash: Hex | null, options: RpcOptions & { readonly nowMs?: number } = {}) {
  const result = await checkRelayContract(
    context.chain.rpc,
    { chainId: context.chain.chainId, contract: context.chain.contract, proposer: context.chain.proposer, guardian: context.chain.guardian, dstackKms: context.chain.dstackKms, releaseDelaySeconds: context.chain.releaseDelaySeconds, composeHash, osImageHash },
    options,
  );
  return { result, json: chainCheckJson(result) as JsonObject };
}

export { APP_AUTH_DELAY_SECONDS, releaseStateJson };
