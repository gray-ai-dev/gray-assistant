/**
 * The guardian's commands on the relay's contract (docs/design/relay-no-always-on-host.md 3.2, 13.3): `releases
 * list|check|approve|reject` and `pause` / `unpause`, for a kit whose config has a `chain` member (`../chain/config.ts`).
 *
 * Each reads the contract from the config's two RPC endpoints, which must agree; signs the EIP-712 message with
 * `guardian-key.json` (or prints the typed data for the guardian's own wallet); prints the signed message as JSON for
 * Gray's relayer (P5 adds the route that takes it); and with `--submit --rpc <url>` sends the `...BySig` transaction from
 * the guardian key itself (it pays; the chain id must be the config's). Nothing here prints the key.
 */
import { closeSync, fsyncSync, openSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { get, isObject, parsePlain, type Json, type JsonObject } from "@gray/json";
import { BaseError, createWalletClient, custom, decodeErrorResult, defineChain, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { APP_AUTH_ABI, APP_AUTH_DELAY_SECONDS, releaseHash, type ReleaseKind } from "../chain/app-auth.ts";
import { checkRelayContract, chainCheckJson, kitErrorIn } from "../chain/checks.ts";
import { parseChainConfig, type ChainConfig } from "../chain/config.ts";
import { bySigCalldata, signedActionJson, signedActionSigner, signGuardianAction, walletTypedData, type GuardianAction, type GuardianMessageContext } from "../chain/guardian.ts";
import { GUARDIAN_KEY_FILE, guardianKeyValue, parseGuardianKeyValue, type GuardianKeyFile } from "../chain/guardian-key.ts";
import { agreedChain, hasCode, listReleases, releaseState, releaseStateJson, signerNonce, switchState, type AgreedChain, type ReleaseState } from "../chain/releases.ts";
import { checkedRpcUrl, httpRequestFn, rpcClient, rpcLabel, type RpcOptions } from "../chain/rpc.ts";
import { RelayKitError } from "../errors.ts";
import { parseJsoncText } from "./config-file.ts";
import { readFileText, readPrivateFile, writePrivateFile } from "./files.ts";

/** The largest config and key file read. */
const MAX_FILE_BYTES = 1024 * 1024;
/** How long a signed action holds by default: a day, time enough for Gray's relayer or a later `--submit`. */
export const DEFAULT_ACTION_LIFETIME_SECONDS = 24n * 60n * 60n;
/** The longest `--deadline` accepted: 30 days from now (the pairing's approvals' lifetime). */
const MAX_ACTION_LIFETIME_SECONDS = 30n * 24n * 60n * 60n;

/** A kit's chain context: the parsed `chain` member and the guardian key file's absolute path, if any. */
export interface ChainContext {
  readonly configPath: string;
  readonly chain: ChainConfig;
  readonly guardianKeyPath: string | null;
}

/** The config's `chain` member, or null when the config has none (a phase-1 kit). The rest of the config is not judged here. */
export function readChainContext(configPath: string): ChainContext | null {
  const raw = parseJsoncText(readFileText(configPath, "relay config", MAX_FILE_BYTES), "relay config");
  if (!isObject(raw as Json)) throw new RelayKitError("usage", "invalid relay config: not an object");
  const member = get(raw as Json, "chain");
  if (member === undefined) return null;
  const chain = parseChainConfig(member);
  const base = dirname(resolve(configPath));
  const guardianKeyPath = chain.guardianKey === null ? null : isAbsolute(chain.guardianKey) ? chain.guardianKey : resolve(base, chain.guardianKey);
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
  if (value === "compose" || value === "os_image") return value;
  throw new RelayKitError("usage", "--kind is compose or os_image");
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
  const [compose, osImage] = await Promise.all([releaseState(chain, contract, "compose", hash), releaseState(chain, contract, "os_image", hash)]);
  if (compose.proposedAt !== 0n && osImage.proposedAt !== 0n) throw new RelayKitError("usage", `${hash} is proposed both as a compose hash and as an OS image hash; say which with --kind compose|os_image`);
  if (compose.proposedAt !== 0n) return compose;
  if (osImage.proposedAt !== 0n) return osImage;
  throw new RelayKitError("chain_refused", `${hash} has not been proposed on ${contract}`);
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
  const what = state.kind === "compose" ? "compose" : "OS image";
  if (state.proposedAt === 0n) return `${what} ${state.hash} was never proposed`;
  if (state.removed) return `${what} ${state.hash} was removed; it is never effective again`;
  if (state.vetoed) return `${what} ${state.hash} is vetoed by the relay; it is not effective until the guardian approves it`;
  if (state.approved) return `${what} ${state.hash} is approved by the relay and effective`;
  if (state.effective) return `${what} ${state.hash} became effective after its 7 days; a veto still stops it`;
  const left = state.effectiveAt - now;
  const days = Number(left) / 86_400;
  return `${what} ${state.hash} becomes effective at ${new Date(Number(state.effectiveAt) * 1000).toISOString()} (in ${days.toFixed(1)} days) unless the guardian vetoes it`;
}

/** What a guardian action command produced. */
export type GuardianActionOutcome =
  | {
      readonly signed: true;
      readonly json: Record<string, string | number | null>;
      /** The transaction `--submit` sent, and the block it was mined in (null: not mined within the wait). */
      readonly transaction: { readonly hash: Hex; readonly block: bigint | null } | null;
      readonly note: string | null;
    }
  | { readonly signed: false; readonly typedData: Record<string, unknown>; readonly context: GuardianMessageContext; readonly note: string | null };

/** Approve, veto, pause or unpause: read what the contract needs, sign (or give the wallet's typed data), maybe submit. */
export async function chainGuardianAction(
  context: ChainContext,
  request: { readonly action: "approve" | "veto" | "pause" | "unpause"; readonly hash?: string; readonly kind?: string; readonly deadline?: string; readonly nonce?: string; readonly submit?: { readonly rpc: string } | null },
  options: ChainCommandOptions,
): Promise<GuardianActionOutcome> {
  const contract = context.chain.contract;
  const guardian = context.chain.guardian;
  const deadline = actionDeadline(request.deadline, options.nowMs);
  const givenNonce = nonceFlag(request.nonce);
  const key = context.guardianKeyPath === null ? null : readGuardianKeyFile(context.guardianKeyPath, guardian);
  if (request.submit && key === null) throw new RelayKitError("usage", "--submit sends the transaction from the guardian key, and this config names none (chain.guardian_key): sign with your wallet and send it there");
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
  const messageContext: GuardianMessageContext = { chainId: context.chain.chainId, contract, version, signer: guardian, nonce, deadline };
  if (key === null) return { signed: false, typedData: walletTypedData(action, messageContext), context: messageContext, note };
  const signed = await signGuardianAction(key.privateKey, action, messageContext);
  if ((await signedActionSigner(signed)) !== guardian) throw new RelayKitError("invalid_key_file", "the signature does not recover to the guardian");
  const json = signedActionJson(signed);
  if (submitUrl === null) return { signed: true, json, transaction: null, note };
  const transaction = await submitBySig(submitUrl, context.chain.chainId, key, contract, bySigCalldata(signed), options);
  return { signed: true, json, transaction, note };
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
  try {
    const receipt = await reader.waitForTransactionReceipt({ hash, timeout: options.receiptTimeoutMs ?? RECEIPT_TIMEOUT_MS, pollingInterval: 1000 });
    if (receipt.status !== "success") throw new RelayKitError("chain_refused", `transaction ${hash} was mined in block ${receipt.blockNumber} and reverted`);
    return { hash, block: receipt.blockNumber };
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    return { hash, block: null };
  }
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
    { chainId: context.chain.chainId, contract: context.chain.contract, proposer: context.chain.proposer, guardian: context.chain.guardian, dstackKms: context.chain.dstackKms, composeHash, osImageHash },
    options,
  );
  return { result, json: chainCheckJson(result) as JsonObject };
}

export { APP_AUTH_DELAY_SECONDS, releaseStateJson };
