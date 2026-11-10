/**
 * The releases on the relay's contract, read from two endpoints that must agree (as `checks.ts`): each proposal from
 * the contract's `Proposed` events, and each release's record (`releaseOf`, `effective`, `effectiveAt`) at the block both
 * endpoints have. Also the guardian's next nonce, which every signed action names.
 */
import { getAddress, type Address, type Hex, type PublicClient } from "viem";
import { RelayKitError } from "../errors.ts";
import { APP_AUTH_ABI, RELEASE_KIND_NUMBER, releaseKindOf, type ReleaseKind } from "./app-auth.ts";
import { endpointChainId, freshCommonBlock, kitErrorIn, type FreshnessOptions } from "./checks.ts";
import { rpcClient, rpcLabel, type RpcOptions } from "./rpc.ts";

/** How many blocks one `eth_getLogs` asks for: within what public Base endpoints answer. */
export const DEFAULT_LOG_RANGE = 10_000n;
/** At most this many log requests per endpoint for one listing (about 23 days of Base blocks at the default range). */
export const MAX_LOG_REQUESTS = 100;

/** One release's state on the contract. */
export interface ReleaseState {
  readonly kind: ReleaseKind;
  readonly hash: Hex;
  /** Unix seconds; 0 when never proposed. */
  readonly proposedAt: bigint;
  /** When it becomes effective without the guardian (0 when never proposed). */
  readonly effectiveAt: bigint;
  readonly approved: boolean;
  readonly vetoed: boolean;
  readonly removed: boolean;
  readonly effective: boolean;
  /** Decisions on it so far (approve, veto, remove); a guardian's `Approve`, `Veto` and `Remove` sign it. */
  readonly version: bigint;
}

/** The two endpoints, checked to be on the configured chain, and the block both have. */
export interface AgreedChain {
  readonly urls: readonly string[];
  readonly clients: readonly PublicClient[];
  readonly block: bigint;
}

async function onEndpoint<T>(url: string, what: string, read: () => Promise<T>): Promise<T> {
  try {
    return await read();
  } catch (error) {
    const kit = kitErrorIn(error);
    if (kit !== null) throw kit;
    throw new RelayKitError("chain_unreachable", `${rpcLabel(url)} could not answer ${what}`);
  }
}

/**
 * Open both endpoints: each must answer the chain id; the block is the lower of their latest, and the chain as it is
 * now (`freshCommonBlock`: the heads close, the block recent), so a lagging endpoint cannot hold both to an old state.
 */
export async function agreedChain(rpcUrls: readonly string[], chainId: number, options: RpcOptions & FreshnessOptions & { readonly clients?: readonly PublicClient[] } = {}): Promise<AgreedChain> {
  if (rpcUrls.length !== 2) throw new RelayKitError("usage", "the chain is read from two RPC endpoints");
  const clients = options.clients ?? rpcUrls.map((url) => rpcClient(url, options));
  const heads = await Promise.all(
    clients.map(async (client, index) => {
      const url = rpcUrls[index] as string;
      const id = await endpointChainId(client, url);
      if (id !== chainId) throw new RelayKitError("chain_refused", `${rpcLabel(url)} is chain ${id}, not ${chainId}`);
      return onEndpoint(url, "eth_blockNumber", () => client.getBlockNumber({ cacheTime: 0 }));
    }),
  );
  return { urls: rpcUrls, clients, block: await freshCommonBlock(clients, rpcUrls, heads, options.nowMs ?? Date.now()) };
}

/** Run one read on both endpoints at the agreed block; refuse unless both answer the same (by `key`). */
export async function readAgreed<T>(chain: AgreedChain, what: string, read: (client: PublicClient) => Promise<T>, key: (value: T) => string): Promise<T> {
  const values = await Promise.all(chain.clients.map((client, index) => onEndpoint(chain.urls[index] as string, what, () => read(client))));
  const [first, second] = values as [T, T];
  if (key(first) !== key(second)) {
    throw new RelayKitError("chain_disagreement", `${rpcLabel(chain.urls[0] as string)} and ${rpcLabel(chain.urls[1] as string)} answer ${what} differently at block ${chain.block}`);
  }
  return first;
}

async function readState(client: PublicClient, contract: Address, kind: ReleaseKind, hash: Hex, block: bigint): Promise<ReleaseState> {
  const args = [RELEASE_KIND_NUMBER[kind], hash] as const;
  const [record, effective, effectiveAt] = await Promise.all([
    client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "releaseOf", args, blockNumber: block }),
    client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "effective", args, blockNumber: block }),
    client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "effectiveAt", args, blockNumber: block }),
  ]);
  return { kind, hash, proposedAt: BigInt(record.proposedAt), effectiveAt, approved: record.approved, vetoed: record.vetoed, removed: record.removed, effective, version: BigInt(record.version) };
}

const stateKey = (state: ReleaseState) => `${state.kind}:${state.hash}:${state.proposedAt}:${state.effectiveAt}:${state.approved}:${state.vetoed}:${state.removed}:${state.effective}:${state.version}`;

/** One release's state, agreed by both endpoints. */
export async function releaseState(chain: AgreedChain, contract: Address, kind: ReleaseKind, hash: Hex): Promise<ReleaseState> {
  return readAgreed(chain, `releaseOf(${kind}, ${hash})`, (client) => readState(client, contract, kind, hash, chain.block), stateKey);
}

/** Whether there is a contract at the address (both endpoints). */
export async function hasCode(chain: AgreedChain, contract: Address): Promise<boolean> {
  return readAgreed(chain, "eth_getCode", async (client) => {
    const code = await client.getCode({ address: contract, blockNumber: chain.block });
    return code !== undefined && code !== "0x";
  }, String);
}

/** The guardian's (or any signer's) next nonce on the contract, agreed by both endpoints. */
export async function signerNonce(chain: AgreedChain, contract: Address, signer: Address): Promise<bigint> {
  return readAgreed(chain, "nonces", (client) => client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "nonces", args: [signer], blockNumber: chain.block }), String);
}

/** The relay's settings the kit signs changes of (13.13): `delay()`, `delayVersion()`, `keysVersion()`, `recovery()`. */
export async function settingsState(chain: AgreedChain, contract: Address): Promise<{ readonly delay: bigint; readonly delayVersion: bigint; readonly keysVersion: bigint; readonly recovery: Address }> {
  return readAgreed(
    chain,
    "delay(), delayVersion(), keysVersion() and recovery()",
    async (client) => {
      const [delay, delayVersion, keysVersion, recovery] = await Promise.all([
        client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "delay", blockNumber: chain.block }),
        client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "delayVersion", blockNumber: chain.block }),
        client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "keysVersion", blockNumber: chain.block }),
        client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "recovery", blockNumber: chain.block }),
      ]);
      return { delay: BigInt(delay), delayVersion: BigInt(delayVersion), keysVersion: BigInt(keysVersion), recovery: getAddress(recovery) };
    },
    (value) => `${value.delay}:${value.delayVersion}:${value.keysVersion}:${value.recovery}`,
  );
}

/** Whether the contract is paused now, its pause version (what `Pause` and `Unpause` sign) and its guardian, agreed by both endpoints. */
export async function switchState(chain: AgreedChain, contract: Address): Promise<{ readonly paused: boolean; readonly pauseVersion: bigint; readonly guardian: Address }> {
  return readAgreed(
    chain,
    "paused(), pauseVersion() and guardian()",
    async (client) => {
      const [paused, pauseVersion, guardian] = await Promise.all([
        client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "paused", blockNumber: chain.block }),
        client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "pauseVersion", blockNumber: chain.block }),
        client.readContract({ address: contract, abi: APP_AUTH_ABI, functionName: "guardian", blockNumber: chain.block }),
      ]);
      return { paused, pauseVersion: BigInt(pauseVersion), guardian: getAddress(guardian) };
    },
    (value) => `${value.paused}:${value.pauseVersion}:${value.guardian}`,
  );
}

/** Every `(kind, hash)` the contract's `Proposed` events name between `fromBlock` and the agreed block, in event order. */
async function proposedOn(client: PublicClient, contract: Address, fromBlock: bigint, toBlock: bigint, range: bigint): Promise<{ kind: ReleaseKind; hash: Hex }[]> {
  const found: { kind: ReleaseKind; hash: Hex }[] = [];
  let requests = 0;
  for (let start = fromBlock; start <= toBlock; start += range) {
    requests += 1;
    if (requests > MAX_LOG_REQUESTS) throw new RelayKitError("usage", `listing from block ${fromBlock} takes more than ${MAX_LOG_REQUESTS} log requests of ${range} blocks; give a later --from-block (the contract's deployment block)`);
    const end = start + range - 1n < toBlock ? start + range - 1n : toBlock;
    const logs = await client.getContractEvents({ address: contract, abi: APP_AUTH_ABI, eventName: "Proposed", fromBlock: start, toBlock: end, strict: true });
    for (const log of logs) found.push({ kind: releaseKindOf(Number(log.args.kind)), hash: log.args.releaseHash as Hex });
  }
  return found;
}

/** Every release proposed on the contract since `fromBlock`, with its state now; both endpoints must agree on both. */
export async function listReleases(chain: AgreedChain, contract: Address, fromBlock: bigint, range: bigint = DEFAULT_LOG_RANGE): Promise<readonly ReleaseState[]> {
  if (fromBlock > chain.block) return [];
  const proposals = await readAgreed(chain, "the Proposed events", (client) => proposedOn(client, contract, fromBlock, chain.block, range), (list) => list.map((entry) => `${entry.kind}:${entry.hash}`).join(","));
  const states: ReleaseState[] = [];
  for (const proposal of proposals) states.push(await releaseState(chain, contract, proposal.kind, proposal.hash));
  return states;
}

/** A state as JSON (integers as decimal strings, instants as ISO text too). */
export function releaseStateJson(state: ReleaseState): Record<string, unknown> {
  const iso = (seconds: bigint) => (seconds === 0n ? null : new Date(Number(seconds) * 1000).toISOString());
  return {
    kind: state.kind,
    hash: state.hash,
    proposed_at: state.proposedAt.toString(),
    proposed_at_iso: iso(state.proposedAt),
    effective_at: state.effectiveAt.toString(),
    effective_at_iso: iso(state.effectiveAt),
    approved: state.approved,
    vetoed: state.vetoed,
    removed: state.removed,
    effective: state.effective,
    version: state.version.toString(),
  };
}
