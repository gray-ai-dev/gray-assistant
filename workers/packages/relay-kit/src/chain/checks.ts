/**
 * The chain checks `deliver` runs before it seals anything (docs/design/relay-no-always-on-host.md 3.3; P4b calls
 * them): the relay's contract read from **two independent RPC endpoints that must agree**, at the same block.
 *
 * Each endpoint must answer the configured chain id. The reading is taken at the lower of the two endpoints' latest
 * blocks, so two honest endpoints answer the same state; any difference is a refusal, as is an endpoint that cannot be
 * read. That block must be the chain as it is now (`freshCommonBlock`): the heads at most MAX_HEAD_LAG_BLOCKS apart and
 * the block at most MAX_BLOCK_AGE_SECONDS old, else one lagging endpoint could hold both to a state before a pause. Then the reading must show: the code at the app id is `GrayRelayAppAuth`'s published runtime code for this
 * proposer, chain and address (`app-auth.ts`); `guardian()` is the kit's guardian; `DELAY()` is 7 days; Base's
 * `DstackKms` has the app registered; the given compose hash and OS image hash are `effective`; `paused()` is false.
 */
import { getAddress, keccak256, parseAbi, type Address, type Hex, type PublicClient } from "viem";
import { isRelayKitError, RelayKitError } from "../errors.ts";
import { APP_AUTH_ABI, APP_AUTH_DELAY_SECONDS, RELEASE_KIND_NUMBER, appAuthCodeHash } from "./app-auth.ts";
import { rpcClient, rpcLabel, type RpcOptions } from "./rpc.ts";

export const DSTACK_KMS_ABI = parseAbi(["function registeredApps(address app) view returns (bool)"]);

/**
 * The most the two endpoints' latest blocks may differ (10 s of Base's 2-second blocks): a lagging endpoint must not
 * set the block both are read at, or it would hold the honest one to a state before a pause or a veto.
 */
export const MAX_HEAD_LAG_BLOCKS = 5n;
/**
 * The oldest the block both are read at may be, by this machine's clock: Base makes one every 2 s, so a minute leaves
 * room for the clock and the requests, and two endpoints that both stopped (or both lie) at an old state are refused.
 * A block dated ahead of the clock is not refused here (a local anvil moved forward in time).
 */
export const MAX_BLOCK_AGE_SECONDS = 60n;

/** The freshness bounds' clock (default `Date.now`). */
export interface FreshnessOptions {
  readonly nowMs?: number;
}

/**
 * The block both endpoints are read at: the lower of their latest blocks, which must be within MAX_HEAD_LAG_BLOCKS of
 * the higher; both must answer the same hash and time for it, and that time must be at most MAX_BLOCK_AGE_SECONDS old.
 * Throws `chain_stale` (or `chain_disagreement`, `chain_unreachable`) otherwise.
 */
export async function freshCommonBlock(clients: readonly PublicClient[], urls: readonly string[], heads: readonly bigint[], nowMs: number): Promise<bigint> {
  const low = heads.reduce((a, b) => (b < a ? b : a));
  const high = heads.reduce((a, b) => (b > a ? b : a));
  if (high - low > MAX_HEAD_LAG_BLOCKS) {
    throw new RelayKitError("chain_stale", `the two endpoints' latest blocks are ${high - low} apart (${low} and ${high}; at most ${MAX_HEAD_LAG_BLOCKS}): one lags behind the chain; name another endpoint`);
  }
  const blocks = await Promise.all(
    clients.map((client, index) =>
      onEndpoint(urls[index] as string, "eth_getBlockByNumber", async () => {
        const block = (await client.request({ method: "eth_getBlockByNumber", params: [`0x${low.toString(16)}`, false] } as never)) as { hash?: unknown; timestamp?: unknown } | null;
        if (block === null || typeof block.hash !== "string" || typeof block.timestamp !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(block.timestamp)) throw new Error("no block");
        return { hash: block.hash.toLowerCase(), timestamp: BigInt(block.timestamp) };
      }),
    ),
  );
  const [first, second] = blocks as [{ hash: string; timestamp: bigint }, { hash: string; timestamp: bigint }];
  if (first.hash !== second.hash || first.timestamp !== second.timestamp) {
    throw new RelayKitError("chain_disagreement", `${rpcLabel(urls[0] as string)} and ${rpcLabel(urls[1] as string)} answer block ${low} differently`);
  }
  const age = BigInt(Math.floor(nowMs / 1000)) - first.timestamp;
  if (age > MAX_BLOCK_AGE_SECONDS) {
    throw new RelayKitError("chain_stale", `block ${low}, the latest both endpoints have, is ${age} s old (at most ${MAX_BLOCK_AGE_SECONDS} s): the endpoints do not follow the chain, or this machine's clock is wrong`);
  }
  return low;
}

export interface ChainCheckInput {
  readonly chainId: number;
  /** The relay's contract: the app id. */
  readonly contract: Address;
  /** Gray's proposer, an immutable of the contract (so part of its code hash). */
  readonly proposer: Address;
  /** The kit's guardian. */
  readonly guardian: Address;
  readonly dstackKms: Address;
  /** The compose hash and OS image hash that must be effective; null skips that check (none to check yet). */
  readonly composeHash: Hex | null;
  readonly osImageHash: Hex | null;
}

/** What one endpoint answered at the agreed block. */
export interface ChainReading {
  readonly codeHash: Hex | null;
  readonly guardian: Address | null;
  readonly delaySeconds: bigint | null;
  readonly paused: boolean | null;
  readonly registered: boolean;
  readonly composeEffective: boolean | null;
  readonly osImageEffective: boolean | null;
}

export type ChainCheckName = "code" | "guardian" | "delay" | "registered" | "compose_effective" | "os_image_effective" | "not_paused";

export interface ChainCheck {
  readonly name: ChainCheckName;
  readonly ok: boolean;
  readonly detail: string;
}

export type ChainCheckResult =
  | {
      readonly ok: true;
      readonly block: bigint;
      readonly endpoints: readonly string[];
      readonly reading: ChainReading;
      readonly checks: readonly ChainCheck[];
    }
  | {
      /**
       * `refused`: both endpoints agree and a check fails. `disagree`: they answered differently. `unreachable`: one
       * could not be read. `stale`: their latest blocks are too far apart, or the block both have is too old.
       */
      readonly ok: false;
      readonly reason: "refused" | "disagree" | "unreachable" | "stale";
      readonly block: bigint | null;
      readonly endpoints: readonly string[];
      readonly reading: ChainReading | null;
      readonly checks: readonly ChainCheck[];
      readonly detail: string;
    };

/** The RelayKitError a viem error carries in its causes, if any. */
export function kitErrorIn(error: unknown): RelayKitError | null {
  for (let at: unknown = error, depth = 0; at !== null && at !== undefined && depth < 8; depth += 1) {
    if (isRelayKitError(at)) return at;
    at = (at as { cause?: unknown }).cause;
  }
  return null;
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

/** The endpoint's chain id, which must be the configured one. */
export async function endpointChainId(client: PublicClient, url: string): Promise<number> {
  return onEndpoint(url, "eth_chainId", () => client.getChainId());
}

async function readAt(client: PublicClient, url: string, input: ChainCheckInput, block: bigint): Promise<ChainReading> {
  return onEndpoint(url, "the relay's contract", async () => {
    const code = await client.getCode({ address: input.contract, blockNumber: block });
    const codeHash = code === undefined || code === "0x" ? null : keccak256(code);
    const registered = await client.readContract({ address: input.dstackKms, abi: DSTACK_KMS_ABI, functionName: "registeredApps", args: [input.contract], blockNumber: block });
    if (codeHash === null) return { codeHash, guardian: null, delaySeconds: null, paused: null, registered, composeEffective: null, osImageEffective: null };
    const read = <T>(functionName: string, args: readonly unknown[] = []) =>
      client.readContract({ address: input.contract, abi: APP_AUTH_ABI, functionName, args, blockNumber: block } as Parameters<PublicClient["readContract"]>[0]) as Promise<T>;
    const [guardian, delaySeconds, paused, composeEffective, osImageEffective] = await Promise.all([
      read<Address>("guardian"),
      read<bigint>("DELAY"),
      read<boolean>("paused"),
      input.composeHash === null ? Promise.resolve(null) : read<boolean>("effective", [RELEASE_KIND_NUMBER.compose, input.composeHash]),
      input.osImageHash === null ? Promise.resolve(null) : read<boolean>("effective", [RELEASE_KIND_NUMBER.os_image, input.osImageHash]),
    ]);
    return { codeHash, guardian: getAddress(guardian), delaySeconds, paused, registered, composeEffective, osImageEffective };
  });
}

function sameReading(a: ChainReading, b: ChainReading): string | null {
  for (const key of Object.keys(a) as (keyof ChainReading)[]) {
    if (a[key] !== b[key]) return key;
  }
  return null;
}

function judge(reading: ChainReading, input: ChainCheckInput, expectedCodeHash: Hex): ChainCheck[] {
  const checks: ChainCheck[] = [];
  checks.push(
    reading.codeHash === null
      ? { name: "code", ok: false, detail: `no contract at ${input.contract}` }
      : reading.codeHash === expectedCodeHash
        ? { name: "code", ok: true, detail: `the code at ${input.contract} is GrayRelayAppAuth's for this proposer and chain (${expectedCodeHash})` }
        : { name: "code", ok: false, detail: `the code at ${input.contract} hashes to ${reading.codeHash}, not GrayRelayAppAuth's ${expectedCodeHash}` },
  );
  checks.push(
    reading.guardian === input.guardian
      ? { name: "guardian", ok: true, detail: `guardian() is ${input.guardian}` }
      : { name: "guardian", ok: false, detail: `guardian() is ${reading.guardian ?? "unreadable"}, not this kit's ${input.guardian}` },
  );
  checks.push(
    reading.delaySeconds === APP_AUTH_DELAY_SECONDS
      ? { name: "delay", ok: true, detail: "DELAY() is 7 days" }
      : { name: "delay", ok: false, detail: `DELAY() is ${reading.delaySeconds ?? "unreadable"} s, not 7 days` },
  );
  checks.push(
    reading.registered
      ? { name: "registered", ok: true, detail: `DstackKms ${input.dstackKms} has the app registered` }
      : { name: "registered", ok: false, detail: `DstackKms ${input.dstackKms} has not registered ${input.contract}` },
  );
  if (input.composeHash !== null) {
    checks.push(
      reading.composeEffective === true
        ? { name: "compose_effective", ok: true, detail: `compose ${input.composeHash} is effective` }
        : { name: "compose_effective", ok: false, detail: `compose ${input.composeHash} is not effective` },
    );
  }
  if (input.osImageHash !== null) {
    checks.push(
      reading.osImageEffective === true
        ? { name: "os_image_effective", ok: true, detail: `OS image ${input.osImageHash} is effective` }
        : { name: "os_image_effective", ok: false, detail: `OS image ${input.osImageHash} is not effective` },
    );
  }
  checks.push(reading.paused === false ? { name: "not_paused", ok: true, detail: "paused() is false" } : { name: "not_paused", ok: false, detail: reading.paused === true ? "the contract is paused" : "paused() is unreadable" });
  return checks;
}

/**
 * Read the relay's contract from two endpoints and judge it. Never throws for what an endpoint answers: an unreachable
 * endpoint, a wrong chain and a disagreement are results, so `deliver` can say which.
 */
export async function checkRelayContract(rpcUrls: readonly string[], input: ChainCheckInput, options: RpcOptions & FreshnessOptions & { readonly clients?: readonly PublicClient[] } = {}): Promise<ChainCheckResult> {
  if (rpcUrls.length !== 2) throw new RelayKitError("usage", "the chain checks read two RPC endpoints");
  const endpoints = rpcUrls.map(rpcLabel);
  const clients = options.clients ?? rpcUrls.map((url) => rpcClient(url, options));
  const expectedCodeHash = appAuthCodeHash({ proposer: input.proposer, chainId: input.chainId, address: input.contract });
  const unreachable = (detail: string, block: bigint | null = null): ChainCheckResult => ({ ok: false, reason: "unreachable", block, endpoints, reading: null, checks: [], detail });
  let block: bigint;
  try {
    const heads = await Promise.all(
      clients.map(async (client, index) => {
        const url = rpcUrls[index] as string;
        const chainId = await endpointChainId(client, url);
        if (chainId !== input.chainId) throw new RelayKitError("chain_refused", `${rpcLabel(url)} is chain ${chainId}, not ${input.chainId}`);
        return onEndpoint(url, "eth_blockNumber", () => client.getBlockNumber({ cacheTime: 0 }));
      }),
    );
    block = await freshCommonBlock(clients, rpcUrls, heads, options.nowMs ?? Date.now());
  } catch (error) {
    const kit = kitErrorIn(error);
    if (kit?.code === "chain_stale") return { ok: false, reason: "stale", block: null, endpoints, reading: null, checks: [], detail: kit.detail ?? "the chain is not read as it is now" };
    if (kit?.code === "chain_disagreement") return { ok: false, reason: "disagree", block: null, endpoints, reading: null, checks: [], detail: kit.detail ?? "the endpoints disagree" };
    return unreachable(kit?.detail ?? "an RPC endpoint could not be read");
  }
  let readings: ChainReading[];
  try {
    readings = await Promise.all(clients.map((client, index) => readAt(client, rpcUrls[index] as string, input, block)));
  } catch (error) {
    const kit = kitErrorIn(error);
    return unreachable(kit?.detail ?? "an RPC endpoint could not be read", block);
  }
  const [first, second] = readings as [ChainReading, ChainReading];
  const differs = sameReading(first, second);
  if (differs !== null) {
    return { ok: false, reason: "disagree", block, endpoints, reading: null, checks: [], detail: `${endpoints[0]} and ${endpoints[1]} answer ${differs} differently at block ${block}` };
  }
  const checks = judge(first, input, expectedCodeHash);
  const failed = checks.filter((check) => !check.ok);
  if (failed.length > 0) return { ok: false, reason: "refused", block, endpoints, reading: first, checks, detail: failed.map((check) => check.detail).join("; ") };
  return { ok: true, block, endpoints, reading: first, checks };
}

/** The result as JSON (integers as decimal strings). */
export function chainCheckJson(result: ChainCheckResult): Record<string, unknown> {
  const reading = result.reading;
  return {
    ok: result.ok,
    ...(result.ok ? {} : { reason: result.reason, detail: result.detail }),
    block: result.block === null ? null : result.block.toString(),
    endpoints: [...result.endpoints],
    reading:
      reading === null
        ? null
        : {
            code_hash: reading.codeHash,
            guardian: reading.guardian,
            delay_seconds: reading.delaySeconds === null ? null : reading.delaySeconds.toString(),
            paused: reading.paused,
            registered: reading.registered,
            compose_effective: reading.composeEffective,
            os_image_effective: reading.osImageEffective,
          },
    checks: result.checks.map((check) => ({ name: check.name, ok: check.ok, detail: check.detail })),
  };
}
