/**
 * The `chain` member of gray-assistant.jsonc: the relay's contract on Base and how the kit reads and signs for it
 * (docs/design/relay-no-always-on-host.md 3.2, 3.3). A config with `chain` is a phase-2 relay's: `releases
 * list|check|approve|reject`, `pause` and `unpause` act on the contract. Pairing writes it once Gray's pairing answer
 * names the proposer and the contract (P5); until then it is written by hand.
 *
 *   "chain": {
 *     "chain_id": 8453,
 *     "rpc": ["https://<provider one>/...", "https://<provider two>/..."],   // two independent endpoints
 *     "proposer": "0x…",          // Gray's release proposer
 *     "guardian": "0x…",          // the relay's guardian
 *     "guardian_key": "guardian-key.json",   // the guardian's key, which the kit holds
 *     "contract": "0x…",          // the relay's GrayRelayAppAuth (the app id)
 *     "dstack_kms": "0x…",        // default Base's DstackKms
 *     "from_block": 123           // where `releases list` starts reading events: the contract's deployment block
 *   }
 */
import { getAddress, isAddress, type Address } from "viem";
import { z } from "zod";
import { RelayKitError } from "../errors.ts";
import { BASE_DSTACK_KMS } from "./app-auth.ts";
import { checkedRpcUrl } from "./rpc.ts";

export interface ChainConfig {
  readonly chainId: number;
  readonly rpc: readonly [string, string];
  readonly proposer: Address;
  readonly guardian: Address;
  /** The guardian key file as written (relative to the config's directory). */
  readonly guardianKey: string;
  readonly contract: Address;
  readonly dstackKms: Address;
  readonly fromBlock: bigint | null;
}

const addressSchema = z.string().refine((value) => isAddress(value, { strict: false }) && !/^0x0{40}$/i.test(value), "an Ethereum address (0x and 40 hex digits), not zero");

export const chainConfigSchema = z
  .object({
    chain_id: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    rpc: z.array(z.string().max(2048)).length(2),
    proposer: addressSchema,
    guardian: addressSchema,
    guardian_key: z.string().min(1).max(4096),
    contract: addressSchema,
    dstack_kms: addressSchema.optional(),
    from_block: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
  })
  .strict();

/** Parse the `chain` member. The two endpoints must be different origins: one provider answering twice is one witness. */
export function parseChainConfig(value: unknown): ChainConfig {
  const parsed = chainConfigSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new RelayKitError("usage", `invalid chain config: chain.${issue?.path.join(".") ?? ""} ${issue?.message ?? ""}`.trim());
  }
  const data = parsed.data;
  const rpc = data.rpc.map((url, index) => checkedRpcUrl(url, `chain.rpc.${index}`)) as [string, string];
  if (new URL(rpc[0]).origin === new URL(rpc[1]).origin) throw new RelayKitError("usage", "chain.rpc names one origin twice: give two independent endpoints (two providers)");
  return {
    chainId: data.chain_id,
    rpc,
    proposer: getAddress(data.proposer),
    guardian: getAddress(data.guardian),
    guardianKey: data.guardian_key,
    contract: getAddress(data.contract),
    dstackKms: getAddress(data.dstack_kms ?? BASE_DSTACK_KMS),
    fromBlock: data.from_block === undefined ? null : BigInt(data.from_block),
  };
}
