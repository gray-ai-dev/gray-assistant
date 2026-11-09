/**
 * Gray's proposer's messages on a relay's contract (docs/design/relay-no-always-on-host.md 3.2, 13.4, 13.11 P6): a
 * `Propose` of a release (`proposeBySig`), and a `Remove` of a release Gray retires (`removeBySig`, the message the
 * guardian signs too, with the proposer as signer and the release's current version). Gray's offline proposer key signs
 * them; anyone may submit them (Gray's relayer). One item is one message for one contract; the release tool keeps items
 * in a file (`gray-release-proposals/1`) between the online read, the offline signature and the submission.
 *
 * Pure: no `node:*`, no network, no clock.
 */
import { encodeFunctionData, getAddress, hashTypedData, recoverTypedDataAddress, type Address, type Hex, type TypedDataDomain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { APP_AUTH_ABI, APP_AUTH_DOMAIN_NAME, APP_AUTH_DOMAIN_VERSION, RELEASE_KIND_NUMBER, checkedAddress, releaseHash, type ReleaseKind } from "./app-auth.ts";
import { AppAuthError } from "./errors.ts";
import { APP_AUTH_TYPES } from "./guardian.ts";

/** `Propose(uint8 kind,bytes32 releaseHash,uint256 nonce,uint256 deadline)`: the contract's `PROPOSE_TYPEHASH`. */
export const PROPOSE_TYPES = {
  Propose: [
    { name: "kind", type: "uint8" },
    { name: "releaseHash", type: "bytes32" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

/** The proposals file's schema. */
export const PROPOSALS_SCHEMA = "gray-release-proposals/1";

/** One message of Gray's proposer for one contract. */
export interface ProposerItem {
  readonly relayId: string;
  readonly chainId: number;
  readonly contract: Address;
  readonly action: "propose" | "remove";
  readonly kind: ReleaseKind;
  readonly hash: Hex;
  /** `remove` only: the release's version the removal decides (`releaseOf(kind, hash).version`); 0 for `propose`. */
  readonly version: bigint;
  /** Gray's proposer, the contract's immutable `proposer()`: the signer. */
  readonly proposer: Address;
  /** The proposer's nonce on this contract (`nonces(proposer)`), one per message in order. */
  readonly nonce: bigint;
  /** Unix seconds; the contract refuses the signature after it. */
  readonly deadline: bigint;
}

function domainOf(item: ProposerItem): TypedDataDomain {
  return { name: APP_AUTH_DOMAIN_NAME, version: APP_AUTH_DOMAIN_VERSION, chainId: item.chainId, verifyingContract: getAddress(item.contract) };
}

/** The typed data of one item, as viem signs and hashes it. */
export function proposerTypedData(item: ProposerItem) {
  const domain = domainOf(item);
  if (item.action === "propose") {
    return { domain, types: PROPOSE_TYPES, primaryType: "Propose", message: { kind: RELEASE_KIND_NUMBER[item.kind], releaseHash: item.hash, nonce: item.nonce, deadline: item.deadline } } as const;
  }
  return {
    domain,
    types: { Remove: APP_AUTH_TYPES.Remove },
    primaryType: "Remove",
    message: { kind: RELEASE_KIND_NUMBER[item.kind], releaseHash: item.hash, version: item.version, signer: getAddress(item.proposer), nonce: item.nonce, deadline: item.deadline },
  } as const;
}

/** The EIP-712 digest the contract checks the proposer's signature against. */
export function proposerDigest(item: ProposerItem): Hex {
  return hashTypedData(proposerTypedData(item) as Parameters<typeof hashTypedData>[0]);
}

/** The address of a secp256k1 private key (the release tool names the key it signs or submits with). */
export function keyAddress(privateKey: Hex): Address {
  return privateKeyToAccount(privateKey).address;
}

/** Sign one item with the proposer key; the key must be the item's proposer. */
export async function signProposerItem(privateKey: Hex, item: ProposerItem): Promise<Hex> {
  const account = privateKeyToAccount(privateKey);
  if (account.address !== getAddress(item.proposer)) throw new AppAuthError("invalid_key_file", `the key is ${account.address}, not the proposer ${getAddress(item.proposer)} the item names`);
  return account.signTypedData(proposerTypedData(item) as Parameters<typeof account.signTypedData>[0]);
}

/** Who signed an item, recovered from the signature. */
export async function proposerItemSigner(item: ProposerItem, signature: Hex): Promise<Address> {
  return recoverTypedDataAddress({ ...(proposerTypedData(item) as Parameters<typeof hashTypedData>[0]), signature });
}

/** The contract call that carries a signed item: `proposeBySig(kind, hash, nonce, deadline, sig)` or `removeBySig(...)`. */
export function proposerCalldata(item: ProposerItem, signature: Hex): Hex {
  const kind = RELEASE_KIND_NUMBER[item.kind];
  if (item.action === "propose") return encodeFunctionData({ abi: APP_AUTH_ABI, functionName: "proposeBySig", args: [kind, item.hash, item.nonce, item.deadline, signature] });
  return encodeFunctionData({ abi: APP_AUTH_ABI, functionName: "removeBySig", args: [kind, item.hash, item.version, getAddress(item.proposer), item.nonce, item.deadline, signature] });
}

/** The `eth_signTypedData_v4` document of an item, for a hardware wallet holding the proposer key. */
export function proposerWalletTypedData(item: ProposerItem): Record<string, unknown> {
  const typed = proposerTypedData(item);
  const message: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(typed.message)) message[name] = typeof value === "bigint" ? value.toString() : value;
  return {
    types: {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId", type: "uint256" },
        { name: "verifyingContract", type: "address" },
      ],
      ...typed.types,
    },
    primaryType: typed.primaryType,
    domain: typed.domain,
    message,
  };
}

/** An item as the proposals file writes it (integers as decimal strings), with its digest and typed data for the signer. */
export function proposerItemJson(item: ProposerItem, signature: Hex | null = null): Record<string, unknown> {
  return {
    relay_id: item.relayId,
    chain_id: item.chainId,
    contract: getAddress(item.contract),
    action: item.action,
    kind: item.kind,
    hash: item.hash,
    version: item.version.toString(),
    proposer: getAddress(item.proposer),
    nonce: item.nonce.toString(),
    deadline: item.deadline.toString(),
    digest: proposerDigest(item),
    typed_data: proposerWalletTypedData(item),
    ...(signature === null ? {} : { signature }),
  };
}

const RELAY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const DECIMAL = /^(0|[1-9][0-9]{0,30})$/;
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;

function field(value: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(value, name) ? value[name] : undefined;
}

function decimal(value: unknown, what: string): bigint {
  if (typeof value !== "string" || !DECIMAL.test(value)) throw new AppAuthError("usage", `${what} is a decimal string`);
  return BigInt(value);
}

/**
 * Read one item of a proposals file back. The `digest` it carries must be the one its fields give (the signer signs
 * what the fields say, never a digest alone), and a `signature`, when present, must be 65 bytes.
 */
export function parseProposerItem(value: unknown, where = "item"): { readonly item: ProposerItem; readonly signature: Hex | null } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new AppAuthError("usage", `${where} is not an object`);
  const record = value as Record<string, unknown>;
  const relayId = field(record, "relay_id");
  if (typeof relayId !== "string" || !RELAY_ID.test(relayId)) throw new AppAuthError("usage", `${where}.relay_id is not a relay id`);
  const chainId = field(record, "chain_id");
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId <= 0) throw new AppAuthError("usage", `${where}.chain_id is not a chain id`);
  const action = field(record, "action");
  if (action !== "propose" && action !== "remove") throw new AppAuthError("usage", `${where}.action is propose or remove`);
  const kind = field(record, "kind");
  if (kind !== "compose" && kind !== "os_image") throw new AppAuthError("usage", `${where}.kind is compose or os_image`);
  const item: ProposerItem = {
    relayId,
    chainId,
    contract: checkedAddress(String(field(record, "contract")), `${where}.contract`),
    action,
    kind,
    hash: releaseHash(String(field(record, "hash")), `${where}.hash`),
    version: decimal(field(record, "version"), `${where}.version`),
    proposer: checkedAddress(String(field(record, "proposer")), `${where}.proposer`),
    nonce: decimal(field(record, "nonce"), `${where}.nonce`),
    deadline: decimal(field(record, "deadline"), `${where}.deadline`),
  };
  if (action === "propose" && item.version !== 0n) throw new AppAuthError("usage", `${where}.version is 0 for a proposal`);
  if (field(record, "digest") !== proposerDigest(item)) throw new AppAuthError("usage", `${where}.digest is not the digest of its fields`);
  const signature = field(record, "signature");
  if (signature === undefined) return { item, signature: null };
  if (typeof signature !== "string" || !SIGNATURE.test(signature)) throw new AppAuthError("usage", `${where}.signature is 65 bytes of hex`);
  return { item, signature: signature as Hex };
}
