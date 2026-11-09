/**
 * The relay's contract, `GrayRelayAppAuth` (contracts/relay-app-auth), as gray-assistant computes it before it exists
 * and Gray's console and provisioner compute it to check the pairing and to deploy it (docs/design/
 * relay-no-always-on-host.md 13.8, C12): its CREATE2 address and the runtime code that must be at it.
 *
 * - **Address.** Gray deploys through the deterministic CREATE2 proxy (`0x4e59…956C`, present on Base and on every
 *   anvil) with `salt = keccak256("gray-relay-app-auth/v1\n" ‖ relay_id)` and `initCode = creationCode ‖
 *   abi.encode(proposer, guardian, recovery, composeHashes, osImageHashes)`, so the address is
 *   `keccak256(0xff ‖ proxy ‖ salt ‖ keccak256(initCode))[12:]`.
 * - **Runtime code.** The compiler leaves every immutable as zeros in the runtime code and the constructor writes them;
 *   the exported artifact names where each sits. Filling them for a given proposer, chain id and address gives the
 *   exact code `eth_getCode` answers there, so its keccak256 is the code hash `deliver` compares (A1's dry run: the
 *   chain id and the EIP-712 domain separator are immutables, so the hash is per chain and per address).
 *
 * Pure: no network, no clock. viem does the hashing and the ABI encoding.
 */
import { concat, encodeAbiParameters, encodeDeployData, getAddress, getCreate2Address, hexToBytes, bytesToHex, isAddress, keccak256, numberToHex, pad, stringToBytes, zeroAddress, type Address, type Hex } from "viem";
import { AppAuthError } from "./errors.ts";
import { APP_AUTH_ABI, APP_AUTH_CREATION_CODE, APP_AUTH_IMMUTABLES, APP_AUTH_RUNTIME_TEMPLATE } from "./artifact.ts";

/** The deterministic deployment proxy (github.com/Arachnid/deterministic-deployment-proxy); A1 found it on Base. */
export const CREATE2_PROXY: Address = "0x4e59b44847b379578588920cA78FbF26c0B4956C";
/** Base mainnet. */
export const BASE_CHAIN_ID = 8453;
/** Phala's `DstackKms` on Base (13.2): `registeredApps(app)` must be true for the relay's contract. */
export const BASE_DSTACK_KMS: Address = "0x2f83172A49584C017F2B256F0FB2Dca14126Ba9C";
/** The contract's `DELAY()`: 7 days (owner 2026-10-29). */
export const APP_AUTH_DELAY_SECONDS = 7n * 24n * 60n * 60n;
/** The salt's prefix; the relay id follows it, as UTF-8. Version 1 of the rule. */
export const APP_AUTH_SALT_PREFIX = "gray-relay-app-auth/v1\n";
/** The contract's EIP-712 domain name and version (`EIP712("GrayRelayAppAuth", "1")`). */
export const APP_AUTH_DOMAIN_NAME = "GrayRelayAppAuth";
export const APP_AUTH_DOMAIN_VERSION = "1";

/** What a release hash measures: the contract's `Kind` (0 compose, 1 OS image). */
export type ReleaseKind = "compose" | "os_image";
export const RELEASE_KIND_NUMBER: Readonly<Record<ReleaseKind, 0 | 1>> = { compose: 0, os_image: 1 };
export function releaseKindOf(value: number): ReleaseKind {
  if (value === 0) return "compose";
  if (value === 1) return "os_image";
  throw new AppAuthError("chain_refused", `release kind ${value} is neither compose (0) nor OS image (1)`);
}

export { APP_AUTH_ABI };

/**
 * A build of the contract: its creation code, its runtime code with the immutables zero, and where each immutable
 * sits. The current build is the exported artifact's (`APP_AUTH_CODE`); a contract deployed from an earlier build (A1's,
 * on Base) is computed from that build's artifact (`appAuthCodeFromArtifact`).
 */
export interface AppAuthCode {
  readonly creationCode: Hex;
  readonly runtimeTemplate: Hex;
  readonly immutables: Readonly<Record<string, readonly { readonly start: number; readonly length: number }[]>>;
}

/** The current build: contracts/relay-app-auth/abi/GrayRelayAppAuth.json. */
export const APP_AUTH_CODE: AppAuthCode = { creationCode: APP_AUTH_CREATION_CODE, runtimeTemplate: APP_AUTH_RUNTIME_TEMPLATE, immutables: APP_AUTH_IMMUTABLES };

/** A build from an exported artifact's JSON value (`export-artifact.sh`'s shape). Throws on another shape. */
export function appAuthCodeFromArtifact(value: unknown): AppAuthCode {
  const record = (typeof value === "object" && value !== null ? value : {}) as Record<string, unknown>;
  const creation = record["creation_code"];
  const runtime = record["runtime_code"];
  const immutables = record["immutables"];
  if (typeof creation !== "string" || !/^0x(?:[0-9a-f]{2})+$/.test(creation) || typeof runtime !== "string" || !/^0x(?:[0-9a-f]{2})+$/.test(runtime)) {
    throw new Error("the artifact's code is not 0x-prefixed lower-case hex");
  }
  if (typeof immutables !== "object" || immutables === null) throw new Error("the artifact has no immutables");
  const places: Record<string, { start: number; length: number }[]> = {};
  for (const [name, list] of Object.entries(immutables as Record<string, unknown>)) {
    if (!Array.isArray(list)) throw new Error(`immutable ${name} has no places`);
    places[name] = list.map((place: unknown) => {
      const { start, length } = (place ?? {}) as { start?: unknown; length?: unknown };
      if (typeof start !== "number" || typeof length !== "number") throw new Error(`immutable ${name} has a place that is not {start, length}`);
      return { start, length };
    });
  }
  return { creationCode: creation as Hex, runtimeTemplate: runtime as Hex, immutables: places };
}

/** The constructor's arguments and the relay id: everything the address depends on. */
export interface AppAuthDeployment {
  readonly relayId: string;
  /** Gray's release proposer. */
  readonly proposer: Address;
  /** The relay's guardian. */
  readonly guardian: Address;
  /** The relay's recovery address, or null for none (the zero address). */
  readonly recovery: Address | null;
  /** The release current at pairing: proposed at deployment, approved by the guardian's pairing signatures. */
  readonly composeHashes: readonly Hex[];
  readonly osImageHashes: readonly Hex[];
}

const HASH = /^0x[0-9a-f]{64}$/;

/** A release hash as the contract takes it: 32 bytes, lower-case hex with 0x; refuses zero (the contract does). */
export function releaseHash(value: string, what = "the hash"): Hex {
  const lower = (value.startsWith("0x") ? value : `0x${value}`).toLowerCase();
  if (!HASH.test(lower)) throw new AppAuthError("usage", `${what} is 32 bytes of hex (64 hex digits, with or without 0x)`);
  if (/^0x0{64}$/.test(lower)) throw new AppAuthError("usage", `${what} is zero, which no release has`);
  return lower as Hex;
}

/** An address in its checksummed form; refuses anything else, the zero address unless allowed. */
export function checkedAddress(value: string, what: string, options: { readonly allowZero?: boolean } = {}): Address {
  if (!isAddress(value, { strict: false })) throw new AppAuthError("usage", `${what} is not an Ethereum address (0x and 40 hex digits)`);
  const address = getAddress(value);
  if (!options.allowZero && address === zeroAddress) throw new AppAuthError("usage", `${what} is the zero address`);
  return address;
}

/** The production salt: `keccak256("gray-relay-app-auth/v1\n" ‖ relay_id)`. */
export function appAuthSalt(relayId: string): Hex {
  if (relayId.length === 0) throw new AppAuthError("usage", "the relay id is empty");
  return keccak256(stringToBytes(`${APP_AUTH_SALT_PREFIX}${relayId}`));
}

/** The CREATE2 init code: the creation code with the constructor's arguments ABI-encoded after it. */
export function appAuthInitCode(deployment: AppAuthDeployment, code: AppAuthCode = APP_AUTH_CODE): Hex {
  if (deployment.composeHashes.length === 0 || deployment.osImageHashes.length === 0) {
    throw new AppAuthError("usage", "the first release names at least one compose hash and one OS image hash");
  }
  return encodeDeployData({
    abi: APP_AUTH_ABI,
    bytecode: code.creationCode,
    args: [deployment.proposer, deployment.guardian, deployment.recovery ?? zeroAddress, [...deployment.composeHashes], [...deployment.osImageHashes]],
  });
}

/** The address Gray's CREATE2 deployment gives the relay's contract. */
export function appAuthAddress(deployment: AppAuthDeployment, code: AppAuthCode = APP_AUTH_CODE): Address {
  return getCreate2Address({ from: CREATE2_PROXY, salt: appAuthSalt(deployment.relayId), bytecodeHash: keccak256(appAuthInitCode(deployment, code)) });
}

/** The proxy's calldata for the deployment: `salt ‖ initCode` (what Gray's provisioner sends, P5). */
export function appAuthDeployCalldata(deployment: AppAuthDeployment, code: AppAuthCode = APP_AUTH_CODE): Hex {
  return concat([appAuthSalt(deployment.relayId), appAuthInitCode(deployment, code)]);
}

/** The contract's EIP-712 domain separator on a chain at an address (OpenZeppelin `EIP712._buildDomainSeparator`). */
export function appAuthDomainSeparator(chainId: number, address: Address): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
      [
        keccak256(stringToBytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
        keccak256(stringToBytes(APP_AUTH_DOMAIN_NAME)),
        keccak256(stringToBytes(APP_AUTH_DOMAIN_VERSION)),
        BigInt(chainId),
        address,
      ],
    ),
  );
}

/** OpenZeppelin `ShortStrings.toShortString`: the bytes left-aligned, the length in the last byte (at most 31 bytes). */
function shortString(text: string): Hex {
  const bytes = stringToBytes(text);
  if (bytes.length > 31) throw new Error(`${text} is longer than a ShortString`);
  const word = new Uint8Array(32);
  word.set(bytes, 0);
  word[31] = bytes.length;
  return bytesToHex(word);
}

/**
 * The value of every immutable of the contract at `address` on `chainId` with this proposer, by the artifact's names.
 * The set must be exactly the artifact's: a contract that gains or loses an immutable fails here, not with a wrong hash.
 */
function immutableValues(proposer: Address, chainId: number, address: Address): Readonly<Record<string, Hex>> {
  return {
    "GrayRelayAppAuth.proposer": pad(proposer, { size: 32 }),
    "EIP712._cachedChainId": numberToHex(chainId, { size: 32 }),
    "EIP712._cachedDomainSeparator": appAuthDomainSeparator(chainId, address),
    "EIP712._cachedThis": pad(address, { size: 32 }),
    "EIP712._hashedName": keccak256(stringToBytes(APP_AUTH_DOMAIN_NAME)),
    "EIP712._hashedVersion": keccak256(stringToBytes(APP_AUTH_DOMAIN_VERSION)),
    "EIP712._name": shortString(APP_AUTH_DOMAIN_NAME),
    "EIP712._version": shortString(APP_AUTH_DOMAIN_VERSION),
  };
}

/** The runtime code at the relay's contract: the artifact's template with the immutables filled in. */
export function appAuthRuntimeCode(input: { readonly proposer: Address; readonly chainId: number; readonly address: Address }, build: AppAuthCode = APP_AUTH_CODE): Hex {
  const values = immutableValues(getAddress(input.proposer), input.chainId, getAddress(input.address));
  const names = Object.keys(build.immutables).sort();
  const known = Object.keys(values).sort();
  if (names.length !== known.length || names.some((name, index) => name !== known[index])) {
    throw new Error(`the contract's immutables (${names.join(", ")}) are not the ones the kit fills (${known.join(", ")})`);
  }
  const code = hexToBytes(build.runtimeTemplate);
  for (const name of names) {
    const value = hexToBytes(values[name] as Hex);
    for (const place of build.immutables[name] ?? []) {
      if (place.length !== 32 || place.start + 32 > code.length) throw new Error(`immutable ${name} has a place the kit cannot fill`);
      if (code.subarray(place.start, place.start + 32).some((byte) => byte !== 0)) throw new Error(`immutable ${name}'s place is not zero in the template`);
      code.set(value, place.start);
    }
  }
  return bytesToHex(code);
}

/** keccak256 of that runtime code: what `eth_getCode` at the address must hash to. */
export function appAuthCodeHash(input: { readonly proposer: Address; readonly chainId: number; readonly address: Address }, build: AppAuthCode = APP_AUTH_CODE): Hex {
  return keccak256(appAuthRuntimeCode(input, build));
}
