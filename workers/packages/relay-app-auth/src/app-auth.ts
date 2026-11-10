/**
 * The relay's contract, `GrayRelayAppAuth` (contracts/relay-app-auth), as gray-assistant computes it before it exists
 * and Gray's console and provisioner compute it to check the pairing and to deploy it (docs/design/
 * relay-no-always-on-host.md 13.8, C12): an OpenZeppelin `ERC1967Proxy` of one shared UUPS implementation, both
 * deployed through the deterministic CREATE2 proxy (`0x4e59…956C`, present on Base and on every anvil).
 *
 * - **Implementation.** `salt = keccak256("gray-relay-app-auth/implementation")`, init code its creation code (no
 *   constructor arguments). Its runtime code holds one immutable, UUPS's `__self` (its own address); filled in, its
 *   keccak256 is the code hash `abi/implementations.json` publishes.
 * - **Address.** `salt = keccak256("gray-relay-app-auth/v1\n" ‖ relay_id)` and `initCode = ERC1967Proxy creation code ‖
 *   abi.encode(implementation, initialize(proposer, proposerRecovery, guardian, recovery, composeHashes, osImageHashes))`, so the address
 *   is `keccak256(0xff ‖ proxy ‖ salt ‖ keccak256(initCode))[12:]`.
 * - **The code there.** `ERC1967Proxy`'s runtime code, the same bytes for every relay; the implementation its ERC-1967
 *   slot names must be one Gray publishes, with that code hash (`publishedImplementation`). An upgrade is a release of
 *   kind `implementation` whose hash is `appAuthUpgradeId`; Gray lists each one it proposes (`publishedUpgrade`).
 *
 * Pure: no network, no clock. viem does the hashing and the ABI encoding.
 */
import { bytesToHex, concat, encodeAbiParameters, encodeFunctionData, getAddress, getCreate2Address, hexToBytes, isAddress, keccak256, pad, stringToBytes, type Address, type Hex } from "viem";
import { AppAuthError } from "./errors.ts";
import { APP_AUTH_ABI, APP_AUTH_CREATION_CODE, APP_AUTH_IMMUTABLES, APP_AUTH_PROXY_CREATION_CODE, APP_AUTH_PROXY_RUNTIME_CODE, APP_AUTH_PUBLISHED, APP_AUTH_RUNTIME_TEMPLATE } from "./artifact.ts";

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
/** The implementation's salt: one implementation per build, shared by every relay. */
export const APP_AUTH_IMPLEMENTATION_SALT: Hex = keccak256(stringToBytes("gray-relay-app-auth/implementation"));
/** ERC-1967's implementation slot: `keccak256("eip1967.proxy.implementation") - 1`. */
export const ERC1967_IMPLEMENTATION_SLOT: Hex = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
/** The contract's EIP-712 domain name and version. */
export const APP_AUTH_DOMAIN_NAME = "GrayRelayAppAuth";
export const APP_AUTH_DOMAIN_VERSION = "1";

/** What a release hash measures: the contract's `Kind` (0 compose, 1 OS image, 2 an upgrade of the contract). */
export type ReleaseKind = "compose" | "os_image" | "implementation";
export const RELEASE_KIND_NUMBER: Readonly<Record<ReleaseKind, 0 | 1 | 2>> = { compose: 0, os_image: 1, implementation: 2 };
export function releaseKindOf(value: number): ReleaseKind {
  if (value === 0) return "compose";
  if (value === 1) return "os_image";
  if (value === 2) return "implementation";
  throw new AppAuthError("chain_refused", `release kind ${value} is none of compose (0), OS image (1) and implementation (2)`);
}

export { APP_AUTH_ABI };

/** A build: the implementation's creation code, its runtime code with the immutables zero and where each sits, and the proxy's code. */
export interface AppAuthCode {
  readonly creationCode: Hex;
  readonly runtimeTemplate: Hex;
  readonly immutables: Readonly<Record<string, readonly { readonly start: number; readonly length: number }[]>>;
  readonly proxyCreationCode: Hex;
  readonly proxyRuntimeCode: Hex;
}

/** The current build: contracts/relay-app-auth/abi/GrayRelayAppAuth.json. */
export const APP_AUTH_CODE: AppAuthCode = {
  creationCode: APP_AUTH_CREATION_CODE,
  runtimeTemplate: APP_AUTH_RUNTIME_TEMPLATE,
  immutables: APP_AUTH_IMMUTABLES,
  proxyCreationCode: APP_AUTH_PROXY_CREATION_CODE,
  proxyRuntimeCode: APP_AUTH_PROXY_RUNTIME_CODE,
};

/** `initialize`'s arguments and the relay id: everything the address depends on but the build. */
export interface AppAuthDeployment {
  readonly relayId: string;
  /** Gray's release proposer. */
  readonly proposer: Address;
  /** Gray's proposer recovery key: the only one that replaces the proposer or itself. */
  readonly proposerRecovery: Address;
  /** The relay's guardian. */
  readonly guardian: Address;
  /** The relay's recovery address: required, another key than the guardian. */
  readonly recovery: Address;
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
  if (!options.allowZero && /^0x0{40}$/.test(address)) throw new AppAuthError("usage", `${what} is the zero address`);
  return address;
}

/** The production salt: `keccak256("gray-relay-app-auth/v1\n" ‖ relay_id)`. */
export function appAuthSalt(relayId: string): Hex {
  if (relayId.length === 0) throw new AppAuthError("usage", "the relay id is empty");
  return keccak256(stringToBytes(`${APP_AUTH_SALT_PREFIX}${relayId}`));
}

/** The shared implementation's address: CREATE2 of its creation code. */
export function appAuthImplementationAddress(code: AppAuthCode = APP_AUTH_CODE): Address {
  return getCreate2Address({ from: CREATE2_PROXY, salt: APP_AUTH_IMPLEMENTATION_SALT, bytecodeHash: keccak256(code.creationCode) });
}

/** The proxy's calldata for the implementation's deployment: `salt ‖ creationCode` (once, by the first relay's Deploy). */
export function appAuthImplementationDeployCalldata(code: AppAuthCode = APP_AUTH_CODE): Hex {
  return concat([APP_AUTH_IMPLEMENTATION_SALT, code.creationCode]);
}

/** The implementation's runtime code at its address: the template with UUPS's `__self` filled in. */
export function appAuthImplementationRuntimeCode(code: AppAuthCode = APP_AUTH_CODE): Hex {
  const names = Object.keys(code.immutables);
  if (names.length !== 1 || names[0] !== "UUPSUpgradeable.__self") {
    throw new Error(`the implementation's immutables (${names.join(", ")}) are not the one the kit fills (UUPSUpgradeable.__self)`);
  }
  const bytes = hexToBytes(code.runtimeTemplate);
  const value = hexToBytes(pad(appAuthImplementationAddress(code), { size: 32 }));
  for (const place of code.immutables["UUPSUpgradeable.__self"] ?? []) {
    if (place.length !== 32 || place.start + 32 > bytes.length) throw new Error("UUPSUpgradeable.__self has a place the kit cannot fill");
    if (bytes.subarray(place.start, place.start + 32).some((byte) => byte !== 0)) throw new Error("UUPSUpgradeable.__self's place is not zero in the template");
    bytes.set(value, place.start);
  }
  return bytesToHex(bytes);
}

/** keccak256 of the implementation's runtime code: what `abi/implementations.json` publishes for this build. */
export function appAuthImplementationCodeHash(code: AppAuthCode = APP_AUTH_CODE): Hex {
  return keccak256(appAuthImplementationRuntimeCode(code));
}

/** keccak256 of the code at every relay's address: `ERC1967Proxy`'s runtime code. */
export function appAuthProxyCodeHash(code: AppAuthCode = APP_AUTH_CODE): Hex {
  return keccak256(code.proxyRuntimeCode);
}

/** The `initialize` call the proxy's constructor makes. Refuses a missing or repeated relay key. */
export function appAuthInitData(deployment: AppAuthDeployment): Hex {
  if (deployment.composeHashes.length === 0 || deployment.osImageHashes.length === 0) {
    throw new AppAuthError("usage", "the first release names at least one compose hash and one OS image hash");
  }
  const proposer = checkedAddress(deployment.proposer, "Gray's proposer");
  const proposerRecovery = checkedAddress(deployment.proposerRecovery, "Gray's proposer recovery key");
  const guardian = checkedAddress(deployment.guardian, "the guardian");
  const recovery = checkedAddress(deployment.recovery, "the recovery address");
  // The contract refuses any two of the four keys alike (KeyNotDistinct); so does this, before an address is computed.
  if (new Set([proposer, proposerRecovery, guardian, recovery]).size !== 4) {
    throw new AppAuthError("usage", "Gray's two keys, the guardian and the recovery address are four different keys");
  }
  return encodeFunctionData({
    abi: APP_AUTH_ABI,
    functionName: "initialize",
    args: [proposer, proposerRecovery, guardian, recovery, [...deployment.composeHashes], [...deployment.osImageHashes]],
  });
}

/** The CREATE2 init code of the relay's contract: the proxy's creation code, then the implementation and the call. */
export function appAuthInitCode(deployment: AppAuthDeployment, code: AppAuthCode = APP_AUTH_CODE): Hex {
  const args = encodeAbiParameters([{ type: "address" }, { type: "bytes" }], [appAuthImplementationAddress(code), appAuthInitData(deployment)]);
  return concat([code.proxyCreationCode, args]);
}

/** The address Gray's CREATE2 deployment gives the relay's contract. */
export function appAuthAddress(deployment: AppAuthDeployment, code: AppAuthCode = APP_AUTH_CODE): Address {
  return getCreate2Address({ from: CREATE2_PROXY, salt: appAuthSalt(deployment.relayId), bytecodeHash: keccak256(appAuthInitCode(deployment, code)) });
}

/** The proxy's calldata for the relay's deployment: `salt ‖ initCode` (what Gray's provisioner sends, P5). */
export function appAuthDeployCalldata(deployment: AppAuthDeployment, code: AppAuthCode = APP_AUTH_CODE): Hex {
  return concat([appAuthSalt(deployment.relayId), appAuthInitCode(deployment, code)]);
}

/** The contract's EIP-712 domain separator on a chain at an address (the proxy's; OpenZeppelin `EIP712Upgradeable`). */
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

/** The implementation an ERC-1967 slot's word names. */
export function implementationFromSlot(word: Hex): Address {
  if (!/^0x[0-9a-fA-F]{64}$/.test(word) || !/^0x0{24}/.test(word)) throw new AppAuthError("chain_refused", "the ERC-1967 implementation slot does not hold an address");
  return getAddress(`0x${word.slice(26)}`);
}

/** The published implementation at `address` whose code hashes to `codeHash`, or null: not one Gray publishes. */
export function publishedImplementation(address: Address, codeHash: Hex | null): { readonly version: number } | null {
  const entry = APP_AUTH_PUBLISHED.implementations.find((item) => getAddress(item.address) === getAddress(address));
  return entry !== undefined && codeHash !== null && entry.code_hash === codeHash.toLowerCase() ? { version: entry.version } : null;
}

/**
 * An upgrade's release hash, as the contract's `upgradeId`: keccak256 of `Upgrade(address from,address to,bytes32
 * codeHash,bytes32 dataHash)`'s type hash and the implementation it starts from, the new one, the new one's code hash and
 * keccak256 of the call run on it (`0x` for none).
 */
export function appAuthUpgradeId(upgrade: { readonly from: Address; readonly to: Address; readonly codeHash: Hex; readonly data: Hex }): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "address" }, { type: "address" }, { type: "bytes32" }, { type: "bytes32" }],
      [keccak256(stringToBytes("Upgrade(address from,address to,bytes32 codeHash,bytes32 dataHash)")), upgrade.from, upgrade.to, upgrade.codeHash, keccak256(upgrade.data)],
    ),
  );
}

/** A proposed upgrade Gray publishes, by its id: from which implementation to which, with which call; null for none. */
export function publishedUpgrade(id: Hex): { readonly from: Address; readonly to: Address; readonly codeHash: Hex; readonly data: Hex; readonly version: number | null } | null {
  for (const item of APP_AUTH_PUBLISHED.upgrades) {
    const upgrade = { from: getAddress(item.from), to: getAddress(item.to), codeHash: item.code_hash as Hex, data: item.data as Hex };
    // An entry whose id is not its own fields' is no entry: the list cannot name one thing and mean another.
    if (item.id !== id.toLowerCase() || appAuthUpgradeId(upgrade) !== item.id) continue;
    return { ...upgrade, version: publishedImplementation(upgrade.to, upgrade.codeHash)?.version ?? null };
  }
  return null;
}
