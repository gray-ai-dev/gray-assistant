/**
 * The guardian's EIP-712 messages to the relay's contract (contracts/relay-app-auth/src/GrayRelayAppAuth.sol): Approve,
 * Veto, Remove, Pause and Unpause, and the relay's SetDelay, SetGuardian and SetRecovery, each with the version of the state it decides (the release's `version`, or
 * `pauseVersion`, `delayVersion`, `keysVersion`), the signer, the signer's nonce and a deadline, under the domain
 * `GrayRelayAppAuth` / `1` / chain id / the contract. The type strings are the contract's (its tests write them out in
 * test/utils/AppAuthTest.sol); viem builds the struct hashes from the field lists below, and the kit's tests hold the
 * result to digests computed from those strings independently.
 *
 * The version binds a signature to the decision state it was made on: once the release (or the off switch) is decided
 * again, directly or by another signature, the contract refuses it with `SupersededSignature(signed, current)`, so a
 * signature held back cannot undo a later decision. The caller reads the version just before signing.
 *
 * A signed action is what Gray's relayer submits (`approveBySig`, `vetoBySig`, ...); `bySigCalldata` is the call. The
 * guardian is the key gray-assistant holds (`guardian-key.json`); the contract checks plain ECDSA signatures.
 *
 * Pure: no network, no clock (the caller gives the deadline).
 */
import { encodeFunctionData, getAddress, hashTypedData, recoverTypedDataAddress, type Address, type Hex, type TypedDataDomain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { AppAuthError } from "./errors.ts";
import { APP_AUTH_ABI, APP_AUTH_DELAY_SECONDS, APP_AUTH_DOMAIN_NAME, APP_AUTH_DOMAIN_VERSION, RELEASE_KIND_NUMBER, appAuthAddress, type AppAuthDeployment, type ReleaseKind } from "./app-auth.ts";

const RELEASE_FIELDS = [
  { name: "kind", type: "uint8" },
  { name: "releaseHash", type: "bytes32" },
  { name: "version", type: "uint64" },
  { name: "signer", type: "address" },
  { name: "nonce", type: "uint256" },
  { name: "deadline", type: "uint256" },
] as const;
const SWITCH_FIELDS = [
  { name: "version", type: "uint64" },
  { name: "signer", type: "address" },
  { name: "nonce", type: "uint256" },
  { name: "deadline", type: "uint256" },
] as const;

/** The contract's message types, as the EIP-712 `types` member (without `EIP712Domain`). */
export const APP_AUTH_TYPES = {
  Approve: RELEASE_FIELDS,
  Veto: RELEASE_FIELDS,
  Remove: RELEASE_FIELDS,
  Pause: SWITCH_FIELDS,
  Unpause: SWITCH_FIELDS,
  SetDelay: [{ name: "newDelay", type: "uint64" }, ...SWITCH_FIELDS],
  SetGuardian: [{ name: "newGuardian", type: "address" }, ...SWITCH_FIELDS],
  SetRecovery: [{ name: "newRecovery", type: "address" }, ...SWITCH_FIELDS],
} as const;

/**
 * One guardian action: on a release, an OS image or an upgrade (approve, veto) or the off switch (pause, unpause). The
 * relay never removes: a veto can be undone, a removal cannot, so only Gray's proposer removes (proposer.ts).
 */
export type GuardianAction =
  | { readonly action: "approve" | "veto"; readonly kind: ReleaseKind; readonly hash: Hex }
  | { readonly action: "pause" | "unpause" }
  /** The relay's release delay (seconds, 0 to 7 days): signed by the guardian or the recovery key, at `delayVersion`. */
  | { readonly action: "set_delay"; readonly delay: bigint }
  /** A new guardian or recovery address: signed by the recovery key only, at `keysVersion`. */
  | { readonly action: "set_guardian" | "set_recovery"; readonly address: Address };

/**
 * Where and by whom: the contract, its chain, the version of the state decided (`releaseOf(kind, hash).version` for a
 * release, `pauseVersion()` for the off switch), the signer and the signer's next nonce, and until when it holds.
 */
export interface GuardianMessageContext {
  readonly chainId: number;
  readonly contract: Address;
  readonly version: bigint;
  readonly signer: Address;
  readonly nonce: bigint;
  /** Unix seconds; the contract refuses the signature after it. */
  readonly deadline: bigint;
}

type SwitchAction = Extract<GuardianAction, { readonly action: "pause" | "unpause" }>;
type ReleaseAction = Extract<GuardianAction, { readonly action: "approve" | "veto" }>;

function isSwitch(action: GuardianAction): action is SwitchAction {
  return action.action === "pause" || action.action === "unpause";
}

function isRelease(action: GuardianAction): action is ReleaseAction {
  return action.action === "approve" || action.action === "veto";
}

const PRIMARY_TYPE = { approve: "Approve", veto: "Veto", pause: "Pause", unpause: "Unpause", set_delay: "SetDelay", set_guardian: "SetGuardian", set_recovery: "SetRecovery" } as const;
const BY_SIG = {
  approve: "approveBySig",
  veto: "vetoBySig",
  pause: "pauseBySig",
  unpause: "unpauseBySig",
  set_delay: "setDelayBySig",
  set_guardian: "setGuardianBySig",
  set_recovery: "setRecoveryBySig",
} as const;

/** The typed data of one action, as viem signs and hashes it. */
export function guardianTypedData(action: GuardianAction, context: GuardianMessageContext) {
  const domain: TypedDataDomain = { name: APP_AUTH_DOMAIN_NAME, version: APP_AUTH_DOMAIN_VERSION, chainId: context.chainId, verifyingContract: getAddress(context.contract) };
  const signer = getAddress(context.signer);
  const versioned = { version: context.version, signer, nonce: context.nonce, deadline: context.deadline };
  if (isSwitch(action)) return { domain, types: APP_AUTH_TYPES, primaryType: PRIMARY_TYPE[action.action], message: versioned } as const;
  if (action.action === "set_delay") return { domain, types: APP_AUTH_TYPES, primaryType: "SetDelay", message: { newDelay: action.delay, ...versioned } } as const;
  if (action.action === "set_guardian" || action.action === "set_recovery") {
    const address = getAddress(action.address);
    return action.action === "set_guardian"
      ? ({ domain, types: APP_AUTH_TYPES, primaryType: "SetGuardian", message: { newGuardian: address, ...versioned } } as const)
      : ({ domain, types: APP_AUTH_TYPES, primaryType: "SetRecovery", message: { newRecovery: address, ...versioned } } as const);
  }
  const release = action as ReleaseAction;
  return {
    domain,
    types: APP_AUTH_TYPES,
    primaryType: PRIMARY_TYPE[release.action],
    message: { kind: RELEASE_KIND_NUMBER[release.kind], releaseHash: release.hash, version: context.version, signer, nonce: context.nonce, deadline: context.deadline },
  } as const;
}

/** The EIP-712 digest the contract checks the signature against. */
export function guardianDigest(action: GuardianAction, context: GuardianMessageContext): Hex {
  // viem's overloads cannot narrow the union of primary types; the value is one of the five shapes above.
  return hashTypedData(guardianTypedData(action, context) as Parameters<typeof hashTypedData>[0]);
}

/** A signed action, in the form the kit prints for Gray's relayer and keeps in the pairing's guardian part. */
export interface SignedGuardianAction {
  readonly action: GuardianAction["action"];
  readonly kind: ReleaseKind | null;
  readonly hash: Hex | null;
  /** `set_delay`'s new delay in seconds. */
  readonly newDelay?: bigint;
  /** `set_guardian`'s or `set_recovery`'s new address. */
  readonly newAddress?: Address;
  readonly chainId: number;
  readonly contract: Address;
  /** The version of the state it decides; a later decision on that state supersedes the signature. */
  readonly version: bigint;
  readonly signer: Address;
  readonly nonce: bigint;
  readonly deadline: bigint;
  /** 65 bytes `r ‖ s ‖ v`, as OpenZeppelin's `ECDSA.tryRecover` takes it. */
  readonly signature: Hex;
}

/**
 * Sign one action with the guardian key. The key must be the context's signer: a key file that names another address
 * would sign a message the contract refuses.
 */
export async function signGuardianAction(privateKey: Hex, action: GuardianAction, context: GuardianMessageContext): Promise<SignedGuardianAction> {
  const account = privateKeyToAccount(privateKey);
  if (account.address !== getAddress(context.signer)) throw new AppAuthError("invalid_key_file", "the guardian key is not the guardian the config names");
  const signature = await account.signTypedData(guardianTypedData(action, context) as Parameters<typeof account.signTypedData>[0]);
  return {
    action: action.action,
    kind: isRelease(action) ? action.kind : null,
    hash: isRelease(action) ? action.hash : null,
    ...(action.action === "set_delay" ? { newDelay: action.delay } : {}),
    ...(action.action === "set_guardian" || action.action === "set_recovery" ? { newAddress: getAddress(action.address) } : {}),
    chainId: context.chainId,
    contract: getAddress(context.contract),
    version: context.version,
    signer: account.address,
    nonce: context.nonce,
    deadline: context.deadline,
    signature,
  };
}

/** Who signed a signed action, recovered from its signature (a check, before it is printed or sent). */
export async function signedActionSigner(signed: SignedGuardianAction): Promise<Address> {
  return recoverTypedDataAddress({ ...(guardianTypedData(actionOf(signed), signed) as Parameters<typeof hashTypedData>[0]), signature: signed.signature });
}

function actionOf(signed: SignedGuardianAction): GuardianAction {
  if (signed.action === "pause" || signed.action === "unpause") return { action: signed.action };
  if (signed.action === "set_delay") {
    if (signed.newDelay === undefined) throw new AppAuthError("usage", "a signed set_delay names its new delay");
    return { action: "set_delay", delay: signed.newDelay };
  }
  if (signed.action === "set_guardian" || signed.action === "set_recovery") {
    if (signed.newAddress === undefined) throw new AppAuthError("usage", `a signed ${signed.action} names its new address`);
    return { action: signed.action, address: signed.newAddress };
  }
  return { action: signed.action, kind: signed.kind as ReleaseKind, hash: signed.hash as Hex };
}

/** The contract call that carries the signed action: `approveBySig(kind, hash, signer, nonce, deadline, signature)` and so on. */
export function bySigCalldata(signed: SignedGuardianAction): Hex {
  const action = actionOf(signed);
  if (action.action === "set_delay") {
    return encodeFunctionData({ abi: APP_AUTH_ABI, functionName: "setDelayBySig", args: [action.delay, signed.version, signed.signer, signed.nonce, signed.deadline, signed.signature] });
  }
  if (action.action === "set_guardian" || action.action === "set_recovery") {
    return encodeFunctionData({ abi: APP_AUTH_ABI, functionName: BY_SIG[action.action], args: [getAddress(action.address), signed.version, signed.signer, signed.nonce, signed.deadline, signed.signature] });
  }
  if (signed.action === "pause" || signed.action === "unpause") {
    return encodeFunctionData({ abi: APP_AUTH_ABI, functionName: BY_SIG[signed.action], args: [signed.version, signed.signer, signed.nonce, signed.deadline, signed.signature] });
  }
  return encodeFunctionData({
    abi: APP_AUTH_ABI,
    functionName: BY_SIG[signed.action],
    args: [RELEASE_KIND_NUMBER[signed.kind as ReleaseKind], signed.hash as Hex, signed.version, signed.signer, signed.nonce, signed.deadline, signed.signature],
  });
}

/** The signed action as JSON for Gray's relayer (P5's submit route; printed until then). Integers as decimal strings. */
export function signedActionJson(signed: SignedGuardianAction): Record<string, string | number | null> {
  return {
    action: signed.action,
    kind: signed.kind,
    hash: signed.hash,
    ...(signed.newDelay === undefined ? {} : { new_delay: signed.newDelay.toString() }),
    ...(signed.newAddress === undefined ? {} : { new_address: signed.newAddress }),
    chain_id: signed.chainId,
    contract: signed.contract,
    version: signed.version.toString(),
    signer: signed.signer,
    nonce: signed.nonce.toString(),
    deadline: signed.deadline.toString(),
    signature: signed.signature,
    function: BY_SIG[signed.action],
    calldata: bySigCalldata(signed),
  };
}

/** How long the pairing's approvals hold: 30 days, time enough for Gray's Deploy after pairing (13.3). */
export const PAIRING_APPROVAL_LIFETIME_SECONDS = 30n * 24n * 60n * 60n;

/** One approval of the first release, in the pairing's guardian part. */
export interface PairingApproval {
  readonly kind: "compose" | "os_image";
  readonly hash: Hex;
  /** 0: a release's version before its first decision, which is what Gray's deployment leaves. */
  readonly version: bigint;
  readonly nonce: bigint;
  readonly deadline: bigint;
  readonly signature: Hex;
}

/** What pairing tells Gray about the guardian (P5 adds it to the pairing request). */
export interface PairingGuardianPart {
  readonly guardian: Address;
  /** The relay's recovery key's address (its key stays with the relay, offline; Gray never receives it). */
  readonly recovery: Address;
  readonly chainId: number;
  /** The relay's contract, computed before it exists (C12). */
  readonly contract: Address;
  /** The relay's release delay in seconds (13.13), part of the contract's address. */
  readonly delaySeconds: bigint;
  /** The approvals of the first release, nonces 0, 1, ... in this order: Gray submits them in this order after Deploy. */
  readonly approvals: readonly PairingApproval[];
}

/**
 * The pairing's guardian part: the contract address for the deployment and the guardian's approval of every compose
 * and OS image hash of the first release, compose hashes first. A fresh contract's nonce for the guardian is 0, so the
 * approvals take nonces 0, 1, ...; the contract accepts each only at its nonce, so they are submitted in order. Each
 * release is at version 0 until its first decision, and a decision on one release leaves the others' versions alone,
 * so every approval names version 0. The kit signs them with the guardian key.
 */
export async function pairingGuardianPart(input: {
  readonly deployment: AppAuthDeployment;
  readonly chainId: number;
  /** Unix seconds; every approval holds until then. */
  readonly deadline: bigint;
  readonly privateKey: Hex;
}): Promise<PairingGuardianPart> {
  const contract = appAuthAddress(input.deployment);
  const guardian = getAddress(input.deployment.guardian);
  const releases: { kind: "compose" | "os_image"; hash: Hex }[] = [
    ...input.deployment.composeHashes.map((hash) => ({ kind: "compose" as const, hash })),
    ...input.deployment.osImageHashes.map((hash) => ({ kind: "os_image" as const, hash })),
  ];
  const approvals: PairingApproval[] = [];
  for (const [index, release] of releases.entries()) {
    const action: GuardianAction = { action: "approve", kind: release.kind, hash: release.hash };
    const context: GuardianMessageContext = { chainId: input.chainId, contract, version: 0n, signer: guardian, nonce: BigInt(index), deadline: input.deadline };
    const { signature } = await signGuardianAction(input.privateKey, action, context);
    approvals.push({ kind: release.kind, hash: release.hash, version: 0n, nonce: BigInt(index), deadline: input.deadline, signature });
  }
  return { guardian, recovery: getAddress(input.deployment.recovery), chainId: input.chainId, contract, delaySeconds: input.deployment.delaySeconds ?? APP_AUTH_DELAY_SECONDS, approvals };
}

/** The guardian part as JSON (the pairing's member, P5). */
export function pairingGuardianJson(part: PairingGuardianPart): Record<string, unknown> {
  return {
    guardian: part.guardian,
    recovery: part.recovery,
    chain_id: part.chainId,
    contract: part.contract,
    delay_seconds: part.delaySeconds.toString(),
    approvals: part.approvals.map((approval) => ({
      kind: approval.kind,
      hash: approval.hash,
      version: approval.version.toString(),
      nonce: approval.nonce.toString(),
      deadline: approval.deadline.toString(),
      signature: approval.signature,
    })),
  };
}
