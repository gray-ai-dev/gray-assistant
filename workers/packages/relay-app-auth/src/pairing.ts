/**
 * Gray's check of a pairing's guardian part (docs/design/relay-no-always-on-host.md 3.2, 4, 13.3; the console's
 * lane-stack/pairing.ts): the contract gray-assistant computed is the one Gray will deploy for this relay, and every
 * approval is the guardian's EIP-712 `Approve` of the first release, which Gray's relayer can submit once the contract
 * exists. Gray recomputes everything from its own terms (the relay id, its proposer, the chain, the release Deploy boots)
 * and the part's guardian and recovery address; nothing the part claims about the release is taken.
 *
 * The approvals are exactly the ones `pairingGuardianPart` makes for a release of one compose hash and one OS image hash:
 * the compose hash at nonce 0, the OS image hash at nonce 1, each at version 0 (a release's state before its first
 * decision, which a fresh deployment leaves), each with a deadline still ahead. A signature must recover to the guardian
 * (ECDSA): the kit's guardian is a plain key, and a wallet the kit holds no key for pairs without a guardian part.
 *
 * Pure: no network; the caller gives the time.
 */
import { getAddress, isAddress, zeroAddress, type Address, type Hex } from "viem";
import { appAuthAddress, type ReleaseKind } from "./app-auth.ts";
import { signedActionSigner, type SignedGuardianAction } from "./guardian.ts";

/** The pairing's guardian part as JSON (relay-kit `pairingGuardianJson`, signed approvals only). */
export interface PairingGuardianWire {
  readonly guardian: string;
  readonly recovery: string | null;
  readonly chain_id: number;
  readonly contract: string;
  readonly approvals: readonly {
    readonly kind: ReleaseKind;
    readonly hash: string;
    readonly version: string;
    readonly nonce: string;
    readonly deadline: string;
    readonly signature: string;
  }[];
}

/** Gray's side of the address: what the relay's contract will be deployed with, but the guardian. */
export interface PairingTerms {
  readonly relayId: string;
  readonly proposer: Address;
  readonly chainId: number;
  /** The release Deploy boots: Phala's measured compose hash and the OS image hash, 0x and 64 lower hex. */
  readonly composeHash: Hex;
  readonly osImageHash: Hex;
}

/** Why a guardian part is refused: one closed word each, for the audit (never a value from the part). */
export type PairingGuardianProblem = "chain" | "guardian" | "recovery" | "contract" | "approvals" | "deadline" | "signature";

export type PairingGuardianCheck =
  | {
      readonly ok: true;
      readonly guardian: Address;
      readonly recovery: Address | null;
      readonly contract: Address;
      /** The approvals in submission order (nonce 0, 1), as the relayer submits them. */
      readonly approvals: readonly SignedGuardianAction[];
    }
  | { readonly ok: false; readonly problem: PairingGuardianProblem };

function address(value: string | null): Address | null {
  if (value === null || !isAddress(value, { strict: false })) return null;
  const checked = getAddress(value);
  return checked === zeroAddress ? null : checked;
}

/** Check a pairing's guardian part against Gray's terms at `nowSeconds` (Unix seconds). */
export async function checkPairingGuardian(part: PairingGuardianWire, terms: PairingTerms, nowSeconds: bigint): Promise<PairingGuardianCheck> {
  if (part.chain_id !== terms.chainId) return { ok: false, problem: "chain" };
  // Gray's own proposer as the relay's guardian would let Gray approve its own releases: never the relay's choice.
  const proposer = getAddress(terms.proposer);
  const guardian = address(part.guardian);
  if (guardian === null || guardian === proposer) return { ok: false, problem: "guardian" };
  const recovery = part.recovery === null ? null : address(part.recovery);
  if (part.recovery !== null && (recovery === null || recovery === proposer)) return { ok: false, problem: "recovery" };
  const contract = appAuthAddress({
    relayId: terms.relayId,
    proposer,
    guardian,
    recovery,
    composeHashes: [terms.composeHash],
    osImageHashes: [terms.osImageHash],
  });
  if (address(part.contract) !== contract) return { ok: false, problem: "contract" };
  const expected: readonly { kind: ReleaseKind; hash: Hex }[] = [
    { kind: "compose", hash: terms.composeHash },
    { kind: "os_image", hash: terms.osImageHash },
  ];
  if (part.approvals.length !== expected.length) return { ok: false, problem: "approvals" };
  const approvals: SignedGuardianAction[] = [];
  for (const [index, want] of expected.entries()) {
    const approval = part.approvals[index]!;
    if (approval.kind !== want.kind || approval.hash !== want.hash || approval.version !== "0" || approval.nonce !== String(index)) return { ok: false, problem: "approvals" };
    const deadline = BigInt(approval.deadline);
    if (deadline <= nowSeconds) return { ok: false, problem: "deadline" };
    const signed: SignedGuardianAction = {
      action: "approve",
      kind: want.kind,
      hash: want.hash,
      chainId: terms.chainId,
      contract,
      version: 0n,
      signer: guardian,
      nonce: BigInt(index),
      deadline,
      signature: approval.signature as Hex,
    };
    let signer: Address;
    try {
      signer = await signedActionSigner(signed);
    } catch {
      return { ok: false, problem: "signature" };
    }
    if (signer !== guardian) return { ok: false, problem: "signature" };
    approvals.push(signed);
  }
  return { ok: true, guardian, recovery, contract, approvals };
}
